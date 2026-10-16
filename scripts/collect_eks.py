#!/usr/bin/env python3
"""
AWS EKS Collector
Collects EKS clusters and managed node groups across opted-in accounts.

Only runs for accounts with eks_collect = true in config.ini.

Collection strategy:
  - Clusters:    list_clusters -> describe_cluster per cluster
  - Node groups: list_nodegroups per cluster -> describe_nodegroup per node group

Tables created automatically:
    aws_eks_clusters     — EKS cluster metadata
    aws_eks_nodegroups   — Managed node groups per cluster
    aws_eks_tags         — Tags for clusters and node groups

Requirements:
    pip install boto3 mysql-connector-python

Usage:
    python3 collect_eks.py
    python3 collect_eks.py --account my-account-name

config.ini opt-in:
    [account:my-account]
    ...
    eks_collect = true
"""

import json
import sys
import argparse
from datetime import datetime, timezone

import mysql.connector
from botocore.exceptions import ClientError, NoCredentialsError

import os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from config_loader import get_db_config, get_accounts, get_session

DB_CONFIG = get_db_config()
ACCOUNTS  = get_accounts()

# ─────────────────────────────────────────────
# ARG PARSING
# ─────────────────────────────────────────────
parser = argparse.ArgumentParser(description="AWS EKS Collector")
parser.add_argument("--account", help="Only run for this account name (must match config.ini)", default=None)
args = parser.parse_args()

if args.account:
    ACCOUNTS = [a for a in ACCOUNTS if a["name"] == args.account]
    if not ACCOUNTS:
        print(f"[ERROR] No account named '{args.account}' found in config.ini")
        sys.exit(1)

# ─────────────────────────────────────────────
# DDL
# ─────────────────────────────────────────────
DDL_CLUSTERS = """
CREATE TABLE IF NOT EXISTS `aws_eks_clusters` (
    `id`                      INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `cluster_name`            VARCHAR(255)  NOT NULL,
    `cluster_arn`             VARCHAR(512),
    `status`                  VARCHAR(50),
    `kubernetes_version`      VARCHAR(20),
    `platform_version`        VARCHAR(20),
    `endpoint`                VARCHAR(512),
    `endpoint_public_access`  TINYINT(1)    DEFAULT 0,
    `endpoint_private_access` TINYINT(1)    DEFAULT 0,
    `public_access_cidrs`     TEXT,
    `role_arn`                VARCHAR(512),
    `vpc_id`                  VARCHAR(100),
    `subnet_ids`              TEXT,
    `security_group_ids`      TEXT,
    `cluster_sg_id`           VARCHAR(100),
    `secrets_encrypted`       TINYINT(1)    DEFAULT 0,
    `kms_key_arn`             VARCHAR(512),
    `logging_enabled`         TEXT,
    `service_ipv4_cidr`       VARCHAR(50),
    `ip_family`               VARCHAR(10),
    `dns_name`                VARCHAR(512),
    `account_name`            VARCHAR(255)  NOT NULL,
    `region`                  VARCHAR(50)   NOT NULL,
    `created_at`              DATETIME,
    `last_seen`               DATETIME      NOT NULL,
    UNIQUE KEY `uq_eks_cluster` (`cluster_name`(100), `account_name`(100), `region`(50)),
    INDEX `idx_account`         (`account_name`),
    INDEX `idx_region`          (`region`),
    INDEX `idx_status`          (`status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""

DDL_NODEGROUPS = """
CREATE TABLE IF NOT EXISTS `aws_eks_nodegroups` (
    `id`                  INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `nodegroup_name`      VARCHAR(255)  NOT NULL,
    `nodegroup_arn`       VARCHAR(512),
    `cluster_name`        VARCHAR(255)  NOT NULL,
    `status`              VARCHAR(50),
    `capacity_type`       VARCHAR(20),
    `instance_types`      TEXT,
    `ami_type`            VARCHAR(50),
    `ami_release_version` VARCHAR(100),
    `disk_size_gb`        SMALLINT UNSIGNED,
    `desired_size`        SMALLINT UNSIGNED DEFAULT 0,
    `min_size`            SMALLINT UNSIGNED DEFAULT 0,
    `max_size`            SMALLINT UNSIGNED DEFAULT 0,
    `node_role_arn`       VARCHAR(512),
    `subnet_ids`          TEXT,
    `labels`              TEXT,
    `taints`              TEXT,
    `update_config`       TEXT,
    `account_name`        VARCHAR(255)  NOT NULL,
    `region`              VARCHAR(50)   NOT NULL,
    `created_at`          DATETIME,
    `last_seen`           DATETIME      NOT NULL,
    UNIQUE KEY `uq_eks_ng` (`nodegroup_name`(80), `cluster_name`(80), `account_name`(80), `region`(30)),
    INDEX `idx_cluster`     (`cluster_name`),
    INDEX `idx_account`     (`account_name`),
    INDEX `idx_region`      (`region`),
    INDEX `idx_status`      (`status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""

DDL_TAGS = """
CREATE TABLE IF NOT EXISTS `aws_eks_tags` (
    `id`           INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `resource_arn` VARCHAR(512) NOT NULL,
    `account_name` VARCHAR(255) NOT NULL,
    `tag_key`      VARCHAR(255) NOT NULL,
    `tag_value`    TEXT,
    `last_seen`    DATETIME     NOT NULL,
    UNIQUE KEY `uq_eks_tag` (`resource_arn`(200), `tag_key`(100)),
    INDEX `idx_resource`    (`resource_arn`(200)),
    INDEX `idx_account`     (`account_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""

# ─────────────────────────────────────────────
# SQL
# ─────────────────────────────────────────────
UPSERT_CLUSTER = """
INSERT INTO `aws_eks_clusters`
    (cluster_name, cluster_arn, status, kubernetes_version, platform_version,
     endpoint, endpoint_public_access, endpoint_private_access, public_access_cidrs,
     role_arn, vpc_id, subnet_ids, security_group_ids, cluster_sg_id,
     secrets_encrypted, kms_key_arn, logging_enabled,
     service_ipv4_cidr, ip_family, dns_name,
     account_name, region, created_at, last_seen)
VALUES
    (%(cluster_name)s, %(cluster_arn)s, %(status)s, %(kubernetes_version)s,
     %(platform_version)s, %(endpoint)s, %(endpoint_public_access)s,
     %(endpoint_private_access)s, %(public_access_cidrs)s, %(role_arn)s,
     %(vpc_id)s, %(subnet_ids)s, %(security_group_ids)s, %(cluster_sg_id)s,
     %(secrets_encrypted)s, %(kms_key_arn)s, %(logging_enabled)s,
     %(service_ipv4_cidr)s, %(ip_family)s, %(dns_name)s,
     %(account_name)s, %(region)s, %(created_at)s, %(last_seen)s)
ON DUPLICATE KEY UPDATE
    cluster_arn              = VALUES(cluster_arn),
    status                   = VALUES(status),
    kubernetes_version       = VALUES(kubernetes_version),
    platform_version         = VALUES(platform_version),
    endpoint                 = VALUES(endpoint),
    endpoint_public_access   = VALUES(endpoint_public_access),
    endpoint_private_access  = VALUES(endpoint_private_access),
    public_access_cidrs      = VALUES(public_access_cidrs),
    vpc_id                   = VALUES(vpc_id),
    subnet_ids               = VALUES(subnet_ids),
    security_group_ids       = VALUES(security_group_ids),
    cluster_sg_id            = VALUES(cluster_sg_id),
    secrets_encrypted        = VALUES(secrets_encrypted),
    logging_enabled          = VALUES(logging_enabled),
    last_seen                = VALUES(last_seen);
"""

UPSERT_NODEGROUP = """
INSERT INTO `aws_eks_nodegroups`
    (nodegroup_name, nodegroup_arn, cluster_name, status, capacity_type,
     instance_types, ami_type, ami_release_version, disk_size_gb,
     desired_size, min_size, max_size, node_role_arn, subnet_ids,
     labels, taints, update_config, account_name, region, created_at, last_seen)
VALUES
    (%(nodegroup_name)s, %(nodegroup_arn)s, %(cluster_name)s, %(status)s,
     %(capacity_type)s, %(instance_types)s, %(ami_type)s, %(ami_release_version)s,
     %(disk_size_gb)s, %(desired_size)s, %(min_size)s, %(max_size)s,
     %(node_role_arn)s, %(subnet_ids)s, %(labels)s, %(taints)s, %(update_config)s,
     %(account_name)s, %(region)s, %(created_at)s, %(last_seen)s)
ON DUPLICATE KEY UPDATE
    status               = VALUES(status),
    capacity_type        = VALUES(capacity_type),
    instance_types       = VALUES(instance_types),
    ami_type             = VALUES(ami_type),
    ami_release_version  = VALUES(ami_release_version),
    disk_size_gb         = VALUES(disk_size_gb),
    desired_size         = VALUES(desired_size),
    min_size             = VALUES(min_size),
    max_size             = VALUES(max_size),
    labels               = VALUES(labels),
    taints               = VALUES(taints),
    update_config        = VALUES(update_config),
    last_seen            = VALUES(last_seen);
"""

UPSERT_TAG = """
INSERT INTO `aws_eks_tags` (resource_arn, account_name, tag_key, tag_value, last_seen)
VALUES (%(resource_arn)s, %(account_name)s, %(tag_key)s, %(tag_value)s, %(last_seen)s)
ON DUPLICATE KEY UPDATE
    tag_value = VALUES(tag_value),
    last_seen = VALUES(last_seen);
"""

# ─────────────────────────────────────────────
# DB INIT
# ─────────────────────────────────────────────
def init_db(cfg):
    conn = mysql.connector.connect(**cfg)
    cur  = conn.cursor()
    for ddl in (DDL_CLUSTERS, DDL_NODEGROUPS, DDL_TAGS):
        cur.execute(ddl)
    conn.commit()
    return conn, cur


# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────
def upsert_tags(cur, resource_arn, account_name, tags_dict, now):
    """tags_dict is a plain dict {key: value} as returned by EKS API."""
    for k, v in (tags_dict or {}).items():
        if not k:
            continue
        cur.execute(UPSERT_TAG, {
            "resource_arn":  resource_arn,
            "account_name":  account_name,
            "tag_key":       k,
            "tag_value":     v or "",
            "last_seen":     now,
        })


def delete_stale(cur, account_name, region, now):
    cur.execute("""
        DELETE FROM `aws_eks_nodegroups`
        WHERE account_name = %s AND region = %s AND last_seen < %s
    """, (account_name, region, now))
    cur.execute("""
        DELETE FROM `aws_eks_clusters`
        WHERE account_name = %s AND region = %s AND last_seen < %s
    """, (account_name, region, now))
    cur.execute("""
        DELETE t FROM `aws_eks_tags` t
        WHERE t.account_name = %s
          AND t.resource_arn NOT IN (
              SELECT cluster_arn FROM `aws_eks_clusters`  WHERE account_name = %s
              UNION ALL
              SELECT nodegroup_arn FROM `aws_eks_nodegroups` WHERE account_name = %s
          )
    """, (account_name, account_name, account_name))


# ─────────────────────────────────────────────
# COLLECTORS
# ─────────────────────────────────────────────
def collect_cluster(eks, cluster_name, account_name, region, cur, now):
    """Describe a single cluster and upsert it. Returns cluster_arn or None."""
    try:
        resp = eks.describe_cluster(name=cluster_name)
    except ClientError as e:
        print(f"       ✘  describe_cluster [{cluster_name}]: {e}")
        return None

    c = resp.get("cluster", {})
    if not c:
        return None

    resources_vpc = c.get("resourcesVpcConfig", {})
    logging_cfg   = c.get("logging", {}).get("clusterLogging", [])
    k8s_net       = c.get("kubernetesNetworkConfig", {})
    encrypt_cfg   = c.get("encryptionConfig", [])

    # Which log types are enabled
    enabled_logs = []
    for entry in logging_cfg:
        if entry.get("enabled"):
            enabled_logs.extend(entry.get("types", []))

    # Secrets encryption
    secrets_encrypted = 0
    kms_key_arn       = ""
    for enc in encrypt_cfg:
        if "secrets" in enc.get("resources", []):
            secrets_encrypted = 1
            kms_key_arn = enc.get("provider", {}).get("keyArn", "")

    created = c.get("createdAt")
    if created:
        created = created.replace(tzinfo=None)

    cur.execute(UPSERT_CLUSTER, {
        "cluster_name":            c["name"],
        "cluster_arn":             c.get("arn", ""),
        "status":                  c.get("status", ""),
        "kubernetes_version":      c.get("version", ""),
        "platform_version":        c.get("platformVersion", ""),
        "endpoint":                c.get("endpoint", "") or "",
        "endpoint_public_access":  int(resources_vpc.get("endpointPublicAccess",  False)),
        "endpoint_private_access": int(resources_vpc.get("endpointPrivateAccess", False)),
        "public_access_cidrs":     json.dumps(resources_vpc.get("publicAccessCidrs", [])),
        "role_arn":                c.get("roleArn", "") or "",
        "vpc_id":                  resources_vpc.get("vpcId", "") or "",
        "subnet_ids":              json.dumps(resources_vpc.get("subnetIds", [])),
        "security_group_ids":      json.dumps(resources_vpc.get("securityGroupIds", [])),
        "cluster_sg_id":           resources_vpc.get("clusterSecurityGroupId", "") or "",
        "secrets_encrypted":       secrets_encrypted,
        "kms_key_arn":             kms_key_arn,
        "logging_enabled":         json.dumps(enabled_logs),
        "service_ipv4_cidr":       k8s_net.get("serviceIpv4Cidr", "") or "",
        "ip_family":               k8s_net.get("ipFamily", "") or "",
        "dns_name":                c.get("endpoint", "") or "",
        "account_name":            account_name,
        "region":                  region,
        "created_at":              created,
        "last_seen":               now,
    })

    upsert_tags(cur, c.get("arn", ""), account_name, c.get("tags", {}), now)
    return c.get("arn", cluster_name)


def collect_nodegroups(eks, cluster_name, account_name, region, cur, now):
    """List and describe all managed node groups for a cluster."""
    count = 0
    try:
        paginator = eks.get_paginator("list_nodegroups")
        ng_names  = []
        for page in paginator.paginate(clusterName=cluster_name):
            ng_names.extend(page.get("nodegroups", []))
    except ClientError as e:
        print(f"       ✘  list_nodegroups [{cluster_name}]: {e}")
        return 0

    for ng_name in ng_names:
        try:
            resp = eks.describe_nodegroup(clusterName=cluster_name, nodegroupName=ng_name)
        except ClientError as e:
            print(f"       ✘  describe_nodegroup [{ng_name}]: {e}")
            continue

        ng = resp.get("nodegroup", {})
        if not ng:
            continue

        scaling = ng.get("scalingConfig", {})
        created = ng.get("createdAt")
        if created:
            created = created.replace(tzinfo=None)

        # Taints — list of {key, value, effect}
        taints = [
            {"key": t.get("key", ""), "value": t.get("value", ""), "effect": t.get("effect", "")}
            for t in ng.get("taints", [])
        ]

        cur.execute(UPSERT_NODEGROUP, {
            "nodegroup_name":      ng["nodegroupName"],
            "nodegroup_arn":       ng.get("nodegroupArn", ""),
            "cluster_name":        cluster_name,
            "status":              ng.get("status", ""),
            "capacity_type":       ng.get("capacityType", ""),
            "instance_types":      json.dumps(ng.get("instanceTypes", [])),
            "ami_type":            ng.get("amiType", ""),
            "ami_release_version": ng.get("releaseVersion", "") or "",
            "disk_size_gb":        ng.get("diskSize"),
            "desired_size":        scaling.get("desiredSize", 0),
            "min_size":            scaling.get("minSize", 0),
            "max_size":            scaling.get("maxSize", 0),
            "node_role_arn":       ng.get("nodeRole", "") or "",
            "subnet_ids":          json.dumps(ng.get("subnets", [])),
            "labels":              json.dumps(ng.get("labels", {})),
            "taints":              json.dumps(taints),
            "update_config":       json.dumps(ng.get("updateConfig", {})),
            "account_name":        account_name,
            "region":              region,
            "created_at":          created,
            "last_seen":           now,
        })

        upsert_tags(cur, ng.get("nodegroupArn", ""), account_name, ng.get("tags", {}), now)
        count += 1

    return count


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
def main():
    conn, cur = init_db(DB_CONFIG)
    now   = datetime.now(timezone.utc).replace(tzinfo=None).strftime("%Y-%m-%d %H:%M:%S")
    total_clusters   = 0
    total_nodegroups = 0

    for acct in ACCOUNTS:
        name    = acct["name"]
        regions = acct["regions"]

        # ── Opt-in check ─────────────────────────────────────────────────
        if not acct.get("eks_collect", False):
            print(f"\n  Skipping {name} — eks_collect not set in config.ini")
            continue

        print(f"\n{'─'*55}")
        print(f"  Account: {name}")
        print(f"{'─'*55}")

        for region in regions:
            print(f"  ↳ Region: {region}")
            try:
                boto_session = get_session(acct)
                eks          = boto_session.client("eks", region_name=region)

                # List all cluster names in this region
                cluster_names = []
                paginator = eks.get_paginator("list_clusters")
                for page in paginator.paginate():
                    cluster_names.extend(page.get("clusters", []))

                if not cluster_names:
                    print("     —  no clusters")
                    continue

                c_count  = 0
                ng_count = 0

                for cluster_name in cluster_names:
                    arn = collect_cluster(eks, cluster_name, name, region, cur, now)
                    if arn:
                        c_count += 1
                        ng_count += collect_nodegroups(eks, cluster_name, name, region, cur, now)

                delete_stale(cur, name, region, now)
                conn.commit()

                total_clusters   += c_count
                total_nodegroups += ng_count
                print(f"     ✔  {c_count} clusters, {ng_count} node groups")

            except NoCredentialsError:
                print(f"     ✘  No credentials for {name}")
            except ClientError as e:
                code = e.response["Error"]["Code"]
                print(f"     ✘  ClientError [{code}]: {e}")
            except Exception as e:
                print(f"     ✘  Unexpected error: {e}")

    cur.close()
    conn.close()
    print(f"\n✅  Done — {total_clusters} clusters, {total_nodegroups} node groups collected.")


if __name__ == "__main__":
    main()
