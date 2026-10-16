#!/usr/bin/env python3
"""
AWS RDS / Aurora Collector
Collects DB clusters (Aurora) and DB instances (RDS) across all accounts.
Designed to run weekly — DB infrastructure changes infrequently.

Tables created automatically:
    aws_rds_clusters   — Aurora cluster-level data
    aws_rds_instances  — Individual DB instances (clustered or standalone)
    aws_rds_tags       — Tags for both clusters and instances

Requirements:
    pip install boto3 mysql-connector-python

Usage:
    python3 collect_rds.py
    python3 collect_rds.py --account my-account-name
"""

import json
import sys
import argparse
from datetime import datetime, timezone

import boto3
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
parser = argparse.ArgumentParser(description="AWS RDS/Aurora Collector")
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
CREATE TABLE IF NOT EXISTS `aws_rds_clusters` (
    `id`                      INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `cluster_id`              VARCHAR(255)  NOT NULL,
    `cluster_arn`             VARCHAR(512),
    `status`                  VARCHAR(50),
    `engine`                  VARCHAR(100),
    `engine_version`          VARCHAR(100),
    `engine_mode`             VARCHAR(50),
    `endpoint`                VARCHAR(512),
    `reader_endpoint`         VARCHAR(512),
    `port`                    SMALLINT UNSIGNED,
    `multi_az`                TINYINT(1)   DEFAULT 0,
    `deletion_protection`     TINYINT(1)   DEFAULT 0,
    `backup_retention_days`   SMALLINT UNSIGNED,
    `preferred_backup_window` VARCHAR(50),
    `preferred_maint_window`  VARCHAR(50),
    `vpc_id`                  VARCHAR(100),
    `subnet_group`            VARCHAR(255),
    `security_groups`         TEXT,
    `parameter_group`         VARCHAR(255),
    `db_cluster_members`      TEXT,
    `master_username`         VARCHAR(100),
    `database_name`           VARCHAR(255),
    `storage_encrypted`       TINYINT(1)   DEFAULT 0,
    `iam_auth_enabled`        TINYINT(1)   DEFAULT 0,
    `account_name`            VARCHAR(255) NOT NULL,
    `region`                  VARCHAR(50)  NOT NULL,
    `created_at`              DATETIME,
    `last_seen`               DATETIME     NOT NULL,
    UNIQUE KEY `uq_cluster` (`cluster_id`, `account_name`),
    INDEX `idx_engine`        (`engine`),
    INDEX `idx_account`       (`account_name`),
    INDEX `idx_vpc`           (`vpc_id`),
    INDEX `idx_status`        (`status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""

DDL_INSTANCES = """
CREATE TABLE IF NOT EXISTS `aws_rds_instances` (
    `id`                       INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `instance_id`              VARCHAR(255)  NOT NULL,
    `instance_arn`             VARCHAR(512),
    `instance_class`           VARCHAR(100),
    `status`                   VARCHAR(50),
    `engine`                   VARCHAR(100),
    `engine_version`           VARCHAR(100),
    `endpoint`                 VARCHAR(512),
    `port`                     SMALLINT UNSIGNED,
    `multi_az`                 TINYINT(1)    DEFAULT 0,
    `publicly_accessible`      TINYINT(1)    DEFAULT 0,
    `storage_type`             VARCHAR(50),
    `storage_gb`               INT UNSIGNED,
    `storage_encrypted`        TINYINT(1)    DEFAULT 0,
    `iops`                     INT UNSIGNED,
    `deletion_protection`      TINYINT(1)    DEFAULT 0,
    `performance_insights`     TINYINT(1)    DEFAULT 0,
    `iam_auth_enabled`         TINYINT(1)    DEFAULT 0,
    `ca_certificate`           VARCHAR(100),
    `master_username`          VARCHAR(100),
    `database_name`            VARCHAR(255),
    `preferred_backup_window`  VARCHAR(50),
    `preferred_maint_window`   VARCHAR(50),
    `backup_retention_days`    SMALLINT UNSIGNED,
    `parameter_group`          VARCHAR(255),
    `subnet_group`             VARCHAR(255),
    `vpc_id`                   VARCHAR(100),
    `security_groups`          TEXT,
    `cluster_id`               VARCHAR(255),
    `replica_source`           VARCHAR(255),
    `auto_minor_upgrade`       TINYINT(1)    DEFAULT 0,
    `account_name`             VARCHAR(255)  NOT NULL,
    `region`                   VARCHAR(50)   NOT NULL,
    `created_at`               DATETIME,
    `last_seen`                DATETIME      NOT NULL,
    UNIQUE KEY `uq_instance` (`instance_id`, `account_name`),
    INDEX `idx_engine`         (`engine`),
    INDEX `idx_account`        (`account_name`),
    INDEX `idx_vpc`            (`vpc_id`),
    INDEX `idx_cluster`        (`cluster_id`),
    INDEX `idx_status`         (`status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""

DDL_TAGS = """
CREATE TABLE IF NOT EXISTS `aws_rds_tags` (
    `id`           INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `resource_id`  VARCHAR(255) NOT NULL,
    `account_name` VARCHAR(255) NOT NULL,
    `tag_key`      VARCHAR(255) NOT NULL,
    `tag_value`    TEXT,
    `last_seen`    DATETIME     NOT NULL,
    UNIQUE KEY `uq_rds_tag` (`resource_id`, `account_name`, `tag_key`),
    INDEX `idx_resource`   (`resource_id`),
    INDEX `idx_account`    (`account_name`),
    INDEX `idx_tag_key`    (`tag_key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""

# ─────────────────────────────────────────────
# SQL
# ─────────────────────────────────────────────
UPSERT_CLUSTER = """
INSERT INTO `aws_rds_clusters`
    (cluster_id, cluster_arn, status, engine, engine_version, engine_mode,
     endpoint, reader_endpoint, port, multi_az, deletion_protection,
     backup_retention_days, preferred_backup_window, preferred_maint_window,
     vpc_id, subnet_group, security_groups, parameter_group, db_cluster_members,
     master_username, database_name, storage_encrypted, iam_auth_enabled,
     account_name, region, created_at, last_seen)
VALUES
    (%(cluster_id)s, %(cluster_arn)s, %(status)s, %(engine)s, %(engine_version)s,
     %(engine_mode)s, %(endpoint)s, %(reader_endpoint)s, %(port)s, %(multi_az)s,
     %(deletion_protection)s, %(backup_retention_days)s, %(preferred_backup_window)s,
     %(preferred_maint_window)s, %(vpc_id)s, %(subnet_group)s, %(security_groups)s,
     %(parameter_group)s, %(db_cluster_members)s, %(master_username)s, %(database_name)s,
     %(storage_encrypted)s, %(iam_auth_enabled)s, %(account_name)s, %(region)s,
     %(created_at)s, %(last_seen)s)
ON DUPLICATE KEY UPDATE
    status                  = VALUES(status),
    engine_version          = VALUES(engine_version),
    endpoint                = VALUES(endpoint),
    reader_endpoint         = VALUES(reader_endpoint),
    port                    = VALUES(port),
    multi_az                = VALUES(multi_az),
    deletion_protection     = VALUES(deletion_protection),
    backup_retention_days   = VALUES(backup_retention_days),
    preferred_backup_window = VALUES(preferred_backup_window),
    preferred_maint_window  = VALUES(preferred_maint_window),
    vpc_id                  = VALUES(vpc_id),
    subnet_group            = VALUES(subnet_group),
    security_groups         = VALUES(security_groups),
    parameter_group         = VALUES(parameter_group),
    db_cluster_members      = VALUES(db_cluster_members),
    storage_encrypted       = VALUES(storage_encrypted),
    iam_auth_enabled        = VALUES(iam_auth_enabled),
    last_seen               = VALUES(last_seen);
"""

UPSERT_INSTANCE = """
INSERT INTO `aws_rds_instances`
    (instance_id, instance_arn, instance_class, status, engine, engine_version,
     endpoint, port, multi_az, publicly_accessible, storage_type, storage_gb,
     storage_encrypted, iops, deletion_protection, performance_insights,
     iam_auth_enabled, ca_certificate, master_username, database_name,
     preferred_backup_window, preferred_maint_window, backup_retention_days,
     parameter_group, subnet_group, vpc_id, security_groups, cluster_id,
     replica_source, auto_minor_upgrade, account_name, region, created_at, last_seen)
VALUES
    (%(instance_id)s, %(instance_arn)s, %(instance_class)s, %(status)s, %(engine)s,
     %(engine_version)s, %(endpoint)s, %(port)s, %(multi_az)s, %(publicly_accessible)s,
     %(storage_type)s, %(storage_gb)s, %(storage_encrypted)s, %(iops)s,
     %(deletion_protection)s, %(performance_insights)s, %(iam_auth_enabled)s,
     %(ca_certificate)s, %(master_username)s, %(database_name)s,
     %(preferred_backup_window)s, %(preferred_maint_window)s, %(backup_retention_days)s,
     %(parameter_group)s, %(subnet_group)s, %(vpc_id)s, %(security_groups)s,
     %(cluster_id)s, %(replica_source)s, %(auto_minor_upgrade)s, %(account_name)s,
     %(region)s, %(created_at)s, %(last_seen)s)
ON DUPLICATE KEY UPDATE
    instance_class        = VALUES(instance_class),
    status                = VALUES(status),
    engine_version        = VALUES(engine_version),
    endpoint              = VALUES(endpoint),
    port                  = VALUES(port),
    multi_az              = VALUES(multi_az),
    publicly_accessible   = VALUES(publicly_accessible),
    storage_type          = VALUES(storage_type),
    storage_gb            = VALUES(storage_gb),
    storage_encrypted     = VALUES(storage_encrypted),
    iops                  = VALUES(iops),
    deletion_protection   = VALUES(deletion_protection),
    performance_insights  = VALUES(performance_insights),
    iam_auth_enabled      = VALUES(iam_auth_enabled),
    vpc_id                = VALUES(vpc_id),
    security_groups       = VALUES(security_groups),
    cluster_id            = VALUES(cluster_id),
    replica_source        = VALUES(replica_source),
    last_seen             = VALUES(last_seen);
"""

UPSERT_TAG = """
INSERT INTO `aws_rds_tags` (resource_id, account_name, tag_key, tag_value, last_seen)
VALUES (%(resource_id)s, %(account_name)s, %(tag_key)s, %(tag_value)s, %(last_seen)s)
ON DUPLICATE KEY UPDATE
    tag_value = VALUES(tag_value),
    last_seen = VALUES(last_seen);
"""


# ─────────────────────────────────────────────
# DB INIT
# ─────────────────────────────────────────────
def init_db(cfg):
    try:
        conn = mysql.connector.connect(**cfg)
        cur  = conn.cursor()
        cur.execute(f"CREATE DATABASE IF NOT EXISTS `{cfg['database']}` CHARACTER SET utf8mb4;")
        cur.execute(f"USE `{cfg['database']}`;")
        for ddl in (DDL_CLUSTERS, DDL_INSTANCES, DDL_TAGS):
            cur.execute(ddl)
        conn.commit()
        print(f"✅  Connected to MySQL — database `{cfg['database']}` ready.")
        return conn, cur
    except mysql.connector.Error as e:
        print(f"[ERROR] MySQL connection failed: {e}")
        sys.exit(1)


def upsert_tags(cur, resource_id, account_name, tags, now):
    for tag in tags:
        k = tag.get("Key", "").strip()
        v = tag.get("Value", "").strip()
        if not k:
            continue
        cur.execute(UPSERT_TAG, {
            "resource_id":  resource_id,
            "account_name": account_name,
            "tag_key":      k,
            "tag_value":    v,
            "last_seen":    now,
        })


def delete_stale(cur, account_name, region, now):
    for tbl, col in [
        ("aws_rds_clusters",  "cluster_id"),
        ("aws_rds_instances", "instance_id"),
    ]:
        cur.execute(f"""
            DELETE FROM `{tbl}`
            WHERE account_name = %s AND region = %s AND last_seen < %s
        """, (account_name, region, now))
    # Stale tags — remove tags for resources that no longer exist
    cur.execute("""
        DELETE t FROM aws_rds_tags t
        WHERE t.account_name = %s
          AND t.resource_id NOT IN (
              SELECT cluster_id FROM aws_rds_clusters WHERE account_name = %s
              UNION ALL
              SELECT instance_id FROM aws_rds_instances WHERE account_name = %s
          )
    """, (account_name, account_name, account_name))


# ─────────────────────────────────────────────
# COLLECTORS
# ─────────────────────────────────────────────
def collect_clusters(rds, account_name, region, cur, now):
    count = 0
    paginator = rds.get_paginator("describe_db_clusters")
    for page in paginator.paginate():
        for c in page.get("DBClusters", []):
            sgs = json.dumps([
                {"id": sg["VpcSecurityGroupId"], "status": sg["Status"]}
                for sg in c.get("VpcSecurityGroups", [])
            ])
            members = json.dumps([
                {"instance_id": m["DBInstanceIdentifier"], "is_writer": m["IsClusterWriter"]}
                for m in c.get("DBClusterMembers", [])
            ])
            pg = ""
            for g in c.get("DBClusterParameterGroups", []):
                pg = g.get("DBClusterParameterGroupName", "")
                break

            created = c.get("ClusterCreateTime")
            if created:
                created = created.replace(tzinfo=None)

            cur.execute(UPSERT_CLUSTER, {
                "cluster_id":              c["DBClusterIdentifier"],
                "cluster_arn":             c.get("DBClusterArn", ""),
                "status":                  c.get("Status", ""),
                "engine":                  c.get("Engine", ""),
                "engine_version":          c.get("EngineVersion", ""),
                "engine_mode":             c.get("EngineMode", "provisioned"),
                "endpoint":                c.get("Endpoint", ""),
                "reader_endpoint":         c.get("ReaderEndpoint", ""),
                "port":                    c.get("Port"),
                "multi_az":                int(c.get("MultiAZ", False)),
                "deletion_protection":     int(c.get("DeletionProtection", False)),
                "backup_retention_days":   c.get("BackupRetentionPeriod", 0),
                "preferred_backup_window": c.get("PreferredBackupWindow", ""),
                "preferred_maint_window":  c.get("PreferredMaintenanceWindow", ""),
                "vpc_id":                  c.get("DbClusterResourceId", ""),  # fallback
                "subnet_group":            c.get("DBSubnetGroup", ""),
                "security_groups":         sgs,
                "parameter_group":         pg,
                "db_cluster_members":      members,
                "master_username":         c.get("MasterUsername", ""),
                "database_name":           c.get("DatabaseName", ""),
                "storage_encrypted":       int(c.get("StorageEncrypted", False)),
                "iam_auth_enabled":        int(c.get("IAMDatabaseAuthenticationEnabled", False)),
                "account_name":            account_name,
                "region":                  region,
                "created_at":              created,
                "last_seen":               now,
            })

            # Fetch tags via ARN
            arn = c.get("DBClusterArn", "")
            if arn:
                try:
                    tag_resp = rds.list_tags_for_resource(ResourceName=arn)
                    upsert_tags(cur, c["DBClusterIdentifier"], account_name,
                                tag_resp.get("TagList", []), now)
                except ClientError:
                    pass

            count += 1
    return count


def collect_instances(rds, account_name, region, cur, now):
    count = 0
    paginator = rds.get_paginator("describe_db_instances")
    for page in paginator.paginate():
        for inst in page.get("DBInstances", []):
            sgs = json.dumps([
                {"id": sg["VpcSecurityGroupId"], "status": sg["Status"]}
                for sg in inst.get("VpcSecurityGroups", [])
            ])
            endpoint_host = ""
            endpoint_port = inst.get("DbInstancePort") or inst.get("Endpoint", {}).get("Port")
            ep = inst.get("Endpoint", {})
            if ep:
                endpoint_host = ep.get("Address", "")
                if not endpoint_port:
                    endpoint_port = ep.get("Port")

            pg = ""
            for g in inst.get("DBParameterGroups", []):
                pg = g.get("DBParameterGroupName", "")
                break

            created = inst.get("InstanceCreateTime")
            if created:
                created = created.replace(tzinfo=None)

            cur.execute(UPSERT_INSTANCE, {
                "instance_id":            inst["DBInstanceIdentifier"],
                "instance_arn":           inst.get("DBInstanceArn", ""),
                "instance_class":         inst.get("DBInstanceClass", ""),
                "status":                 inst.get("DBInstanceStatus", ""),
                "engine":                 inst.get("Engine", ""),
                "engine_version":         inst.get("EngineVersion", ""),
                "endpoint":               endpoint_host,
                "port":                   endpoint_port,
                "multi_az":               int(inst.get("MultiAZ", False)),
                "publicly_accessible":    int(inst.get("PubliclyAccessible", False)),
                "storage_type":           inst.get("StorageType", ""),
                "storage_gb":             inst.get("AllocatedStorage"),
                "storage_encrypted":      int(inst.get("StorageEncrypted", False)),
                "iops":                   inst.get("Iops"),
                "deletion_protection":    int(inst.get("DeletionProtection", False)),
                "performance_insights":   int(inst.get("PerformanceInsightsEnabled", False)),
                "iam_auth_enabled":       int(inst.get("IAMDatabaseAuthenticationEnabled", False)),
                "ca_certificate":         inst.get("CACertificateIdentifier", ""),
                "master_username":        inst.get("MasterUsername", ""),
                "database_name":          inst.get("DBName", ""),
                "preferred_backup_window":inst.get("PreferredBackupWindow", ""),
                "preferred_maint_window": inst.get("PreferredMaintenanceWindow", ""),
                "backup_retention_days":  inst.get("BackupRetentionPeriod", 0),
                "parameter_group":        pg,
                "subnet_group":           inst.get("DBSubnetGroup", {}).get("DBSubnetGroupName", ""),
                "vpc_id":                 inst.get("DBSubnetGroup", {}).get("VpcId", ""),
                "security_groups":        sgs,
                "cluster_id":             inst.get("DBClusterIdentifier", ""),
                "replica_source":         inst.get("ReadReplicaSourceDBInstanceIdentifier", ""),
                "auto_minor_upgrade":     int(inst.get("AutoMinorVersionUpgrade", False)),
                "account_name":           account_name,
                "region":                 region,
                "created_at":             created,
                "last_seen":              now,
            })

            arn = inst.get("DBInstanceArn", "")
            if arn:
                try:
                    tag_resp = rds.list_tags_for_resource(ResourceName=arn)
                    upsert_tags(cur, inst["DBInstanceIdentifier"], account_name,
                                tag_resp.get("TagList", []), now)
                except ClientError:
                    pass

            count += 1
    return count


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
def main():
    conn, cur = init_db(DB_CONFIG)
    now = datetime.now(timezone.utc).replace(tzinfo=None).strftime("%Y-%m-%d %H:%M:%S")
    total_clusters = 0
    total_instances = 0

    for acct in ACCOUNTS:
        name    = acct["name"]
        regions = acct["regions"]
        print(f"\n{'─'*55}")
        print(f"  Account: {name}")
        print(f"{'─'*55}")

        for region in regions:
            print(f"  ↳ Region: {region}")
            try:
                session = get_session(acct)
                rds     = session.client("rds", region_name=region)

                c_count = collect_clusters(rds, name, region, cur, now)
                i_count = collect_instances(rds, name, region, cur, now)
                delete_stale(cur, name, region, now)
                conn.commit()

                total_clusters  += c_count
                total_instances += i_count
                print(f"     ✔  {c_count} clusters, {i_count} instances")

            except NoCredentialsError:
                print(f"     ✘  No credentials for {name}")
            except ClientError as e:
                code = e.response["Error"]["Code"]
                print(f"     ✘  ClientError [{code}]: {e}")
            except Exception as e:
                print(f"     ✘  Unexpected error: {e}")

    cur.close()
    conn.close()
    print(f"\n✅  Done — {total_clusters} clusters, {total_instances} instances collected.")


if __name__ == "__main__":
    main()
