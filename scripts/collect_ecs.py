#!/usr/bin/env python3
"""
AWS ECS Collector
Collects ECS clusters, services, and task definitions across opted-in accounts.

Only runs for accounts with ecs_collect = true in config.ini. This is an
opt-in collector because most accounts do not run ECS.

Collection strategy:
  - Clusters:         list_clusters -> describe_clusters (batch 100)
  - Services:         list_services per cluster -> describe_services (batch 10)
  - Task definitions: describe_task_definition per unique family:revision
                      seen across all services (deduplicated, cached)

Tables created automatically:
    aws_ecs_clusters          — ECS cluster metadata
    aws_ecs_services          — Services within each cluster
    aws_ecs_task_definitions  — Task definition details (deduplicated by family:revision)
    aws_ecs_tags              — Tags for clusters and services

Requirements:
    pip install boto3 mysql-connector-python

Usage:
    python3 collect_ecs.py
    python3 collect_ecs.py --account my-account-name

config.ini opt-in:
    [account:my-account]
    ...
    ecs_collect = true
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
parser = argparse.ArgumentParser(description="AWS ECS Collector")
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
CREATE TABLE IF NOT EXISTS `aws_ecs_clusters` (
    `id`                          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `cluster_arn`                 VARCHAR(512)  NOT NULL,
    `cluster_name`                VARCHAR(255)  NOT NULL,
    `status`                      VARCHAR(50),
    `active_services`             SMALLINT UNSIGNED DEFAULT 0,
    `running_tasks`               SMALLINT UNSIGNED DEFAULT 0,
    `pending_tasks`               SMALLINT UNSIGNED DEFAULT 0,
    `registered_container_instances` SMALLINT UNSIGNED DEFAULT 0,
    `capacity_providers`          TEXT,
    `default_capacity_strategy`   TEXT,
    `container_insights`          VARCHAR(20),
    `account_name`                VARCHAR(255)  NOT NULL,
    `region`                      VARCHAR(50)   NOT NULL,
    `last_seen`                   DATETIME      NOT NULL,
    UNIQUE KEY `uq_ecs_cluster`   (`cluster_arn`),
    INDEX `idx_account`           (`account_name`),
    INDEX `idx_region`            (`region`),
    INDEX `idx_name`              (`cluster_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""

DDL_SERVICES = """
CREATE TABLE IF NOT EXISTS `aws_ecs_services` (
    `id`                      INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `service_arn`             VARCHAR(512)  NOT NULL,
    `service_name`            VARCHAR(255)  NOT NULL,
    `cluster_arn`             VARCHAR(512)  NOT NULL,
    `cluster_name`            VARCHAR(255),
    `status`                  VARCHAR(50),
    `desired_count`           SMALLINT UNSIGNED DEFAULT 0,
    `running_count`           SMALLINT UNSIGNED DEFAULT 0,
    `pending_count`           SMALLINT UNSIGNED DEFAULT 0,
    `task_definition`         VARCHAR(512),
    `launch_type`             VARCHAR(50),
    `scheduling_strategy`     VARCHAR(50),
    `platform_family`         VARCHAR(50),
    `platform_version`        VARCHAR(50),
    `deployment_controller`   VARCHAR(50),
    `health_check_grace`      INT UNSIGNED,
    `load_balancers`          TEXT,
    `vpc_id`                  VARCHAR(100),
    `subnets`                 TEXT,
    `security_groups`         TEXT,
    `assign_public_ip`        VARCHAR(20),
    `role_arn`                VARCHAR(512),
    `account_name`            VARCHAR(255)  NOT NULL,
    `region`                  VARCHAR(50)   NOT NULL,
    `created_at`              DATETIME,
    `last_seen`               DATETIME      NOT NULL,
    UNIQUE KEY `uq_ecs_service`  (`service_arn`),
    INDEX `idx_cluster`          (`cluster_arn`),
    INDEX `idx_account`          (`account_name`),
    INDEX `idx_region`           (`region`),
    INDEX `idx_name`             (`service_name`),
    INDEX `idx_status`           (`status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""

DDL_TASK_DEFS = """
CREATE TABLE IF NOT EXISTS `aws_ecs_task_definitions` (
    `id`                  INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `task_def_arn`        VARCHAR(512)  NOT NULL,
    `family`              VARCHAR(255)  NOT NULL,
    `revision`            SMALLINT UNSIGNED,
    `status`              VARCHAR(50),
    `network_mode`        VARCHAR(50),
    `task_role_arn`       VARCHAR(512),
    `execution_role_arn`  VARCHAR(512),
    `cpu`                 VARCHAR(20),
    `memory`              VARCHAR(20),
    `requires_compat`     VARCHAR(100),
    `containers`          TEXT,
    `volumes`             TEXT,
    `account_name`        VARCHAR(255)  NOT NULL,
    `region`              VARCHAR(50)   NOT NULL,
    `registered_at`       DATETIME,
    `last_seen`           DATETIME      NOT NULL,
    UNIQUE KEY `uq_ecs_taskdef` (`task_def_arn`),
    INDEX `idx_family`          (`family`),
    INDEX `idx_account`         (`account_name`),
    INDEX `idx_region`          (`region`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""

DDL_TAGS = """
CREATE TABLE IF NOT EXISTS `aws_ecs_tags` (
    `id`           INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `resource_arn` VARCHAR(512) NOT NULL,
    `account_name` VARCHAR(255) NOT NULL,
    `tag_key`      VARCHAR(255) NOT NULL,
    `tag_value`    TEXT,
    `last_seen`    DATETIME     NOT NULL,
    UNIQUE KEY `uq_ecs_tag`  (`resource_arn`(200), `tag_key`(100)),
    INDEX `idx_resource`     (`resource_arn`(200)),
    INDEX `idx_account`      (`account_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""

# ─────────────────────────────────────────────
# SQL
# ─────────────────────────────────────────────
UPSERT_CLUSTER = """
INSERT INTO `aws_ecs_clusters`
    (cluster_arn, cluster_name, status, active_services, running_tasks,
     pending_tasks, registered_container_instances, capacity_providers,
     default_capacity_strategy, container_insights, account_name, region, last_seen)
VALUES
    (%(cluster_arn)s, %(cluster_name)s, %(status)s, %(active_services)s,
     %(running_tasks)s, %(pending_tasks)s, %(registered_container_instances)s,
     %(capacity_providers)s, %(default_capacity_strategy)s, %(container_insights)s,
     %(account_name)s, %(region)s, %(last_seen)s)
ON DUPLICATE KEY UPDATE
    cluster_name                     = VALUES(cluster_name),
    status                           = VALUES(status),
    active_services                  = VALUES(active_services),
    running_tasks                    = VALUES(running_tasks),
    pending_tasks                    = VALUES(pending_tasks),
    registered_container_instances   = VALUES(registered_container_instances),
    capacity_providers               = VALUES(capacity_providers),
    container_insights               = VALUES(container_insights),
    last_seen                        = VALUES(last_seen);
"""

UPSERT_SERVICE = """
INSERT INTO `aws_ecs_services`
    (service_arn, service_name, cluster_arn, cluster_name, status,
     desired_count, running_count, pending_count, task_definition,
     launch_type, scheduling_strategy, platform_family, platform_version,
     deployment_controller, health_check_grace, load_balancers,
     vpc_id, subnets, security_groups, assign_public_ip,
     role_arn, account_name, region, created_at, last_seen)
VALUES
    (%(service_arn)s, %(service_name)s, %(cluster_arn)s, %(cluster_name)s, %(status)s,
     %(desired_count)s, %(running_count)s, %(pending_count)s, %(task_definition)s,
     %(launch_type)s, %(scheduling_strategy)s, %(platform_family)s, %(platform_version)s,
     %(deployment_controller)s, %(health_check_grace)s, %(load_balancers)s,
     %(vpc_id)s, %(subnets)s, %(security_groups)s, %(assign_public_ip)s,
     %(role_arn)s, %(account_name)s, %(region)s, %(created_at)s, %(last_seen)s)
ON DUPLICATE KEY UPDATE
    cluster_name          = VALUES(cluster_name),
    status                = VALUES(status),
    desired_count         = VALUES(desired_count),
    running_count         = VALUES(running_count),
    pending_count         = VALUES(pending_count),
    task_definition       = VALUES(task_definition),
    launch_type           = VALUES(launch_type),
    platform_family       = VALUES(platform_family),
    platform_version      = VALUES(platform_version),
    load_balancers        = VALUES(load_balancers),
    vpc_id                = VALUES(vpc_id),
    subnets               = VALUES(subnets),
    security_groups       = VALUES(security_groups),
    assign_public_ip      = VALUES(assign_public_ip),
    last_seen             = VALUES(last_seen);
"""

UPSERT_TASK_DEF = """
INSERT INTO `aws_ecs_task_definitions`
    (task_def_arn, family, revision, status, network_mode,
     task_role_arn, execution_role_arn, cpu, memory, requires_compat,
     containers, volumes, account_name, region, registered_at, last_seen)
VALUES
    (%(task_def_arn)s, %(family)s, %(revision)s, %(status)s, %(network_mode)s,
     %(task_role_arn)s, %(execution_role_arn)s, %(cpu)s, %(memory)s, %(requires_compat)s,
     %(containers)s, %(volumes)s, %(account_name)s, %(region)s, %(registered_at)s, %(last_seen)s)
ON DUPLICATE KEY UPDATE
    status             = VALUES(status),
    task_role_arn      = VALUES(task_role_arn),
    execution_role_arn = VALUES(execution_role_arn),
    containers         = VALUES(containers),
    last_seen          = VALUES(last_seen);
"""

UPSERT_TAG = """
INSERT INTO `aws_ecs_tags` (resource_arn, account_name, tag_key, tag_value, last_seen)
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
    for ddl in (DDL_CLUSTERS, DDL_SERVICES, DDL_TASK_DEFS, DDL_TAGS):
        cur.execute(ddl)
    conn.commit()
    return conn, cur


# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────
def upsert_tags(cur, resource_arn, account_name, tags, now):
    for tag in tags:
        k = tag.get("key", "").strip()
        v = tag.get("value", "").strip()
        if not k:
            continue
        cur.execute(UPSERT_TAG, {
            "resource_arn":  resource_arn,
            "account_name":  account_name,
            "tag_key":       k,
            "tag_value":     v,
            "last_seen":     now,
        })


def chunks(lst, n):
    """Yield successive n-sized chunks from lst."""
    for i in range(0, len(lst), n):
        yield lst[i:i + n]


def delete_stale(cur, account_name, region, now):
    cur.execute("""
        DELETE FROM `aws_ecs_services`
        WHERE account_name = %s AND region = %s AND last_seen < %s
    """, (account_name, region, now))
    cur.execute("""
        DELETE FROM `aws_ecs_clusters`
        WHERE account_name = %s AND region = %s AND last_seen < %s
    """, (account_name, region, now))
    # Task definitions are global per account+region — clean up orphans
    cur.execute("""
        DELETE FROM `aws_ecs_task_definitions`
        WHERE account_name = %s AND region = %s AND last_seen < %s
    """, (account_name, region, now))
    # Clean up orphaned tags
    cur.execute("""
        DELETE t FROM `aws_ecs_tags` t
        WHERE t.account_name = %s
          AND t.resource_arn NOT IN (
              SELECT cluster_arn FROM `aws_ecs_clusters` WHERE account_name = %s
              UNION ALL
              SELECT service_arn FROM `aws_ecs_services` WHERE account_name = %s
          )
    """, (account_name, account_name, account_name))


# ─────────────────────────────────────────────
# COLLECTORS
# ─────────────────────────────────────────────
def collect_clusters(ecs, account_name, region, cur, now):
    """List and describe all ECS clusters in the region."""
    arns = []
    paginator = ecs.get_paginator("list_clusters")
    for page in paginator.paginate():
        arns.extend(page.get("clusterArns", []))

    if not arns:
        return 0

    count = 0
    # describe_clusters accepts up to 100 ARNs at a time
    for batch in chunks(arns, 100):
        resp = ecs.describe_clusters(
            clusters=batch,
            include=["TAGS", "SETTINGS", "CONFIGURATIONS", "STATISTICS"],
        )
        for c in resp.get("clusters", []):
            # Container Insights setting
            insights = ""
            for setting in c.get("settings", []):
                if setting.get("name") == "containerInsights":
                    insights = setting.get("value", "")

            cur.execute(UPSERT_CLUSTER, {
                "cluster_arn":                    c["clusterArn"],
                "cluster_name":                   c["clusterName"],
                "status":                         c.get("status", ""),
                "active_services":                c.get("activeServicesCount", 0),
                "running_tasks":                  c.get("runningTasksCount", 0),
                "pending_tasks":                  c.get("pendingTasksCount", 0),
                "registered_container_instances": c.get("registeredContainerInstancesCount", 0),
                "capacity_providers":             json.dumps(c.get("capacityProviders", [])),
                "default_capacity_strategy":      json.dumps(c.get("defaultCapacityProviderStrategy", [])),
                "container_insights":             insights,
                "account_name":                   account_name,
                "region":                         region,
                "last_seen":                      now,
            })

            upsert_tags(cur, c["clusterArn"], account_name, c.get("tags", []), now)
            count += 1

    return count


def collect_services(ecs, account_name, region, cluster_arn, cluster_name, cur, now):
    """List and describe all services within a cluster."""
    arns = []
    paginator = ecs.get_paginator("list_services")
    for page in paginator.paginate(cluster=cluster_arn):
        arns.extend(page.get("serviceArns", []))

    if not arns:
        return 0

    count = 0
    # describe_services accepts up to 10 ARNs at a time
    for batch in chunks(arns, 10):
        resp = ecs.describe_services(
            cluster=cluster_arn,
            services=batch,
            include=["TAGS"],
        )
        for s in resp.get("services", []):
            # Network config — extract VPC/subnet/SG from awsvpcConfiguration
            net    = s.get("networkConfiguration", {}).get("awsvpcConfiguration", {})
            vpc_id = ""  # ECS service itself doesn't expose VPC directly; derive from subnets if needed
            subnets = json.dumps(net.get("subnets", []))
            sgs     = json.dumps(net.get("securityGroups", []))
            pub_ip  = net.get("assignPublicIp", "")

            # Load balancers — store name/target group/container port
            lbs = []
            for lb in s.get("loadBalancers", []):
                lbs.append({
                    "name":            lb.get("loadBalancerName", ""),
                    "target_group":    lb.get("targetGroupArn", ""),
                    "container_name":  lb.get("containerName", ""),
                    "container_port":  lb.get("containerPort"),
                })

            # Deployment controller type
            dc = s.get("deploymentController", {}).get("type", "ECS")

            created = s.get("createdAt")
            if created:
                created = created.replace(tzinfo=None)

            cur.execute(UPSERT_SERVICE, {
                "service_arn":           s["serviceArn"],
                "service_name":          s["serviceName"],
                "cluster_arn":           cluster_arn,
                "cluster_name":          cluster_name,
                "status":                s.get("status", ""),
                "desired_count":         s.get("desiredCount", 0),
                "running_count":         s.get("runningCount", 0),
                "pending_count":         s.get("pendingCount", 0),
                "task_definition":       s.get("taskDefinition", ""),
                "launch_type":           s.get("launchType", ""),
                "scheduling_strategy":   s.get("schedulingStrategy", ""),
                "platform_family":       s.get("platformFamily", "") or "",
                "platform_version":      s.get("platformVersion", "") or "",
                "deployment_controller": dc,
                "health_check_grace":    s.get("healthCheckGracePeriodSeconds"),
                "load_balancers":        json.dumps(lbs),
                "vpc_id":                vpc_id,
                "subnets":               subnets,
                "security_groups":       sgs,
                "assign_public_ip":      pub_ip,
                "role_arn":              s.get("roleArn", "") or "",
                "account_name":          account_name,
                "region":                region,
                "created_at":            created,
                "last_seen":             now,
            })

            upsert_tags(cur, s["serviceArn"], account_name, s.get("tags", []), now)
            count += 1

    return count


def collect_task_definitions(ecs, task_def_arns, account_name, region, cur, now):
    """
    Describe unique task definition ARNs seen across all services.
    Deduplicated before calling — one describe_task_definition call per unique ARN.
    """
    count = 0
    seen  = set()

    for arn in task_def_arns:
        if arn in seen or not arn:
            continue
        seen.add(arn)

        try:
            resp = ecs.describe_task_definition(
                taskDefinition=arn,
                include=["TAGS"],
            )
        except ClientError as e:
            print(f"       ✘  describe_task_definition [{arn}]: {e}")
            continue

        td = resp.get("taskDefinition", {})
        if not td:
            continue

        # Containers — just the useful bits, not the full blob
        containers = []
        for c in td.get("containerDefinitions", []):
            containers.append({
                "name":    c.get("name", ""),
                "image":   c.get("image", ""),
                "cpu":     c.get("cpu", 0),
                "memory":  c.get("memory") or c.get("memoryReservation"),
                "ports":   [
                    {"container": p.get("containerPort"), "host": p.get("hostPort"), "protocol": p.get("protocol", "tcp")}
                    for p in c.get("portMappings", [])
                ],
                "env_count":    len(c.get("environment", [])),
                "secrets_count": len(c.get("secrets", [])),
                "log_driver":   c.get("logConfiguration", {}).get("logDriver", ""),
            })

        volumes = [{"name": v.get("name", "")} for v in td.get("volumes", [])]

        registered_at = td.get("registeredAt")
        if registered_at:
            registered_at = registered_at.replace(tzinfo=None)

        requires_compat = ", ".join(td.get("requiresCompatibilities", []))

        cur.execute(UPSERT_TASK_DEF, {
            "task_def_arn":       td["taskDefinitionArn"],
            "family":             td.get("family", ""),
            "revision":           td.get("revision"),
            "status":             td.get("status", ""),
            "network_mode":       td.get("networkMode", ""),
            "task_role_arn":      td.get("taskRoleArn", "") or "",
            "execution_role_arn": td.get("executionRoleArn", "") or "",
            "cpu":                td.get("cpu", "") or "",
            "memory":             td.get("memory", "") or "",
            "requires_compat":    requires_compat,
            "containers":         json.dumps(containers),
            "volumes":            json.dumps(volumes),
            "account_name":       account_name,
            "region":             region,
            "registered_at":      registered_at,
            "last_seen":          now,
        })
        count += 1

    return count


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
def main():
    conn, cur = init_db(DB_CONFIG)
    now   = datetime.now(timezone.utc).replace(tzinfo=None).strftime("%Y-%m-%d %H:%M:%S")
    total_clusters  = 0
    total_services  = 0
    total_task_defs = 0

    for acct in ACCOUNTS:
        name    = acct["name"]
        regions = acct["regions"]

        # ── Opt-in check ─────────────────────────────────────────────────
        if not acct.get("ecs_collect", False):
            print(f"\n  Skipping {name} — ecs_collect not set in config.ini")
            continue

        print(f"\n{'─'*55}")
        print(f"  Account: {name}")
        print(f"{'─'*55}")

        for region in regions:
            print(f"  ↳ Region: {region}")
            try:
                boto_session = get_session(acct)
                ecs          = boto_session.client("ecs", region_name=region)

                # ── Clusters ─────────────────────────────────────────────
                c_count = collect_clusters(ecs, name, region, cur, now)
                print(f"     ✔  {c_count} clusters")

                # ── Services (per cluster) + collect task def ARNs ───────
                cur.execute("""
                    SELECT cluster_arn, cluster_name FROM aws_ecs_clusters
                    WHERE account_name = %s AND region = %s AND last_seen = %s
                """, (name, region, now))
                clusters = [{"cluster_arn": r[0], "cluster_name": r[1]} for r in cur.fetchall()]

                s_count      = 0
                task_def_arns = []

                for cluster in clusters:
                    svc_count = collect_services(
                        ecs, name, region,
                        cluster["cluster_arn"],
                        cluster["cluster_name"],
                        cur, now
                    )
                    s_count += svc_count

                    # Collect task definition ARNs from services we just wrote
                    cur.execute("""
                        SELECT DISTINCT task_definition FROM aws_ecs_services
                        WHERE cluster_arn = %s AND account_name = %s
                          AND task_definition != ''
                    """, (cluster["cluster_arn"], name))
                    task_def_arns.extend(
                        r[0] for r in cur.fetchall()
                    )

                print(f"     ✔  {s_count} services")

                # ── Task definitions (deduplicated) ───────────────────────
                td_count = collect_task_definitions(
                    ecs, task_def_arns, name, region, cur, now
                )
                print(f"     ✔  {td_count} task definitions")

                delete_stale(cur, name, region, now)
                conn.commit()

                total_clusters  += c_count
                total_services  += s_count
                total_task_defs += td_count

            except NoCredentialsError:
                print(f"     ✘  No credentials for {name}")
            except ClientError as e:
                code = e.response["Error"]["Code"]
                print(f"     ✘  ClientError [{code}]: {e}")
            except Exception as e:
                print(f"     ✘  Unexpected error: {e}")

    cur.close()
    conn.close()
    print(f"\n✅  Done — {total_clusters} clusters, {total_services} services, "
          f"{total_task_defs} task definitions collected.")


if __name__ == "__main__":
    main()
