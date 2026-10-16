#!/usr/bin/env python3
"""
AWS EKS Node History Collector
Hourly snapshot of ALL nodes on each EKS cluster — both managed node group
nodes and self-managed nodes (Karpenter, static ASGs, etc.) — by querying
EC2 directly using the cluster ownership tag.

Why EC2 instead of the EKS API:
  - describe_nodegroup only returns managed node groups; self-managed nodes
    are invisible to it.
  - EC2 instances belonging to a cluster are tagged:
      kubernetes.io/cluster/<cluster-name> = owned  (or shared)
  - This gives us every node regardless of how it was provisioned.

What is recorded per snapshot:
  - instance_id, instance_type, node_group (if managed, else 'self-managed'),
    capacity_type (ON_DEMAND / SPOT / UNKNOWN), az, node_state, recorded_at

Tables created automatically:
    aws_eks_node_history  — one row per node per hourly snapshot

Retention: 90 days (pruned automatically on each run)

Usage:
    python3 collect_eks_node_history.py
    python3 collect_eks_node_history.py --account my-account-name
    python3 collect_eks_node_history.py --dry-run

Cron (hourly):
    0 * * * * /path/to/venv/bin/python3 /path/to/aws-inventory/scripts/collect_eks_node_history.py >> /var/log/eks-node-history.log 2>&1
"""

import sys
import argparse
from datetime import datetime, timezone

import mysql.connector
from botocore.exceptions import ClientError, NoCredentialsError

import os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from config_loader import get_db_config, get_accounts, get_session

DB_CONFIG      = get_db_config()
ACCOUNTS       = get_accounts()
RETENTION_DAYS = 90

# ─────────────────────────────────────────────
# ARG PARSING
# ─────────────────────────────────────────────
parser = argparse.ArgumentParser(description="AWS EKS Node History Collector")
parser.add_argument("--account", help="Only run for this account name", default=None)
parser.add_argument("--dry-run", action="store_true",
                    help="Print what would be collected without writing to DB")
args = parser.parse_args()

if args.account:
    ACCOUNTS = [a for a in ACCOUNTS if a["name"] == args.account]
    if not ACCOUNTS:
        print(f"[ERROR] No account named '{args.account}' found in config.ini")
        sys.exit(1)

# ─────────────────────────────────────────────
# DDL
# ─────────────────────────────────────────────
DDL_HISTORY = """
CREATE TABLE IF NOT EXISTS `aws_eks_node_history` (
    `id`              INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `account_name`    VARCHAR(255)  NOT NULL,
    `region`          VARCHAR(50)   NOT NULL,
    `cluster_name`    VARCHAR(255)  NOT NULL,
    `instance_id`     VARCHAR(32)   NOT NULL,
    `instance_type`   VARCHAR(50)   NOT NULL,
    `node_group`      VARCHAR(255)  NOT NULL DEFAULT 'self-managed',
    `capacity_type`   VARCHAR(20)   NOT NULL DEFAULT 'UNKNOWN',
    `az`              VARCHAR(50)   NOT NULL DEFAULT '',
    `node_state`      VARCHAR(20)   NOT NULL DEFAULT '',
    `asg_name`        VARCHAR(255)  NOT NULL DEFAULT '',
    `recorded_at`     DATETIME      NOT NULL,
    INDEX `idx_cluster_time`  (`cluster_name`(100), `account_name`(100), `recorded_at`),
    INDEX `idx_account`       (`account_name`),
    INDEX `idx_recorded_at`   (`recorded_at`),
    INDEX `idx_instance`      (`instance_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""

INSERT_HISTORY = """
INSERT INTO `aws_eks_node_history`
    (account_name, region, cluster_name, instance_id, instance_type,
     node_group, capacity_type, az, node_state, asg_name, recorded_at)
VALUES
    (%(account_name)s, %(region)s, %(cluster_name)s, %(instance_id)s, %(instance_type)s,
     %(node_group)s, %(capacity_type)s, %(az)s, %(node_state)s, %(asg_name)s, %(recorded_at)s)
"""

PRUNE_OLD = """
DELETE FROM `aws_eks_node_history`
WHERE recorded_at < NOW() - INTERVAL %s DAY
"""

# ─────────────────────────────────────────────
# DB INIT
# ─────────────────────────────────────────────
def init_db(db_config):
    conn = mysql.connector.connect(**db_config)
    cur  = conn.cursor(dictionary=True)
    cur.execute(DDL_HISTORY)
    # Upgrade tables created before asg_name existed
    cur.execute("SHOW COLUMNS FROM `aws_eks_node_history` LIKE 'asg_name'")
    if not cur.fetchall():
        cur.execute("ALTER TABLE `aws_eks_node_history` "
                    "ADD COLUMN `asg_name` VARCHAR(255) NOT NULL DEFAULT '' AFTER `node_state`")
    conn.commit()
    return conn, cur


# ─────────────────────────────────────────────
# FETCH KNOWN CLUSTERS FROM DB
# ─────────────────────────────────────────────
def get_known_clusters(cur, account_name: str) -> list:
    """
    Read clusters from aws_eks_clusters so we only query accounts/regions
    that collect_eks.py has already discovered.
    Returns list of {cluster_name, region} dicts.
    """
    cur.execute("""
        SELECT cluster_name, region
        FROM aws_eks_clusters
        WHERE account_name = %s
        ORDER BY region, cluster_name
    """, (account_name,))
    return cur.fetchall()


# ─────────────────────────────────────────────
# EC2 NODE DISCOVERY
# ─────────────────────────────────────────────
def get_cluster_nodes(ec2_client, cluster_name: str) -> list:
    """
    Return all running/pending EC2 instances tagged as belonging to this
    EKS cluster. Covers both managed node groups and self-managed nodes.

    Tag filter:  kubernetes.io/cluster/<cluster_name> = owned  OR  shared
    State filter: running, pending  (skip terminated/stopped)

    Capacity type detection order:
      1. eks:capacity-type tag (set by EKS managed node groups)
      2. karpenter.sh/capacity-type tag (set by Karpenter)
      3. EC2 InstanceLifecycle field ("spot" → SPOT, else ON_DEMAND)

    Node group detection:
      1. eks:nodegroup-name tag (EKS managed)
      2. aws:eks:nodegroup-name tag (alternate EKS tag format)
      3. Falls back to "self-managed"
    """
    nodes = []

    try:
        paginator = ec2_client.get_paginator("describe_instances")
        pages = paginator.paginate(
            Filters=[
                {
                    "Name":   f"tag:kubernetes.io/cluster/{cluster_name}",
                    "Values": ["owned", "shared"],
                },
                {
                    "Name":   "instance-state-name",
                    "Values": ["running", "pending"],
                },
            ]
        )

        for page in pages:
            for reservation in page.get("Reservations", []):
                for inst in reservation.get("Instances", []):
                    tag_map = {
                        t["Key"]: t.get("Value", "")
                        for t in inst.get("Tags", [])
                    }

                    # ── Node group ───────────────────────────────────────
                    node_group = (
                        tag_map.get("eks:nodegroup-name")
                        or tag_map.get("aws:eks:nodegroup-name")
                        or ""
                    )
                    if not node_group:
                        node_group = "self-managed"

                    # ── Capacity type ────────────────────────────────────
                    capacity_type = (
                        tag_map.get("eks:capacity-type")
                        or tag_map.get("karpenter.sh/capacity-type")
                        or ""
                    ).upper()

                    if not capacity_type:
                        lifecycle = inst.get("InstanceLifecycle", "")
                        if lifecycle == "spot":
                            capacity_type = "SPOT"
                        elif lifecycle == "scheduled":
                            capacity_type = "SCHEDULED"
                        else:
                            capacity_type = "ON_DEMAND"

                    tags = {t["Key"]: t["Value"] for t in inst.get("Tags", [])}
                    asg_name = tags.get("aws:autoscaling:groupName", "")

                    nodes.append({
                        "instance_id":   inst["InstanceId"],
                        "instance_type": inst.get("InstanceType", "unknown"),
                        "node_group":    node_group,
                        "capacity_type": capacity_type,
                        "az":            inst.get("Placement", {}).get("AvailabilityZone", ""),
                        "node_state":    inst.get("State", {}).get("Name", ""),
                        "asg_name":      asg_name,
                    })

    except ClientError as e:
        code = e.response["Error"]["Code"]
        print(f"       ✘  describe_instances [{cluster_name}]: {code} — {e}")

    return nodes


# ─────────────────────────────────────────────
# PRUNE OLD ROWS
# ─────────────────────────────────────────────
def prune_history(cur, conn, dry_run: bool):
    if dry_run:
        cur.execute("""
            SELECT COUNT(*) AS cnt FROM aws_eks_node_history
            WHERE recorded_at < NOW() - INTERVAL %s DAY
        """, (RETENTION_DAYS,))
        row = cur.fetchone()
        print(f"\n[dry-run] Would prune {row['cnt']} rows older than {RETENTION_DAYS} days")
        return
    cur.execute(PRUNE_OLD, (RETENTION_DAYS,))
    pruned = cur.rowcount
    conn.commit()
    if pruned:
        print(f"\n🗑  Pruned {pruned} rows older than {RETENTION_DAYS} days")


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
def main():
    if args.dry_run:
        print("⚠  Dry-run mode — no data will be written\n")

    conn, cur = init_db(DB_CONFIG)
    now = datetime.now(timezone.utc).replace(tzinfo=None).strftime("%Y-%m-%d %H:%M:%S")

    total_snapshots = 0

    for acct in ACCOUNTS:
        name = acct["name"]

        if not acct.get("eks_collect", False):
            continue

        clusters = get_known_clusters(cur, name)
        if not clusters:
            print(f"\n  {name} — no clusters in DB (run collect_eks.py first)")
            continue

        # Group clusters by region — one boto session covers all clusters in a region
        by_region: dict = {}
        for cl in clusters:
            by_region.setdefault(cl["region"], []).append(cl["cluster_name"])

        print(f"\n{'─'*55}")
        print(f"  Account: {name}  ({len(clusters)} clusters)")
        print(f"{'─'*55}")

        for region, cluster_names in by_region.items():
            print(f"  ↳ Region: {region}")
            try:
                boto_session = get_session(acct)
                ec2_client   = boto_session.client("ec2", region_name=region)

                for cluster_name in cluster_names:
                    nodes = get_cluster_nodes(ec2_client, cluster_name)

                    if args.dry_run:
                        # Group output by node_group + capacity_type → instance type counts
                        summary: dict = {}
                        for n in nodes:
                            grp_key = f"{n['node_group']} [{n['capacity_type']}]"
                            summary.setdefault(grp_key, {})
                            summary[grp_key][n["instance_type"]] = (
                                summary[grp_key].get(n["instance_type"], 0) + 1
                            )
                        print(f"     [dry-run] {cluster_name}: {len(nodes)} nodes total")
                        for grp, types in sorted(summary.items()):
                            type_str = ", ".join(
                                f"{cnt}×{itype}"
                                for itype, cnt in sorted(types.items())
                            )
                            print(f"       • {grp}: {type_str}")
                        continue

                    # Write one row per node
                    for node in nodes:
                        cur.execute(INSERT_HISTORY, {
                            "account_name":  name,
                            "region":        region,
                            "cluster_name":  cluster_name,
                            "instance_id":   node["instance_id"],
                            "instance_type": node["instance_type"],
                            "node_group":    node["node_group"],
                            "capacity_type": node["capacity_type"],
                            "az":            node["az"],
                            "node_state":    node["node_state"],
                            "asg_name":      node["asg_name"],
                            "recorded_at":   now,
                        })

                    conn.commit()
                    total_snapshots += len(nodes)
                    print(f"     ✔  {cluster_name}: {len(nodes)} nodes recorded")

            except NoCredentialsError:
                print(f"     ✘  No credentials for {name}")
            except ClientError as e:
                code = e.response["Error"]["Code"]
                print(f"     ✘  ClientError [{code}]: {e}")
            except Exception as e:
                print(f"     ✘  Unexpected error: {e}")

    prune_history(cur, conn, args.dry_run)

    cur.close()
    conn.close()
    print(f"\n✅  Done — {total_snapshots} node snapshots recorded  [{now}]")


if __name__ == "__main__":
    main()
