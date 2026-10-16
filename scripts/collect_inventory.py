#!/usr/bin/env python3
"""
AWS Multi-Account Inventory Script — MySQL Backend
Collects EC2, Load Balancers, VPCs, and Route53 DNS records
across multiple AWS accounts and stores them in a local MySQL database.

Requirements:
    pip install boto3 mysql-connector-python

Tables created automatically:
    aws_inventory_resources  — EC2, Load Balancers, VPCs
    aws_resource_tags        — Tags for all collected resources
    aws_domains              — Route53 hosted zones + records
"""

import socket
import sys
from datetime import datetime
import argparse
import mysql.connector
from botocore.exceptions import ClientError, NoCredentialsError

# ─────────────────────────────────────────────
# CONFIG — loaded from config.ini
# ─────────────────────────────────────────────
import os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from config_loader import get_db_config, get_accounts, get_session
DB_CONFIG = get_db_config()
ACCOUNTS  = get_accounts()

# ─────────────────────────────────────────────
# ARGS - supports account arguments
# ─────────────────────────────────────────────
parser = argparse.ArgumentParser(description="AWS Inventory Collector")
parser.add_argument("--account", help="Only run for this account name (must match config.ini)", default=None)
args = parser.parse_args()

if args.account:
    ACCOUNTS = [a for a in ACCOUNTS if a["name"] == args.account]
    if not ACCOUNTS:
        print(f"[ERROR] No account named '{args.account}' found in config.ini")
        sys.exit(1)

# ─────────────────────────────────────────────
# DATABASE SETUP
# ─────────────────────────────────────────────

DDL_RESOURCES = """
CREATE TABLE IF NOT EXISTS `aws_inventory_resources` (
    `id`           INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `name`         VARCHAR(255)  NOT NULL,
    `aws_id`       VARCHAR(255)  NOT NULL,
    `ipadd`        TEXT,
    `account_name` VARCHAR(255)  NOT NULL,
    `type`         VARCHAR(50)   NOT NULL,
    `region`       VARCHAR(50)   NOT NULL,
    `extra`        TEXT,
    `last_seen`    DATETIME      NOT NULL,
    UNIQUE KEY `uq_resource` (`aws_id`, `account_name`, `type`),
    INDEX `idx_ipadd`        ((SUBSTRING(`ipadd`, 1, 100))),
    INDEX `idx_name`         (`name`),
    INDEX `idx_account`      (`account_name`),
    INDEX `idx_type`         (`type`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""

DDL_TAGS = """
CREATE TABLE IF NOT EXISTS `aws_resource_tags` (
    `id`           INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `aws_id`       VARCHAR(255)  NOT NULL,
    `account_name` VARCHAR(255)  NOT NULL,
    `tag_key`      VARCHAR(255)  NOT NULL,
    `tag_value`    TEXT,
    `last_seen`    DATETIME      NOT NULL,
    UNIQUE KEY `uq_tag` (`aws_id`, `account_name`, `tag_key`),
    INDEX `idx_aws_id`    (`aws_id`),
    INDEX `idx_account`   (`account_name`),
    INDEX `idx_tag_key`   (`tag_key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""

DDL_DOMAINS = """
CREATE TABLE IF NOT EXISTS `aws_domains` (
    `id`                INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `hosted_zone_name`  VARCHAR(255) NOT NULL,
    `hosted_zone_id`    VARCHAR(100) NOT NULL,
    `record_name`       VARCHAR(255) NOT NULL,
    `record_type`       VARCHAR(20)  NOT NULL,
    `record_alias_name` VARCHAR(255),
    `record_value`      TEXT,
    `record_ttl`        INT UNSIGNED,
    `account_name`      VARCHAR(255) NOT NULL,
    `last_seen`         DATETIME     NOT NULL,
    UNIQUE KEY `uq_record` (`hosted_zone_id`, `record_name`, `record_type`, `record_value`(200)),
    INDEX `idx_zone_name`   (`hosted_zone_name`),
    INDEX `idx_record_name` (`record_name`),
    INDEX `idx_record_value`((SUBSTRING(`record_value`, 1, 100))),
    INDEX `idx_account`     (`account_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""

UPSERT_RESOURCE = """
INSERT INTO `aws_inventory_resources`
    (`name`, `aws_id`, `ipadd`, `account_name`, `type`, `region`, `extra`, `last_seen`)
VALUES
    (%(name)s, %(aws_id)s, %(ipadd)s, %(account_name)s, %(type)s, %(region)s, %(extra)s, %(last_seen)s)
ON DUPLICATE KEY UPDATE
    `name`         = VALUES(`name`),
    `ipadd`        = VALUES(`ipadd`),
    `region`       = VALUES(`region`),
    `extra`        = VALUES(`extra`),
    `last_seen`    = VALUES(`last_seen`);
"""

UPSERT_TAG = """
INSERT INTO `aws_resource_tags`
    (`aws_id`, `account_name`, `tag_key`, `tag_value`, `last_seen`)
VALUES
    (%(aws_id)s, %(account_name)s, %(tag_key)s, %(tag_value)s, %(last_seen)s)
ON DUPLICATE KEY UPDATE
    `tag_value` = VALUES(`tag_value`),
    `last_seen` = VALUES(`last_seen`);
"""

UPSERT_DOMAIN = """
INSERT INTO `aws_domains`
    (`hosted_zone_name`, `hosted_zone_id`, `record_name`, `record_type`,
     `record_alias_name`, `record_value`, `record_ttl`, `account_name`, `last_seen`)
VALUES
    (%(hosted_zone_name)s, %(hosted_zone_id)s, %(record_name)s, %(record_type)s,
     %(record_alias_name)s, %(record_value)s, %(record_ttl)s, %(account_name)s, %(last_seen)s)
ON DUPLICATE KEY UPDATE
    `hosted_zone_name`  = VALUES(`hosted_zone_name`),
    `record_alias_name` = VALUES(`record_alias_name`),
    `record_value`      = VALUES(`record_value`),
    `record_ttl`        = VALUES(`record_ttl`),
    `account_name`      = VALUES(`account_name`),
    `last_seen`         = VALUES(`last_seen`);
"""


def init_db(cfg: dict):
    """Connect to MySQL and ensure tables exist. Returns (connection, cursor)."""
    try:
        conn = mysql.connector.connect(**cfg)
        cur  = conn.cursor()
        cur.execute(f"CREATE DATABASE IF NOT EXISTS `{cfg['database']}` CHARACTER SET utf8mb4;")
        cur.execute(f"USE `{cfg['database']}`;")
        cur.execute(DDL_RESOURCES)
        cur.execute(DDL_TAGS)
        cur.execute(DDL_DOMAINS)
        conn.commit()
        print(f"✅  Connected to MySQL — database `{cfg['database']}` ready.")
        return conn, cur
    except mysql.connector.Error as e:
        print(f"[ERROR] MySQL connection failed: {e}")
        sys.exit(1)


def upsert_tags(cur, aws_id: str, account_name: str, tags: list, now: str):
    """Upsert a list of {'Key': ..., 'Value': ...} tag dicts for a resource."""
    for tag in tags:
        key = tag.get("Key", "").strip()
        val = tag.get("Value", "").strip()
        if not key:
            continue
        cur.execute(UPSERT_TAG, {
            "aws_id":       aws_id,
            "account_name": account_name,
            "tag_key":      key,
            "tag_value":    val,
            "last_seen":    now,
        })


def delete_stale(cur, account_name: str, region: str, now: str):
    """Remove resources and tags that were not touched in the current sync run."""
    cur.execute("""
        DELETE FROM `aws_inventory_resources`
        WHERE `last_seen` < %s
          AND `account_name` = %s
          AND `region` = %s
    """, (now, account_name, region))

    # Clean up tags for aws_ids that no longer exist in the resources table
    cur.execute("""
        DELETE t FROM `aws_resource_tags` t
        LEFT JOIN `aws_inventory_resources` r
            ON t.aws_id = r.aws_id AND t.account_name = r.account_name
        WHERE r.aws_id IS NULL
          AND t.account_name = %s
    """, (account_name,))


# ─────────────────────────────────────────────
# EC2
# ─────────────────────────────────────────────

def collect_ec2(session, account_name, region, cur, now):
    count = 0
    try:
        ec2   = session.client("ec2", region_name=region)
        pager = ec2.get_paginator("describe_instances")
        for page in pager.paginate():
            for res in page["Reservations"]:
                for inst in res["Instances"]:
                    if inst["State"]["Name"] == "terminated":
                        continue

                    name = next(
                        (t["Value"] for t in inst.get("Tags", []) if t["Key"] == "Name"),
                        inst["InstanceId"],
                    )

                    # Collect all IPs (primary + any secondary on each interface)
                    ips = set()
                    for eni in inst.get("NetworkInterfaces", []):
                        for pa in eni.get("PrivateIpAddresses", []):
                            if pa.get("PrivateIpAddress"):
                                ips.add(pa["PrivateIpAddress"])
                            assoc = pa.get("Association", {})
                            if assoc.get("PublicIp"):
                                ips.add(assoc["PublicIp"])

                    sg_ids = ",".join(
                        sg.get("GroupId", "") for sg in inst.get("SecurityGroups", [])
                    )
                    cur.execute(UPSERT_RESOURCE, {
                        "name":         name,
                        "aws_id":       inst["InstanceId"],
                        "ipadd":        ", ".join(sorted(ips)),
                        "account_name": account_name,
                        "type":         "ec2",
                        "region":       region,
                        "extra":        f"State={inst['State']['Name']} | InstanceType={inst.get('InstanceType','')} | SGs={sg_ids}",
                        "last_seen":    now,
                    })

                    upsert_tags(cur, inst["InstanceId"], account_name, inst.get("Tags", []), now)
                    count += 1

    except ClientError as e:
        print(f"    [WARN] EC2 {account_name}/{region}: {e.response['Error']['Message']}")
    return count


# ─────────────────────────────────────────────
# LOAD BALANCERS
# ─────────────────────────────────────────────

def resolve_dns_ips(dns_name: str) -> str:
    """Attempt DNS resolution to get IPs. NLBs return static IPs; ALBs rotate."""
    try:
        results = socket.getaddrinfo(dns_name, None)
        ips = sorted({r[4][0] for r in results})
        return ", ".join(ips)
    except Exception:
        return ""


def collect_load_balancers(session, account_name, region, cur, now):
    count = 0

    # ── ALB / NLB ──────────────────────────────
    try:
        elb2  = session.client("elbv2", region_name=region)
        pager = elb2.get_paginator("describe_load_balancers")
        for page in pager.paginate():
            for lb in page["LoadBalancers"]:
                dns   = lb.get("DNSName", "")
                ips   = resolve_dns_ips(dns) if dns else ""
                ltype = lb.get("Type", "").lower()
                short = {"application": "alb", "network": "nlb", "gateway": "gwlb"}.get(ltype, ltype)

                # For NLBs — also grab any static EIP allocations
                if short == "nlb":
                    try:
                        az_info = lb.get("AvailabilityZones", [])
                        static  = [
                            az["LoadBalancerAddresses"][0]["IpAddress"]
                            for az in az_info
                            if az.get("LoadBalancerAddresses")
                            and az["LoadBalancerAddresses"][0].get("IpAddress")
                        ]
                        if static:
                            ips = ", ".join(sorted(set(static)))
                    except Exception:
                        pass

                arn_parts = lb["LoadBalancerArn"].split(":")
                lb_id     = "/".join(arn_parts[-1].split("/")[1:]) if arn_parts else lb["LoadBalancerName"]

                # ALBs have SecurityGroups; NLBs return an empty list — handled gracefully
                sg_ids = ",".join(lb.get("SecurityGroups", []))

                cur.execute(UPSERT_RESOURCE, {
                    "name":         lb["LoadBalancerName"],
                    "aws_id":       lb_id,
                    "ipadd":        ips,
                    "account_name": account_name,
                    "type":         short,
                    "region":       region,
                    "extra":        f"DNS={dns} | Scheme={lb.get('Scheme','')} | State={lb.get('State',{}).get('Code','')} | SGs={sg_ids}",
                    "last_seen":    now,
                })

                # Fetch tags for ALB/NLB via describe_tags (requires ARN)
                try:
                    tag_resp = elb2.describe_tags(ResourceArns=[lb["LoadBalancerArn"]])
                    for td in tag_resp.get("TagDescriptions", []):
                        upsert_tags(cur, lb_id, account_name, td.get("Tags", []), now)
                except ClientError:
                    pass

                count += 1

    except ClientError as e:
        print(f"    [WARN] ELBv2 {account_name}/{region}: {e.response['Error']['Message']}")

    # ── Classic ELB ────────────────────────────
    try:
        elb1  = session.client("elb", region_name=region)
        pager = elb1.get_paginator("describe_load_balancers")
        for page in pager.paginate():
            for lb in page["LoadBalancerDescriptions"]:
                dns    = lb.get("DNSName", "")
                ips    = resolve_dns_ips(dns) if dns else ""
                sg_ids = ",".join(lb.get("SecurityGroups", []))

                cur.execute(UPSERT_RESOURCE, {
                    "name":         lb["LoadBalancerName"],
                    "aws_id":       lb["LoadBalancerName"],
                    "ipadd":        ips,
                    "account_name": account_name,
                    "type":         "clb",
                    "region":       region,
                    "extra":        f"DNS={dns} | Scheme={lb.get('Scheme','')} | SGs={sg_ids}",
                    "last_seen":    now,
                })

                # Fetch tags for Classic ELB via describe_tags (uses name, not ARN)
                try:
                    tag_resp = elb1.describe_tags(LoadBalancerNames=[lb["LoadBalancerName"]])
                    for td in tag_resp.get("TagDescriptions", []):
                        upsert_tags(cur, lb["LoadBalancerName"], account_name, td.get("Tags", []), now)
                except ClientError:
                    pass

                count += 1

    except ClientError as e:
        print(f"    [WARN] ELB Classic {account_name}/{region}: {e.response['Error']['Message']}")

    return count


# ─────────────────────────────────────────────
# VPC
# ─────────────────────────────────────────────

def collect_vpcs(session, account_name, region, cur, now):
    count = 0
    try:
        ec2   = session.client("ec2", region_name=region)
        pager = ec2.get_paginator("describe_vpcs")
        for page in pager.paginate():
            for vpc in page["Vpcs"]:
                name = next(
                    (t["Value"] for t in vpc.get("Tags", []) if t["Key"] == "Name"),
                    vpc["VpcId"],
                )

                cidrs = [vpc.get("CidrBlock", "")]
                for assoc in vpc.get("CidrBlockAssociationSet", []):
                    c = assoc.get("CidrBlock", "")
                    if c and c not in cidrs:
                        cidrs.append(c)
                for assoc in vpc.get("Ipv6CidrBlockAssociationSet", []):
                    c = assoc.get("Ipv6CidrBlock", "")
                    if c and c not in cidrs:
                        cidrs.append(c)

                cur.execute(UPSERT_RESOURCE, {
                    "name":         name,
                    "aws_id":       vpc["VpcId"],
                    "ipadd":        ", ".join(filter(None, cidrs)),
                    "account_name": account_name,
                    "type":         "vpc",
                    "region":       region,
                    "extra":        f"State={vpc.get('State','')} | Default={vpc.get('IsDefault', False)}",
                    "last_seen":    now,
                })

                upsert_tags(cur, vpc["VpcId"], account_name, vpc.get("Tags", []), now)
                count += 1

    except ClientError as e:
        print(f"    [WARN] VPC {account_name}/{region}: {e.response['Error']['Message']}")
    return count


# ─────────────────────────────────────────────
# ROUTE 53
# ─────────────────────────────────────────────

def collect_route53(session, account_name, cur, now):
    count = 0
    try:
        r53 = session.client("route53", region_name="us-east-1")

        zones, resp = [], r53.list_hosted_zones()
        zones.extend(resp["HostedZones"])
        while resp["IsTruncated"]:
            resp = r53.list_hosted_zones(Marker=resp["NextMarker"])
            zones.extend(resp["HostedZones"])

        for zone in zones:
            zone_name = zone["Name"].rstrip(".")
            zone_id   = zone["Id"].split("/")[-1]

            pager = r53.get_paginator("list_resource_record_sets")
            for page in pager.paginate(HostedZoneId=zone_id):
                for rr in page["ResourceRecordSets"]:
                    record_name   = rr["Name"].rstrip(".")
                    rtype         = rr["Type"]
                    ttl           = rr.get("TTL")
                    alias_name    = None
                    record_values = []

                    if "AliasTarget" in rr:
                        alias_name    = rr["AliasTarget"]["DNSName"].rstrip(".")
                        record_values = [alias_name]
                    else:
                        record_values = [r["Value"] for r in rr.get("ResourceRecords", [])]

                    for val in record_values or [""]:
                        cur.execute(UPSERT_DOMAIN, {
                            "hosted_zone_name":  zone_name,
                            "hosted_zone_id":    zone_id,
                            "record_name":       record_name,
                            "record_type":       rtype,
                            "record_alias_name": alias_name,
                            "record_value":      val,
                            "record_ttl":        ttl,
                            "account_name":      account_name,
                            "last_seen":         now,
                        })
                        count += 1
    except ClientError as e:
        print(f"    [WARN] Route53 {account_name}: {e.response['Error']['Message']}")
    return count


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

def main():
    conn, cur = init_db(DB_CONFIG)
    now       = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    totals    = {"ec2": 0, "lb": 0, "vpc": 0, "dns": 0}
    r53_done  = set()

    for account in ACCOUNTS:
        print(f"\n{'─'*60}")
        print(f"🔍  Account: {account['name']}")
        print(f"{'─'*60}")

        try:
            session = get_session(account)
        except (NoCredentialsError, ClientError) as e:
            print(f"  [ERROR] Auth failed for {account['name']}: {e}")
            continue

        if account["name"] not in r53_done:
            print("  → Route53  (global)")
            n = collect_route53(session, account["name"], cur, now)
            totals["dns"] += n
            print(f"       {n} records upserted")
            r53_done.add(account["name"])

        for region in account.get("regions", ["us-east-1"]):
            print(f"  → EC2            [{region}]")
            n = collect_ec2(session, account["name"], region, cur, now)
            totals["ec2"] += n
            print(f"       {n} instances upserted")

            print(f"  → Load Balancers [{region}]")
            n = collect_load_balancers(session, account["name"], region, cur, now)
            totals["lb"] += n
            print(f"       {n} load balancers upserted")

            print(f"  → VPCs           [{region}]")
            n = collect_vpcs(session, account["name"], region, cur, now)
            totals["vpc"] += n
            print(f"       {n} VPCs upserted")

            # ── Stale-delete: remove anything not touched this run ──
            print(f"  → Stale cleanup  [{region}]")
            delete_stale(cur, account["name"], region, now)

        conn.commit()

    print(f"\n{'═'*60}")
    print(f"✅  Sync complete — {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print(f"   EC2 instances : {totals['ec2']}")
    print(f"   Load balancers: {totals['lb']}")
    print(f"   VPCs          : {totals['vpc']}")
    print(f"   DNS records   : {totals['dns']}")
    print(f"{'═'*60}")

    cur.close()
    conn.close()


if __name__ == "__main__":
    main()
