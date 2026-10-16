#!/usr/bin/env python3
"""
AWS Network Collector
Collects Subnets, Route Tables, Network ACLs, NAT Gateways,
Internet Gateways, VPC Peering Connections, and Transit Gateways
across multiple AWS accounts.

Requirements:
    pip install boto3 mysql-connector-python
"""

import sys
from datetime import datetime

import argparse

import mysql.connector
from botocore.exceptions import ClientError, NoCredentialsError

import os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from config_loader import get_db_config, get_accounts, get_session
from schema import ensure_tables

DB_CONFIG = get_db_config()
ACCOUNTS  = get_accounts()

# ─────────────────────────────────────────────
# ARGS - supports account argument
# ─────────────────────────────────────────────
parser = argparse.ArgumentParser(description="AWS Network Collector")
parser.add_argument("--account", help="Only run for this account name (must match config.ini)", default=None)
args = parser.parse_args()

if args.account:
    ACCOUNTS = [a for a in ACCOUNTS if a["name"] == args.account]
    if not ACCOUNTS:
        print(f"[ERROR] No account named '{args.account}' found in config.ini")
        sys.exit(1)


# ─────────────────────────────────────────────
# SQL
# ─────────────────────────────────────────────

UPSERT_SUBNET = """
INSERT INTO `aws_subnets`
    (`subnet_id`, `name`, `vpc_id`, `cidr_block`, `availability_zone`,
     `available_ips`, `state`, `map_public_ip`, `default_for_az`,
     `account_name`, `region`, `last_seen`)
VALUES
    (%(subnet_id)s, %(name)s, %(vpc_id)s, %(cidr_block)s, %(availability_zone)s,
     %(available_ips)s, %(state)s, %(map_public_ip)s, %(default_for_az)s,
     %(account_name)s, %(region)s, %(last_seen)s)
ON DUPLICATE KEY UPDATE
    `name`             = VALUES(`name`),
    `cidr_block`       = VALUES(`cidr_block`),
    `availability_zone`= VALUES(`availability_zone`),
    `available_ips`    = VALUES(`available_ips`),
    `state`            = VALUES(`state`),
    `map_public_ip`    = VALUES(`map_public_ip`),
    `default_for_az`   = VALUES(`default_for_az`),
    `last_seen`        = VALUES(`last_seen`);
"""

UPSERT_SUBNET_TAG = """
INSERT INTO `aws_subnet_tags`
    (`aws_id`, `account_name`, `tag_key`, `tag_value`, `last_seen`)
VALUES
    (%(aws_id)s, %(account_name)s, %(tag_key)s, %(tag_value)s, %(last_seen)s)
ON DUPLICATE KEY UPDATE
    `tag_value` = VALUES(`tag_value`),
    `last_seen` = VALUES(`last_seen`);
"""

UPSERT_ROUTE = """
INSERT INTO `aws_route_tables`
    (`route_table_id`, `name`, `vpc_id`, `associated_subnets`, `main`,
     `destination`, `target`, `target_type`, `state`,
     `account_name`, `region`, `last_seen`)
VALUES
    (%(route_table_id)s, %(name)s, %(vpc_id)s, %(associated_subnets)s, %(main)s,
     %(destination)s, %(target)s, %(target_type)s, %(state)s,
     %(account_name)s, %(region)s, %(last_seen)s)
ON DUPLICATE KEY UPDATE
    `name`               = VALUES(`name`),
    `associated_subnets` = VALUES(`associated_subnets`),
    `main`               = VALUES(`main`),
    `target`             = VALUES(`target`),
    `target_type`        = VALUES(`target_type`),
    `state`              = VALUES(`state`),
    `last_seen`          = VALUES(`last_seen`);
"""

UPSERT_NACL = """
INSERT INTO `aws_network_acls`
    (`nacl_id`, `name`, `vpc_id`, `associated_subnets`, `is_default`,
     `rule_number`, `direction`, `protocol`, `from_port`, `to_port`,
     `cidr_block`, `action`, `account_name`, `region`, `last_seen`)
VALUES
    (%(nacl_id)s, %(name)s, %(vpc_id)s, %(associated_subnets)s, %(is_default)s,
     %(rule_number)s, %(direction)s, %(protocol)s, %(from_port)s, %(to_port)s,
     %(cidr_block)s, %(action)s, %(account_name)s, %(region)s, %(last_seen)s)
ON DUPLICATE KEY UPDATE
    `name`               = VALUES(`name`),
    `associated_subnets` = VALUES(`associated_subnets`),
    `is_default`         = VALUES(`is_default`),
    `protocol`           = VALUES(`protocol`),
    `from_port`          = VALUES(`from_port`),
    `to_port`            = VALUES(`to_port`),
    `cidr_block`         = VALUES(`cidr_block`),
    `action`             = VALUES(`action`),
    `last_seen`          = VALUES(`last_seen`);
"""

UPSERT_NAT = """
INSERT INTO `aws_nat_gateways`
    (`nat_gw_id`, `name`, `vpc_id`, `subnet_id`, `state`, `type`,
     `public_ip`, `private_ip`, `account_name`, `region`, `last_seen`)
VALUES
    (%(nat_gw_id)s, %(name)s, %(vpc_id)s, %(subnet_id)s, %(state)s, %(type)s,
     %(public_ip)s, %(private_ip)s, %(account_name)s, %(region)s, %(last_seen)s)
ON DUPLICATE KEY UPDATE
    `name`       = VALUES(`name`),
    `state`      = VALUES(`state`),
    `public_ip`  = VALUES(`public_ip`),
    `private_ip` = VALUES(`private_ip`),
    `last_seen`  = VALUES(`last_seen`);
"""

UPSERT_IGW = """
INSERT INTO `aws_internet_gateways`
    (`igw_id`, `name`, `vpc_id`, `state`, `account_name`, `region`, `last_seen`)
VALUES
    (%(igw_id)s, %(name)s, %(vpc_id)s, %(state)s, %(account_name)s, %(region)s, %(last_seen)s)
ON DUPLICATE KEY UPDATE
    `name`     = VALUES(`name`),
    `vpc_id`   = VALUES(`vpc_id`),
    `state`    = VALUES(`state`),
    `last_seen`= VALUES(`last_seen`);
"""

UPSERT_PEERING = """
INSERT INTO `aws_vpc_peering`
    (`peering_id`, `name`, `status`,
     `requester_vpc_id`, `requester_cidr`, `requester_account`, `requester_region`,
     `accepter_vpc_id`,  `accepter_cidr`,  `accepter_account`,  `accepter_region`,
     `account_name`, `region`, `last_seen`)
VALUES
    (%(peering_id)s, %(name)s, %(status)s,
     %(requester_vpc_id)s, %(requester_cidr)s, %(requester_account)s, %(requester_region)s,
     %(accepter_vpc_id)s,  %(accepter_cidr)s,  %(accepter_account)s,  %(accepter_region)s,
     %(account_name)s, %(region)s, %(last_seen)s)
ON DUPLICATE KEY UPDATE
    `name`              = VALUES(`name`),
    `status`            = VALUES(`status`),
    `requester_cidr`    = VALUES(`requester_cidr`),
    `accepter_cidr`     = VALUES(`accepter_cidr`),
    `last_seen`         = VALUES(`last_seen`);
"""

UPSERT_TGW = """
INSERT INTO `aws_transit_gateways`
    (`tgw_id`, `name`, `description`, `state`, `account_name`, `region`, `last_seen`)
VALUES
    (%(tgw_id)s, %(name)s, %(description)s, %(state)s, %(account_name)s, %(region)s, %(last_seen)s)
ON DUPLICATE KEY UPDATE
    `name`        = VALUES(`name`),
    `description` = VALUES(`description`),
    `state`       = VALUES(`state`),
    `last_seen`   = VALUES(`last_seen`);
"""

UPSERT_TGW_ATTACH = """
INSERT INTO `aws_tgw_attachments`
    (`attachment_id`, `tgw_id`, `resource_type`, `resource_id`,
     `resource_account`, `state`, `account_name`, `region`, `last_seen`)
VALUES
    (%(attachment_id)s, %(tgw_id)s, %(resource_type)s, %(resource_id)s,
     %(resource_account)s, %(state)s, %(account_name)s, %(region)s, %(last_seen)s)
ON DUPLICATE KEY UPDATE
    `state`            = VALUES(`state`),
    `resource_type`    = VALUES(`resource_type`),
    `resource_id`      = VALUES(`resource_id`),
    `resource_account` = VALUES(`resource_account`),
    `last_seen`        = VALUES(`last_seen`);
"""


# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────

def get_tag(tags: list, key: str, default: str = "") -> str:
    return next((t["Value"] for t in tags if t["Key"] == key), default)


def upsert_tags(cur, aws_id: str, account_name: str, tags: list, now: str, table: str = "aws_subnet_tags"):
    for tag in tags:
        key = tag.get("Key", "").strip()
        val = tag.get("Value", "").strip()
        if not key:
            continue
        cur.execute(f"""
            INSERT INTO `{table}`
                (`aws_id`, `account_name`, `tag_key`, `tag_value`, `last_seen`)
            VALUES
                (%s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
                `tag_value` = VALUES(`tag_value`),
                `last_seen` = VALUES(`last_seen`)
        """, (aws_id, account_name, key, val, now))


def normalize_protocol(proto: str) -> str:
    mapping = {"-1": "All", "6": "TCP", "17": "UDP", "1": "ICMP", "58": "ICMPv6"}
    return mapping.get(str(proto), str(proto).upper())


def delete_stale(cur, account_name: str, region: str, now: str):
    """Remove network resources not touched in the current sync run."""
    tables = [
        "aws_subnets", "aws_route_tables", "aws_network_acls",
        "aws_nat_gateways", "aws_internet_gateways",
        "aws_vpc_peering", "aws_transit_gateways", "aws_tgw_attachments",
    ]
    for table in tables:
        cur.execute(f"""
            DELETE FROM `{table}`
            WHERE `last_seen` < %s
              AND `account_name` = %s
              AND `region` = %s
        """, (now, account_name, region))

    # Clean up subnet tags for subnet_ids that no longer exist
    cur.execute("""
        DELETE t FROM `aws_subnet_tags` t
        LEFT JOIN `aws_subnets` s
            ON t.aws_id = s.subnet_id AND t.account_name = s.account_name
        WHERE s.subnet_id IS NULL
          AND t.account_name = %s
    """, (account_name,))


# ─────────────────────────────────────────────
# COLLECTORS
# ─────────────────────────────────────────────

def collect_subnets(session, account_name, region, cur, now) -> int:
    count = 0
    try:
        ec2   = session.client("ec2", region_name=region)
        pager = ec2.get_paginator("describe_subnets")
        for page in pager.paginate():
            for s in page["Subnets"]:
                tags = s.get("Tags", [])
                name = get_tag(tags, "Name", s["SubnetId"])
                cur.execute(UPSERT_SUBNET, {
                    "subnet_id":         s["SubnetId"],
                    "name":              name,
                    "vpc_id":            s["VpcId"],
                    "cidr_block":        s.get("CidrBlock", ""),
                    "availability_zone": s.get("AvailabilityZone", ""),
                    "available_ips":     s.get("AvailableIpAddressCount", 0),
                    "state":             s.get("State", ""),
                    "map_public_ip":     1 if s.get("MapPublicIpOnLaunch") else 0,
                    "default_for_az":    1 if s.get("DefaultForAz") else 0,
                    "account_name":      account_name,
                    "region":            region,
                    "last_seen":         now,
                })
                upsert_tags(cur, s["SubnetId"], account_name, tags, now, "aws_subnet_tags")
                count += 1
    except ClientError as e:
        print(f"    [WARN] Subnets {account_name}/{region}: {e.response['Error']['Message']}")
    return count


def collect_route_tables(session, account_name, region, cur, now) -> int:
    count = 0
    try:
        ec2   = session.client("ec2", region_name=region)
        pager = ec2.get_paginator("describe_route_tables")
        for page in pager.paginate():
            for rt in page["RouteTables"]:
                tags = rt.get("Tags", [])
                name = get_tag(tags, "Name", rt["RouteTableId"])

                # Collect associated subnet IDs
                assoc_subnets = ",".join(
                    a["SubnetId"] for a in rt.get("Associations", [])
                    if a.get("SubnetId")
                )
                is_main = any(
                    a.get("Main") for a in rt.get("Associations", [])
                )

                # One row per route
                routes = rt.get("Routes", [])
                if not routes:
                    # Insert a placeholder so the RT still appears
                    cur.execute(UPSERT_ROUTE, {
                        "route_table_id":   rt["RouteTableId"],
                        "name":             name,
                        "vpc_id":           rt["VpcId"],
                        "associated_subnets": assoc_subnets,
                        "main":             1 if is_main else 0,
                        "destination":      "",
                        "target":           "",
                        "target_type":      "",
                        "state":            "",
                        "account_name":     account_name,
                        "region":           region,
                        "last_seen":        now,
                    })
                    count += 1
                else:
                    for route in routes:
                        dest = (
                            route.get("DestinationCidrBlock") or
                            route.get("DestinationIpv6CidrBlock") or
                            route.get("DestinationPrefixListId", "")
                        )
                        # Determine target and type
                        target, ttype = "", ""
                        if route.get("GatewayId"):
                            target = route["GatewayId"]
                            ttype  = "igw" if target.startswith("igw-") else "local" if target == "local" else "gateway"
                        elif route.get("NatGatewayId"):
                            target, ttype = route["NatGatewayId"], "nat"
                        elif route.get("TransitGatewayId"):
                            target, ttype = route["TransitGatewayId"], "tgw"
                        elif route.get("VpcPeeringConnectionId"):
                            target, ttype = route["VpcPeeringConnectionId"], "peering"
                        elif route.get("NetworkInterfaceId"):
                            target, ttype = route["NetworkInterfaceId"], "eni"
                        elif route.get("InstanceId"):
                            target, ttype = route["InstanceId"], "instance"
                        elif route.get("EgressOnlyInternetGatewayId"):
                            target, ttype = route["EgressOnlyInternetGatewayId"], "eigw"

                        cur.execute(UPSERT_ROUTE, {
                            "route_table_id":    rt["RouteTableId"],
                            "name":              name,
                            "vpc_id":            rt["VpcId"],
                            "associated_subnets": assoc_subnets,
                            "main":              1 if is_main else 0,
                            "destination":       dest,
                            "target":            target,
                            "target_type":       ttype,
                            "state":             route.get("State", ""),
                            "account_name":      account_name,
                            "region":            region,
                            "last_seen":         now,
                        })
                        count += 1
    except ClientError as e:
        print(f"    [WARN] Route Tables {account_name}/{region}: {e.response['Error']['Message']}")
    return count


def collect_network_acls(session, account_name, region, cur, now) -> int:
    count = 0
    try:
        ec2   = session.client("ec2", region_name=region)
        pager = ec2.get_paginator("describe_network_acls")
        for page in pager.paginate():
            for nacl in page["NetworkAcls"]:
                tags = nacl.get("Tags", [])
                name = get_tag(tags, "Name", nacl["NetworkAclId"])

                assoc_subnets = ",".join(
                    a["SubnetId"] for a in nacl.get("Associations", [])
                    if a.get("SubnetId")
                )

                # Combine inbound + outbound entries
                entries = [
                    (e, "inbound")  for e in nacl.get("Entries", []) if not e.get("Egress")
                ] + [
                    (e, "outbound") for e in nacl.get("Entries", []) if e.get("Egress")
                ]

                if not entries:
                    cur.execute(UPSERT_NACL, {
                        "nacl_id": nacl["NetworkAclId"], "name": name,
                        "vpc_id": nacl["VpcId"], "associated_subnets": assoc_subnets,
                        "is_default": 1 if nacl.get("IsDefault") else 0,
                        "rule_number": None, "direction": None, "protocol": None,
                        "from_port": None, "to_port": None, "cidr_block": None,
                        "action": None, "account_name": account_name,
                        "region": region, "last_seen": now,
                    })
                    count += 1
                else:
                    for entry, direction in entries:
                        proto = normalize_protocol(entry.get("Protocol", "-1"))
                        pr    = entry.get("PortRange", {})
                        cidr  = entry.get("CidrBlock") or entry.get("Ipv6CidrBlock", "")
                        cur.execute(UPSERT_NACL, {
                            "nacl_id":            nacl["NetworkAclId"],
                            "name":               name,
                            "vpc_id":             nacl["VpcId"],
                            "associated_subnets": assoc_subnets,
                            "is_default":         1 if nacl.get("IsDefault") else 0,
                            "rule_number":        entry.get("RuleNumber"),
                            "direction":          direction,
                            "protocol":           proto,
                            "from_port":          pr.get("From"),
                            "to_port":            pr.get("To"),
                            "cidr_block":         cidr,
                            "action":             entry.get("RuleAction", ""),
                            "account_name":       account_name,
                            "region":             region,
                            "last_seen":          now,
                        })
                        count += 1
    except ClientError as e:
        print(f"    [WARN] NACLs {account_name}/{region}: {e.response['Error']['Message']}")
    return count


def collect_nat_gateways(session, account_name, region, cur, now) -> int:
    count = 0
    try:
        ec2   = session.client("ec2", region_name=region)
        pager = ec2.get_paginator("describe_nat_gateways")
        for page in pager.paginate():
            for nat in page["NatGateways"]:
                if nat.get("State") == "deleted":
                    continue
                tags   = nat.get("Tags", [])
                name   = get_tag(tags, "Name", nat["NatGatewayId"])
                addrs  = nat.get("NatGatewayAddresses", [{}])
                pub_ip = addrs[0].get("PublicIp", "") if addrs else ""
                pri_ip = addrs[0].get("PrivateIp", "") if addrs else ""

                cur.execute(UPSERT_NAT, {
                    "nat_gw_id":    nat["NatGatewayId"],
                    "name":         name,
                    "vpc_id":       nat.get("VpcId", ""),
                    "subnet_id":    nat.get("SubnetId", ""),
                    "state":        nat.get("State", ""),
                    "type":         nat.get("ConnectivityType", "public"),
                    "public_ip":    pub_ip,
                    "private_ip":   pri_ip,
                    "account_name": account_name,
                    "region":       region,
                    "last_seen":    now,
                })
                count += 1
    except ClientError as e:
        print(f"    [WARN] NAT GWs {account_name}/{region}: {e.response['Error']['Message']}")
    return count


def collect_internet_gateways(session, account_name, region, cur, now) -> int:
    count = 0
    try:
        ec2   = session.client("ec2", region_name=region)
        pager = ec2.get_paginator("describe_internet_gateways")
        for page in pager.paginate():
            for igw in page["InternetGateways"]:
                tags  = igw.get("Tags", [])
                name  = get_tag(tags, "Name", igw["InternetGatewayId"])
                atts  = igw.get("Attachments", [{}])
                vpc   = atts[0].get("VpcId", "") if atts else ""
                state = atts[0].get("State", "detached") if atts else "detached"

                cur.execute(UPSERT_IGW, {
                    "igw_id":       igw["InternetGatewayId"],
                    "name":         name,
                    "vpc_id":       vpc,
                    "state":        state,
                    "account_name": account_name,
                    "region":       region,
                    "last_seen":    now,
                })
                count += 1
    except ClientError as e:
        print(f"    [WARN] IGWs {account_name}/{region}: {e.response['Error']['Message']}")
    return count


def collect_vpc_peering(session, account_name, region, cur, now) -> int:
    count = 0
    try:
        ec2   = session.client("ec2", region_name=region)
        pager = ec2.get_paginator("describe_vpc_peering_connections")
        for page in pager.paginate():
            for pcx in page["VpcPeeringConnections"]:
                status = pcx.get("Status", {}).get("Code", "")
                if status in ("deleted", "rejected", "failed", "expired"):
                    continue
                tags = pcx.get("Tags", [])
                name = get_tag(tags, "Name", pcx["VpcPeeringConnectionId"])
                req  = pcx.get("RequesterVpcInfo", {})
                acc  = pcx.get("AccepterVpcInfo", {})

                cur.execute(UPSERT_PEERING, {
                    "peering_id":        pcx["VpcPeeringConnectionId"],
                    "name":              name,
                    "status":            status,
                    "requester_vpc_id":  req.get("VpcId", ""),
                    "requester_cidr":    req.get("CidrBlock", ""),
                    "requester_account": req.get("OwnerId", ""),
                    "requester_region":  req.get("Region", ""),
                    "accepter_vpc_id":   acc.get("VpcId", ""),
                    "accepter_cidr":     acc.get("CidrBlock", ""),
                    "accepter_account":  acc.get("OwnerId", ""),
                    "accepter_region":   acc.get("Region", ""),
                    "account_name":      account_name,
                    "region":            region,
                    "last_seen":         now,
                })
                count += 1
    except ClientError as e:
        print(f"    [WARN] VPC Peering {account_name}/{region}: {e.response['Error']['Message']}")
    return count


def collect_transit_gateways(session, account_name, region, cur, now) -> int:
    count = 0
    try:
        ec2   = session.client("ec2", region_name=region)
        pager = ec2.get_paginator("describe_transit_gateways")
        for page in pager.paginate():
            for tgw in page["TransitGateways"]:
                if tgw.get("State") == "deleted":
                    continue
                tags = tgw.get("Tags", [])
                name = get_tag(tags, "Name", tgw["TransitGatewayId"])

                cur.execute(UPSERT_TGW, {
                    "tgw_id":       tgw["TransitGatewayId"],
                    "name":         name,
                    "description":  tgw.get("Description", ""),
                    "state":        tgw.get("State", ""),
                    "account_name": account_name,
                    "region":       region,
                    "last_seen":    now,
                })
                count += 1

        # Collect attachments for TGWs visible in this account/region
        apager = ec2.get_paginator("describe_transit_gateway_attachments")
        for page in apager.paginate():
            for att in page["TransitGatewayAttachments"]:
                if att.get("State") == "deleted":
                    continue
                cur.execute(UPSERT_TGW_ATTACH, {
                    "attachment_id":    att["TransitGatewayAttachmentId"],
                    "tgw_id":           att["TransitGatewayId"],
                    "resource_type":    att.get("ResourceType", ""),
                    "resource_id":      att.get("ResourceId", ""),
                    "resource_account": att.get("ResourceOwnerId", ""),
                    "state":            att.get("State", ""),
                    "account_name":     account_name,
                    "region":           region,
                    "last_seen":        now,
                })
                count += 1

    except ClientError as e:
        print(f"    [WARN] TGWs {account_name}/{region}: {e.response['Error']['Message']}")
    return count


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

def main():
    conn = mysql.connector.connect(**DB_CONFIG)
    cur  = conn.cursor()
    ensure_tables(cur, "network")
    cur.execute(f"USE `{DB_CONFIG['database']}`;")
    now  = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    totals = {
        "subnets": 0, "routes": 0, "nacls": 0,
        "nat_gws": 0, "igws": 0, "peering": 0, "tgws": 0,
    }

    for account in ACCOUNTS:
        print(f"\n{'─'*60}")
        print(f"🔍  Account: {account['name']}")
        print(f"{'─'*60}")

        try:
            session = get_session(account)
        except (NoCredentialsError, ClientError) as e:
            print(f"  [ERROR] Auth failed for {account['name']}: {e}")
            continue

        for region in account.get("regions", ["us-east-1"]):
            print(f"  → Subnets           [{region}]")
            n = collect_subnets(session, account["name"], region, cur, now)
            totals["subnets"] += n
            print(f"       {n} upserted")

            print(f"  → Route Tables      [{region}]")
            n = collect_route_tables(session, account["name"], region, cur, now)
            totals["routes"] += n
            print(f"       {n} upserted")

            print(f"  → Network ACLs      [{region}]")
            n = collect_network_acls(session, account["name"], region, cur, now)
            totals["nacls"] += n
            print(f"       {n} upserted")

            print(f"  → NAT Gateways      [{region}]")
            n = collect_nat_gateways(session, account["name"], region, cur, now)
            totals["nat_gws"] += n
            print(f"       {n} upserted")

            print(f"  → Internet Gateways [{region}]")
            n = collect_internet_gateways(session, account["name"], region, cur, now)
            totals["igws"] += n
            print(f"       {n} upserted")

            print(f"  → VPC Peering       [{region}]")
            n = collect_vpc_peering(session, account["name"], region, cur, now)
            totals["peering"] += n
            print(f"       {n} upserted")

            print(f"  → Transit Gateways  [{region}]")
            n = collect_transit_gateways(session, account["name"], region, cur, now)
            totals["tgws"] += n
            print(f"       {n} upserted")

            print(f"  → Stale cleanup     [{region}]")
            delete_stale(cur, account["name"], region, now)

        conn.commit()

    print(f"\n{'═'*60}")
    print(f"✅  Sync complete — {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print(f"   Subnets           : {totals['subnets']}")
    print(f"   Route table rows  : {totals['routes']}")
    print(f"   NACL rules        : {totals['nacls']}")
    print(f"   NAT Gateways      : {totals['nat_gws']}")
    print(f"   Internet Gateways : {totals['igws']}")
    print(f"   VPC Peering       : {totals['peering']}")
    print(f"   TGW rows          : {totals['tgws']}")
    print(f"{'═'*60}")

    cur.close()
    conn.close()


if __name__ == "__main__":
    main()
