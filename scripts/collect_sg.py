#!/usr/bin/env python3
"""
AWS Security Group Collector
Collects all security groups, their rules, and tags across multiple AWS accounts.

Requirements:
    pip install boto3 mysql-connector-python
"""

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
from schema import ensure_tables
DB_CONFIG = get_db_config()
ACCOUNTS  = get_accounts()


# ─────────────────────────────────────────────
# ARGS - supports account arguments
# ─────────────────────────────────────────────
parser = argparse.ArgumentParser(description="AWS Security Group Collector")
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
UPSERT_SG = """
INSERT INTO `aws_security_groups`
    (`sg_id`, `sg_name`, `description`, `vpc_id`, `account_name`, `region`,
     `direction`, `protocol`, `from_port`, `to_port`, `target`,
     `target_type`, `description_rule`, `last_seen`)
VALUES
    (%(sg_id)s, %(sg_name)s, %(description)s, %(vpc_id)s, %(account_name)s, %(region)s,
     %(direction)s, %(protocol)s, %(from_port)s, %(to_port)s, %(target)s,
     %(target_type)s, %(description_rule)s, %(last_seen)s)
ON DUPLICATE KEY UPDATE
    `sg_name`          = VALUES(`sg_name`),
    `description`      = VALUES(`description`),
    `vpc_id`           = VALUES(`vpc_id`),
    `target_type`      = VALUES(`target_type`),
    `description_rule` = VALUES(`description_rule`),
    `last_seen`        = VALUES(`last_seen`);
"""

UPSERT_SG_TAG = """
INSERT INTO `aws_sg_tags`
    (`aws_id`, `account_name`, `tag_key`, `tag_value`, `last_seen`)
VALUES
    (%(aws_id)s, %(account_name)s, %(tag_key)s, %(tag_value)s, %(last_seen)s)
ON DUPLICATE KEY UPDATE
    `tag_value` = VALUES(`tag_value`),
    `last_seen` = VALUES(`last_seen`);
"""


# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────

def upsert_sg_tags(cur, sg_id: str, account_name: str, tags: list, now: str):
    """Upsert a list of {'Key': ..., 'Value': ...} tag dicts for a security group."""
    for tag in tags:
        key = tag.get("Key", "").strip()
        val = tag.get("Value", "").strip()
        if not key:
            continue
        cur.execute(UPSERT_SG_TAG, {
            "aws_id":       sg_id,
            "account_name": account_name,
            "tag_key":      key,
            "tag_value":    val,
            "last_seen":    now,
        })


def delete_stale(cur, account_name: str, region: str, now: str):
    """Remove SG rules and tags that were not touched in the current sync run."""
    cur.execute("""
        DELETE FROM `aws_security_groups`
        WHERE `last_seen` < %s
          AND `account_name` = %s
          AND `region` = %s
    """, (now, account_name, region))

    # Clean up tags for sg_ids that no longer exist in the SG table
    cur.execute("""
        DELETE t FROM `aws_sg_tags` t
        LEFT JOIN `aws_security_groups` s
            ON t.aws_id = s.sg_id AND t.account_name = s.account_name
        WHERE s.sg_id IS NULL
          AND t.account_name = %s
    """, (account_name,))


def normalize_protocol(proto: str) -> str:
    """Normalize protocol codes to readable names."""
    mapping = {"-1": "All", "6": "TCP", "17": "UDP", "1": "ICMP", "58": "ICMPv6"}
    return mapping.get(str(proto), str(proto).upper())


def expand_rules(sg: dict, direction: str, rules_key: str, now: str, account_name: str, region: str) -> list:
    """Expand a list of inbound or outbound rules into flat rows."""
    rows = []
    sg_id   = sg["GroupId"]
    sg_name = sg.get("GroupName", sg_id)
    desc    = sg.get("Description", "")
    vpc_id  = sg.get("VpcId", "")

    for rule in sg.get(rules_key, []):
        proto     = normalize_protocol(rule.get("IpProtocol", "-1"))
        from_port = rule.get("FromPort")
        to_port   = rule.get("ToPort")
        rule_desc = rule.get("Description", "")

        # ── IPv4 CIDRs ──────────────────────
        for cidr in rule.get("IpRanges", []):
            rows.append({
                "sg_id": sg_id, "sg_name": sg_name, "description": desc,
                "vpc_id": vpc_id, "account_name": account_name, "region": region,
                "direction": direction, "protocol": proto,
                "from_port": from_port, "to_port": to_port,
                "target": cidr.get("CidrIp", ""),
                "target_type": "cidr",
                "description_rule": cidr.get("Description", rule_desc),
                "last_seen": now,
            })

        # ── IPv6 CIDRs ──────────────────────
        for cidr in rule.get("Ipv6Ranges", []):
            rows.append({
                "sg_id": sg_id, "sg_name": sg_name, "description": desc,
                "vpc_id": vpc_id, "account_name": account_name, "region": region,
                "direction": direction, "protocol": proto,
                "from_port": from_port, "to_port": to_port,
                "target": cidr.get("CidrIpv6", ""),
                "target_type": "cidr",
                "description_rule": cidr.get("Description", rule_desc),
                "last_seen": now,
            })

        # ── Security Group references ────────
        for ref in rule.get("UserIdGroupPairs", []):
            rows.append({
                "sg_id": sg_id, "sg_name": sg_name, "description": desc,
                "vpc_id": vpc_id, "account_name": account_name, "region": region,
                "direction": direction, "protocol": proto,
                "from_port": from_port, "to_port": to_port,
                "target": ref.get("GroupId", ""),
                "target_type": "sg",
                "description_rule": ref.get("Description", rule_desc),
                "last_seen": now,
            })

        # ── Prefix Lists ─────────────────────
        for pl in rule.get("PrefixListIds", []):
            rows.append({
                "sg_id": sg_id, "sg_name": sg_name, "description": desc,
                "vpc_id": vpc_id, "account_name": account_name, "region": region,
                "direction": direction, "protocol": proto,
                "from_port": from_port, "to_port": to_port,
                "target": pl.get("PrefixListId", ""),
                "target_type": "prefix",
                "description_rule": pl.get("Description", rule_desc),
                "last_seen": now,
            })

        # ── Bare protocol rule (no target) ───
        if not any([
            rule.get("IpRanges"), rule.get("Ipv6Ranges"),
            rule.get("UserIdGroupPairs"), rule.get("PrefixListIds")
        ]):
            rows.append({
                "sg_id": sg_id, "sg_name": sg_name, "description": desc,
                "vpc_id": vpc_id, "account_name": account_name, "region": region,
                "direction": direction, "protocol": proto,
                "from_port": from_port, "to_port": to_port,
                "target": "", "target_type": "cidr",
                "description_rule": rule_desc,
                "last_seen": now,
            })

    return rows


def collect_security_groups(session, account_name, region, cur, now) -> int:
    count = 0
    try:
        ec2   = session.client("ec2", region_name=region)
        pager = ec2.get_paginator("describe_security_groups")
        for page in pager.paginate():
            for sg in page["SecurityGroups"]:
                rows  = expand_rules(sg, "inbound",  "IpPermissions",       now, account_name, region)
                rows += expand_rules(sg, "outbound", "IpPermissionsEgress", now, account_name, region)

                # If SG has no rules at all, insert a placeholder row so it still appears
                if not rows:
                    rows.append({
                        "sg_id": sg["GroupId"], "sg_name": sg.get("GroupName", ""),
                        "description": sg.get("Description", ""), "vpc_id": sg.get("VpcId", ""),
                        "account_name": account_name, "region": region,
                        "direction": "inbound", "protocol": None,
                        "from_port": None, "to_port": None,
                        "target": "", "target_type": "cidr",
                        "description_rule": "No rules defined",
                        "last_seen": now,
                    })

                for row in rows:
                    cur.execute(UPSERT_SG, row)
                    count += 1

                # Upsert tags for this SG (tags are on the SG object itself)
                upsert_sg_tags(cur, sg["GroupId"], account_name, sg.get("Tags", []), now)

    except ClientError as e:
        print(f"    [WARN] SG {account_name}/{region}: {e.response['Error']['Message']}")
    return count


def main():
    conn = mysql.connector.connect(**DB_CONFIG)
    cur  = conn.cursor()
    ensure_tables(cur, "sg")
    now  = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    total = 0

    for account in ACCOUNTS:
        print(f"\n{'─'*60}")
        print(f"🔍  Account: {account['name']}")
        print(f"{'─'*60}")

        try:
            session = get_session(account)
        except (NoCredentialsError, ClientError) as e:
            print(f"  [ERROR] Auth failed for {account['name']}: {e}")
            continue

        for region in account.get("regions", ["us-west-2"]):
            print(f"  → Security Groups [{region}]")
            n = collect_security_groups(session, account["name"], region, cur, now)
            total += n
            print(f"       {n} rules upserted")

            print(f"  → Stale cleanup   [{region}]")
            delete_stale(cur, account["name"], region, now)

        conn.commit()

    print(f"\n{'═'*60}")
    print(f"✅  Done — {total} security group rules upserted")
    print(f"{'═'*60}")

    cur.close()
    conn.close()


if __name__ == "__main__":
    main()
