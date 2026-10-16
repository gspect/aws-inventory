#!/usr/bin/env python3
"""
AWS Load Balancer Collector
Collects Application, Network, and Classic Load Balancers — including
listeners, listener rules (ALB only), target groups, target health,
and Classic LB instance membership — across all configured AWS accounts.

Tables created/used:
    aws_load_balancers       — ALB + NLB + CLB summary rows
    aws_lb_listeners         — listeners for all LB types
    aws_lb_listener_rules    — ALB listener rules (conditions + actions)
    aws_lb_target_groups     — target groups (ALB + NLB)
    aws_lb_tg_targets        — registered targets and health state
    aws_clb_instances        — Classic LB instance membership
    aws_lb_tags              — tags for LBs and target groups

Requirements:
    pip install boto3 mysql-connector-python
"""

import sys
import json
import argparse
from datetime import datetime

import mysql.connector
from botocore.exceptions import ClientError, NoCredentialsError

import os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from config_loader import get_db_config, get_accounts, get_session

DB_CONFIG = get_db_config()
ACCOUNTS  = get_accounts()


# ─────────────────────────────────────────────
# ARGS
# ─────────────────────────────────────────────

parser = argparse.ArgumentParser(description="AWS Load Balancer Collector")
parser.add_argument("--account", help="Only run for this account name (must match config.ini)", default=None)
args = parser.parse_args()

if args.account:
    ACCOUNTS = [a for a in ACCOUNTS if a["name"] == args.account]
    if not ACCOUNTS:
        print(f"[ERROR] No account named '{args.account}' found in config.ini")
        sys.exit(1)


# ─────────────────────────────────────────────
# DDL — auto-create tables on first run
# ─────────────────────────────────────────────

DDL = """
CREATE TABLE IF NOT EXISTS `aws_load_balancers` (
    `lb_arn`        VARCHAR(512)  NOT NULL,
    `lb_name`       VARCHAR(255)  NOT NULL,
    `lb_type`       VARCHAR(20)   NOT NULL COMMENT 'application | network | classic',
    `dns_name`      VARCHAR(512)  NOT NULL,
    `scheme`        VARCHAR(30)   DEFAULT NULL COMMENT 'internet-facing | internal',
    `state`         VARCHAR(30)   DEFAULT NULL,
    `vpc_id`        VARCHAR(50)   DEFAULT NULL,
    `account_name`  VARCHAR(100)  NOT NULL,
    `region`        VARCHAR(30)   NOT NULL,
    `last_seen`     DATETIME      NOT NULL,
    PRIMARY KEY (`lb_arn`),
    KEY `idx_lb_dns`  (`dns_name`(128)),
    KEY `idx_lb_name` (`lb_name`(100)),
    KEY `idx_lb_acct` (`account_name`, `region`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `aws_lb_listeners` (
    `listener_arn`  VARCHAR(512)  NOT NULL,
    `lb_arn`        VARCHAR(512)  NOT NULL,
    `lb_type`       VARCHAR(20)   NOT NULL,
    `protocol`      VARCHAR(20)   DEFAULT NULL,
    `port`          SMALLINT UNSIGNED DEFAULT NULL,
    `ssl_policy`    VARCHAR(100)  DEFAULT NULL,
    `default_action_type`    VARCHAR(50)  DEFAULT NULL COMMENT 'forward | redirect | fixed-response',
    `default_action_target`  VARCHAR(512) DEFAULT NULL COMMENT 'TG ARN or redirect URL',
    `account_name`  VARCHAR(100)  NOT NULL,
    `region`        VARCHAR(30)   NOT NULL,
    `last_seen`     DATETIME      NOT NULL,
    PRIMARY KEY (`listener_arn`),
    KEY `idx_listener_lb` (`lb_arn`(128))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `aws_lb_listener_rules` (
    `rule_arn`          VARCHAR(512)  NOT NULL,
    `listener_arn`      VARCHAR(512)  NOT NULL,
    `lb_arn`            VARCHAR(512)  NOT NULL,
    `priority`          VARCHAR(20)   NOT NULL COMMENT 'integer string or "default"',
    `is_default`        TINYINT(1)    NOT NULL DEFAULT 0,
    `condition_type`    VARCHAR(50)   DEFAULT NULL COMMENT 'host-header | path-pattern | etc.',
    `condition_values`  TEXT          DEFAULT NULL COMMENT 'JSON array of match strings',
    `action_type`       VARCHAR(50)   DEFAULT NULL COMMENT 'forward | redirect | fixed-response | authenticate-cognito | authenticate-oidc',
    `action_target`     VARCHAR(512)  DEFAULT NULL COMMENT 'TG ARN for forward; null for redirect',
    `redirect_host`     VARCHAR(255)  DEFAULT NULL,
    `redirect_path`     VARCHAR(255)  DEFAULT NULL,
    `redirect_port`     VARCHAR(10)   DEFAULT NULL,
    `redirect_protocol` VARCHAR(10)   DEFAULT NULL,
    `redirect_status`   VARCHAR(10)   DEFAULT NULL COMMENT 'HTTP_301 | HTTP_302',
    `fixed_status`      VARCHAR(10)   DEFAULT NULL,
    `fixed_body`        TEXT          DEFAULT NULL,
    `account_name`      VARCHAR(100)  NOT NULL,
    `region`            VARCHAR(30)   NOT NULL,
    `last_seen`         DATETIME      NOT NULL,
    PRIMARY KEY (`rule_arn`),
    KEY `idx_rule_listener` (`listener_arn`(128)),
    KEY `idx_rule_lb`       (`lb_arn`(128))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `aws_lb_target_groups` (
    `tg_arn`            VARCHAR(512)  NOT NULL,
    `tg_name`           VARCHAR(255)  NOT NULL,
    `target_type`       VARCHAR(20)   DEFAULT NULL COMMENT 'instance | ip | lambda | alb',
    `protocol`          VARCHAR(20)   DEFAULT NULL,
    `port`              SMALLINT UNSIGNED DEFAULT NULL,
    `vpc_id`            VARCHAR(50)   DEFAULT NULL,
    `health_check_protocol`  VARCHAR(20)  DEFAULT NULL,
    `health_check_path`      VARCHAR(512) DEFAULT NULL,
    `health_check_port`      VARCHAR(20)  DEFAULT NULL,
    `healthy_threshold`      TINYINT      DEFAULT NULL,
    `unhealthy_threshold`    TINYINT      DEFAULT NULL,
    `lb_arns`           TEXT          DEFAULT NULL COMMENT 'JSON array of attached LB ARNs',
    `account_name`      VARCHAR(100)  NOT NULL,
    `region`            VARCHAR(30)   NOT NULL,
    `last_seen`         DATETIME      NOT NULL,
    PRIMARY KEY (`tg_arn`),
    KEY `idx_tg_name` (`tg_name`(100)),
    KEY `idx_tg_acct` (`account_name`, `region`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `aws_lb_tg_targets` (
    `tg_arn`        VARCHAR(512)  NOT NULL,
    `target_id`     VARCHAR(255)  NOT NULL COMMENT 'instance ID, IP, or Lambda ARN',
    `port`          SMALLINT UNSIGNED DEFAULT NULL,
    `az`            VARCHAR(50)   DEFAULT NULL,
    `health_state`  VARCHAR(30)   DEFAULT NULL,
    `health_reason` VARCHAR(255)  DEFAULT NULL,
    `account_name`  VARCHAR(100)  NOT NULL,
    `region`        VARCHAR(30)   NOT NULL,
    `last_seen`     DATETIME      NOT NULL,
    PRIMARY KEY (`tg_arn`(256), `target_id`(100)),
    KEY `idx_tgt_id`   (`target_id`(100)),
    KEY `idx_tgt_acct` (`account_name`, `region`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `aws_clb_instances` (
    `lb_name`       VARCHAR(255)  NOT NULL,
    `instance_id`   VARCHAR(50)   NOT NULL,
    `state`         VARCHAR(30)   DEFAULT NULL,
    `reason_code`   VARCHAR(100)  DEFAULT NULL,
    `description`   VARCHAR(255)  DEFAULT NULL,
    `account_name`  VARCHAR(100)  NOT NULL,
    `region`        VARCHAR(30)   NOT NULL,
    `last_seen`     DATETIME      NOT NULL,
    PRIMARY KEY (`lb_name`(100), `instance_id`, `account_name`(50), `region`),
    KEY `idx_clb_inst` (`instance_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `aws_lb_tags` (
    `aws_id`        VARCHAR(512)  NOT NULL,
    `aws_id_type`   VARCHAR(20)   NOT NULL COMMENT 'lb | tg',
    `account_name`  VARCHAR(100)  NOT NULL,
    `tag_key`       VARCHAR(255)  NOT NULL,
    `tag_value`     VARCHAR(512)  DEFAULT NULL,
    `last_seen`     DATETIME      NOT NULL,
    PRIMARY KEY (`aws_id`(256), `tag_key`(100), `account_name`(50)),
    KEY `idx_lbtag_acct` (`account_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""


# ─────────────────────────────────────────────
# SQL
# ─────────────────────────────────────────────

UPSERT_LB = """
INSERT INTO `aws_load_balancers`
    (`lb_arn`, `lb_name`, `lb_type`, `dns_name`, `scheme`, `state`,
     `vpc_id`, `account_name`, `region`, `last_seen`)
VALUES
    (%(lb_arn)s, %(lb_name)s, %(lb_type)s, %(dns_name)s, %(scheme)s, %(state)s,
     %(vpc_id)s, %(account_name)s, %(region)s, %(last_seen)s)
ON DUPLICATE KEY UPDATE
    `lb_name`  = VALUES(`lb_name`),
    `dns_name` = VALUES(`dns_name`),
    `scheme`   = VALUES(`scheme`),
    `state`    = VALUES(`state`),
    `vpc_id`   = VALUES(`vpc_id`),
    `last_seen`= VALUES(`last_seen`);
"""

UPSERT_LISTENER = """
INSERT INTO `aws_lb_listeners`
    (`listener_arn`, `lb_arn`, `lb_type`, `protocol`, `port`, `ssl_policy`,
     `default_action_type`, `default_action_target`,
     `account_name`, `region`, `last_seen`)
VALUES
    (%(listener_arn)s, %(lb_arn)s, %(lb_type)s, %(protocol)s, %(port)s, %(ssl_policy)s,
     %(default_action_type)s, %(default_action_target)s,
     %(account_name)s, %(region)s, %(last_seen)s)
ON DUPLICATE KEY UPDATE
    `protocol`             = VALUES(`protocol`),
    `port`                 = VALUES(`port`),
    `ssl_policy`           = VALUES(`ssl_policy`),
    `default_action_type`  = VALUES(`default_action_type`),
    `default_action_target`= VALUES(`default_action_target`),
    `last_seen`            = VALUES(`last_seen`);
"""

UPSERT_RULE = """
INSERT INTO `aws_lb_listener_rules`
    (`rule_arn`, `listener_arn`, `lb_arn`, `priority`, `is_default`,
     `condition_type`, `condition_values`,
     `action_type`, `action_target`,
     `redirect_host`, `redirect_path`, `redirect_port`,
     `redirect_protocol`, `redirect_status`,
     `fixed_status`, `fixed_body`,
     `account_name`, `region`, `last_seen`)
VALUES
    (%(rule_arn)s, %(listener_arn)s, %(lb_arn)s, %(priority)s, %(is_default)s,
     %(condition_type)s, %(condition_values)s,
     %(action_type)s, %(action_target)s,
     %(redirect_host)s, %(redirect_path)s, %(redirect_port)s,
     %(redirect_protocol)s, %(redirect_status)s,
     %(fixed_status)s, %(fixed_body)s,
     %(account_name)s, %(region)s, %(last_seen)s)
ON DUPLICATE KEY UPDATE
    `priority`          = VALUES(`priority`),
    `is_default`        = VALUES(`is_default`),
    `condition_type`    = VALUES(`condition_type`),
    `condition_values`  = VALUES(`condition_values`),
    `action_type`       = VALUES(`action_type`),
    `action_target`     = VALUES(`action_target`),
    `redirect_host`     = VALUES(`redirect_host`),
    `redirect_path`     = VALUES(`redirect_path`),
    `redirect_port`     = VALUES(`redirect_port`),
    `redirect_protocol` = VALUES(`redirect_protocol`),
    `redirect_status`   = VALUES(`redirect_status`),
    `fixed_status`      = VALUES(`fixed_status`),
    `fixed_body`        = VALUES(`fixed_body`),
    `last_seen`         = VALUES(`last_seen`);
"""

UPSERT_TG = """
INSERT INTO `aws_lb_target_groups`
    (`tg_arn`, `tg_name`, `target_type`, `protocol`, `port`, `vpc_id`,
     `health_check_protocol`, `health_check_path`, `health_check_port`,
     `healthy_threshold`, `unhealthy_threshold`, `lb_arns`,
     `account_name`, `region`, `last_seen`)
VALUES
    (%(tg_arn)s, %(tg_name)s, %(target_type)s, %(protocol)s, %(port)s, %(vpc_id)s,
     %(health_check_protocol)s, %(health_check_path)s, %(health_check_port)s,
     %(healthy_threshold)s, %(unhealthy_threshold)s, %(lb_arns)s,
     %(account_name)s, %(region)s, %(last_seen)s)
ON DUPLICATE KEY UPDATE
    `tg_name`               = VALUES(`tg_name`),
    `target_type`           = VALUES(`target_type`),
    `protocol`              = VALUES(`protocol`),
    `port`                  = VALUES(`port`),
    `health_check_protocol` = VALUES(`health_check_protocol`),
    `health_check_path`     = VALUES(`health_check_path`),
    `health_check_port`     = VALUES(`health_check_port`),
    `healthy_threshold`     = VALUES(`healthy_threshold`),
    `unhealthy_threshold`   = VALUES(`unhealthy_threshold`),
    `lb_arns`               = VALUES(`lb_arns`),
    `last_seen`             = VALUES(`last_seen`);
"""

UPSERT_TG_TARGET = """
INSERT INTO `aws_lb_tg_targets`
    (`tg_arn`, `target_id`, `port`, `az`, `health_state`, `health_reason`,
     `account_name`, `region`, `last_seen`)
VALUES
    (%(tg_arn)s, %(target_id)s, %(port)s, %(az)s, %(health_state)s, %(health_reason)s,
     %(account_name)s, %(region)s, %(last_seen)s)
ON DUPLICATE KEY UPDATE
    `port`         = VALUES(`port`),
    `az`           = VALUES(`az`),
    `health_state` = VALUES(`health_state`),
    `health_reason`= VALUES(`health_reason`),
    `last_seen`    = VALUES(`last_seen`);
"""

UPSERT_CLB_INST = """
INSERT INTO `aws_clb_instances`
    (`lb_name`, `instance_id`, `state`, `reason_code`, `description`,
     `account_name`, `region`, `last_seen`)
VALUES
    (%(lb_name)s, %(instance_id)s, %(state)s, %(reason_code)s, %(description)s,
     %(account_name)s, %(region)s, %(last_seen)s)
ON DUPLICATE KEY UPDATE
    `state`       = VALUES(`state`),
    `reason_code` = VALUES(`reason_code`),
    `description` = VALUES(`description`),
    `last_seen`   = VALUES(`last_seen`);
"""

UPSERT_TAG = """
INSERT INTO `aws_lb_tags`
    (`aws_id`, `aws_id_type`, `account_name`, `tag_key`, `tag_value`, `last_seen`)
VALUES
    (%(aws_id)s, %(aws_id_type)s, %(account_name)s, %(tag_key)s, %(tag_value)s, %(last_seen)s)
ON DUPLICATE KEY UPDATE
    `tag_value` = VALUES(`tag_value`),
    `last_seen` = VALUES(`last_seen`);
"""


# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────

def get_tag(tags: list, key: str, default: str = "") -> str:
    return next((t["Value"] for t in tags if t["Key"] == key), default)


def upsert_tags(cur, aws_id: str, aws_id_type: str, account_name: str,
                tags: list, now: str):
    for tag in tags:
        key = tag.get("Key", "").strip()
        val = tag.get("Value", "").strip()
        if not key:
            continue
        cur.execute(UPSERT_TAG, {
            "aws_id":       aws_id,
            "aws_id_type":  aws_id_type,
            "account_name": account_name,
            "tag_key":      key,
            "tag_value":    val,
            "last_seen":    now,
        })


def parse_default_action(actions: list) -> tuple[str, str]:
    """
    Return (action_type, action_target) from a listener's DefaultActions list.
    For forward actions, target is the first TG ARN.
    For redirects, target is a human-readable URL string.
    """
    if not actions:
        return (None, None)
    act = actions[0]
    atype = act.get("Type", "")

    if atype == "forward":
        tg_arn = act.get("TargetGroupArn") or ""
        if not tg_arn:
            # weighted TG config
            groups = act.get("ForwardConfig", {}).get("TargetGroups", [])
            tg_arn = groups[0].get("TargetGroupArn", "") if groups else ""
        return ("forward", tg_arn)

    if atype == "redirect":
        rc = act.get("RedirectConfig", {})
        url = (
            f"{rc.get('Protocol','#{protocol}')}://"
            f"{rc.get('Host','#{host}')}:{rc.get('Port','#{port}')}"
            f"{rc.get('Path','/#{path}')}"
        )
        return ("redirect", url)

    if atype == "fixed-response":
        fr = act.get("FixedResponseConfig", {})
        return ("fixed-response", str(fr.get("StatusCode", "")))

    return (atype, None)


def parse_rule(rule: dict, listener_arn: str, lb_arn: str,
               account_name: str, region: str, now: str) -> list[dict]:
    """
    Expand one ALB listener rule into one or more rows — one per condition
    block. A rule with multiple conditions (e.g. host-header AND path-pattern)
    gets one row per condition so each is independently searchable.
    Returns an empty list if the rule has no recognisable conditions.
    """
    priority   = str(rule.get("Priority", "default"))
    is_default = 1 if rule.get("IsDefault", False) else 0
    rule_arn   = rule.get("RuleArn", "")

    # ── Action ──────────────────────────────────────────────────────────────
    actions  = rule.get("Actions", [])
    act      = actions[0] if actions else {}
    atype    = act.get("Type", "")

    action_target    = None
    redirect_host    = None
    redirect_path    = None
    redirect_port    = None
    redirect_proto   = None
    redirect_status  = None
    fixed_status     = None
    fixed_body       = None

    if atype == "forward":
        action_target = act.get("TargetGroupArn") or ""
        if not action_target:
            groups = act.get("ForwardConfig", {}).get("TargetGroups", [])
            action_target = groups[0].get("TargetGroupArn", "") if groups else ""

    elif atype == "redirect":
        rc              = act.get("RedirectConfig", {})
        redirect_host   = rc.get("Host")
        redirect_path   = rc.get("Path")
        redirect_port   = rc.get("Port")
        redirect_proto  = rc.get("Protocol")
        redirect_status = rc.get("StatusCode")

    elif atype == "fixed-response":
        fr           = act.get("FixedResponseConfig", {})
        fixed_status = str(fr.get("StatusCode", ""))
        fixed_body   = fr.get("MessageBody")

    # ── Conditions ──────────────────────────────────────────────────────────
    conditions = rule.get("Conditions", [])

    # Default rules have no conditions — store a single placeholder row
    if not conditions or is_default:
        return [{
            "rule_arn":          rule_arn,
            "listener_arn":      listener_arn,
            "lb_arn":            lb_arn,
            "priority":          priority,
            "is_default":        is_default,
            "condition_type":    None,
            "condition_values":  None,
            "action_type":       atype or None,
            "action_target":     action_target,
            "redirect_host":     redirect_host,
            "redirect_path":     redirect_path,
            "redirect_port":     redirect_port,
            "redirect_protocol": redirect_proto,
            "redirect_status":   redirect_status,
            "fixed_status":      fixed_status,
            "fixed_body":        fixed_body,
            "account_name":      account_name,
            "region":            region,
            "last_seen":         now,
        }]

    rows = []
    for cond in conditions:
        ctype  = cond.get("Field", "")
        values = []

        if ctype == "host-header":
            values = cond.get("HostHeaderConfig", {}).get("Values", [])
        elif ctype == "path-pattern":
            values = cond.get("PathPatternConfig", {}).get("Values", [])
        elif ctype == "http-header":
            hh     = cond.get("HttpHeaderConfig", {})
            values = hh.get("Values", [])
            ctype  = f"http-header:{hh.get('HttpHeaderName','')}"
        elif ctype == "query-string":
            values = [
                f"{qs.get('Key','')}={qs.get('Value','')}"
                for qs in cond.get("QueryStringConfig", {}).get("Values", [])
            ]
        elif ctype == "http-request-method":
            values = cond.get("HttpRequestMethodConfig", {}).get("Values", [])
        elif ctype == "source-ip":
            values = cond.get("SourceIpConfig", {}).get("Values", [])
        else:
            values = cond.get("Values", [])

        # Use a deterministic ARN suffix for multi-condition rules so each
        # condition gets its own primary key without colliding
        suffix   = ctype.replace(":", "_").replace("-", "_")
        row_arn  = f"{rule_arn}::{suffix}" if len(conditions) > 1 else rule_arn

        rows.append({
            "rule_arn":          row_arn,
            "listener_arn":      listener_arn,
            "lb_arn":            lb_arn,
            "priority":          priority,
            "is_default":        is_default,
            "condition_type":    ctype or None,
            "condition_values":  json.dumps(values) if values else None,
            "action_type":       atype or None,
            "action_target":     action_target,
            "redirect_host":     redirect_host,
            "redirect_path":     redirect_path,
            "redirect_port":     redirect_port,
            "redirect_protocol": redirect_proto,
            "redirect_status":   redirect_status,
            "fixed_status":      fixed_status,
            "fixed_body":        fixed_body,
            "account_name":      account_name,
            "region":            region,
            "last_seen":         now,
        })

    return rows


# ─────────────────────────────────────────────
# STALE CLEANUP
# ─────────────────────────────────────────────

def delete_stale(cur, account_name: str, region: str, now: str):
    """Remove rows not touched in the current sync run for this account/region."""
    tables_simple = [
        "aws_load_balancers",
        "aws_lb_listeners",
        "aws_lb_listener_rules",
        "aws_lb_target_groups",
        "aws_lb_tg_targets",
        "aws_clb_instances",
    ]
    for tbl in tables_simple:
        cur.execute(f"""
            DELETE FROM `{tbl}`
            WHERE `last_seen` < %s
              AND `account_name` = %s
              AND `region` = %s
        """, (now, account_name, region))

    # Tags: clean up orphaned rows (LBs/TGs that no longer exist)
    cur.execute("""
        DELETE t FROM `aws_lb_tags` t
        LEFT JOIN `aws_load_balancers` lb ON t.aws_id = lb.lb_arn
        LEFT JOIN `aws_lb_target_groups` tg ON t.aws_id = tg.tg_arn
        WHERE lb.lb_arn IS NULL AND tg.tg_arn IS NULL
          AND t.account_name = %s
    """, (account_name,))


# ─────────────────────────────────────────────
# ELBv2 (ALB + NLB)
# ─────────────────────────────────────────────

def collect_elbv2(session, account_name: str, region: str, cur, now: str) -> dict:
    """Collect ALBs and NLBs via the elbv2 API."""
    counts = {"lbs": 0, "listeners": 0, "rules": 0, "tgs": 0, "targets": 0}
    try:
        elb = session.client("elbv2", region_name=region)

        # ── Load Balancers ───────────────────────────────────────────────
        lb_arns_in_region = []
        pager = elb.get_paginator("describe_load_balancers")
        for page in pager.paginate():
            for lb in page["LoadBalancers"]:
                lb_arn  = lb["LoadBalancerArn"]
                lb_type = lb.get("Type", "application")  # application | network
                state   = lb.get("State", {}).get("Code", "")

                cur.execute(UPSERT_LB, {
                    "lb_arn":       lb_arn,
                    "lb_name":      lb.get("LoadBalancerName", ""),
                    "lb_type":      lb_type,
                    "dns_name":     lb.get("DNSName", ""),
                    "scheme":       lb.get("Scheme", ""),
                    "state":        state,
                    "vpc_id":       lb.get("VpcId", ""),
                    "account_name": account_name,
                    "region":       region,
                    "last_seen":    now,
                })
                lb_arns_in_region.append(lb_arn)
                counts["lbs"] += 1

        # Tags for LBs — batch up to 20 ARNs per call (API limit)
        for i in range(0, len(lb_arns_in_region), 20):
            batch = lb_arns_in_region[i:i+20]
            try:
                resp = elb.describe_tags(ResourceArns=batch)
                for td in resp.get("TagDescriptions", []):
                    upsert_tags(cur, td["ResourceArn"], "lb", account_name,
                                td.get("Tags", []), now)
            except ClientError:
                pass  # Tags are best-effort

        # ── Listeners ────────────────────────────────────────────────────
        listener_arns_by_lb: dict[str, list[str]] = {}
        for lb_arn in lb_arns_in_region:
            lb_type = "application"  # will be refined from DB; use elbv2 for both
            try:
                lpager = elb.get_paginator("describe_listeners")
                for lpage in lpager.paginate(LoadBalancerArn=lb_arn):
                    for lst in lpage["Listeners"]:
                        l_arn   = lst["ListenerArn"]
                        da_type, da_target = parse_default_action(
                            lst.get("DefaultActions", [])
                        )

                        # Detect lb_type from the listener ARN prefix
                        lb_type_detected = "network" if ":loadbalancer/net/" in lb_arn else "application"

                        cur.execute(UPSERT_LISTENER, {
                            "listener_arn":         l_arn,
                            "lb_arn":               lb_arn,
                            "lb_type":              lb_type_detected,
                            "protocol":             lst.get("Protocol"),
                            "port":                 lst.get("Port"),
                            "ssl_policy":           lst.get("SslPolicy"),
                            "default_action_type":  da_type,
                            "default_action_target": da_target,
                            "account_name":         account_name,
                            "region":               region,
                            "last_seen":            now,
                        })
                        counts["listeners"] += 1

                        listener_arns_by_lb.setdefault(lb_arn, []).append(l_arn)

                        # ── ALB rules only ───────────────────────────────
                        if ":loadbalancer/net/" not in lb_arn:
                            try:
                                rpager = elb.get_paginator("describe_rules")
                                for rpage in rpager.paginate(ListenerArn=l_arn):
                                    for rule in rpage["Rules"]:
                                        rows = parse_rule(
                                            rule, l_arn, lb_arn,
                                            account_name, region, now
                                        )
                                        for row in rows:
                                            cur.execute(UPSERT_RULE, row)
                                            counts["rules"] += 1
                            except ClientError as e:
                                print(f"    [WARN] Rules {account_name}/{region} "
                                      f"{l_arn[-30:]}: {e.response['Error']['Message']}")

            except ClientError as e:
                print(f"    [WARN] Listeners {account_name}/{region} "
                      f"{lb_arn[-40:]}: {e.response['Error']['Message']}")

        # ── Target Groups ────────────────────────────────────────────────
        tg_arns_in_region = []
        tpager = elb.get_paginator("describe_target_groups")
        for tpage in tpager.paginate():
            for tg in tpage["TargetGroups"]:
                tg_arn = tg["TargetGroupArn"]
                hc     = tg  # health check fields are on the TG object directly

                cur.execute(UPSERT_TG, {
                    "tg_arn":                tg_arn,
                    "tg_name":               tg.get("TargetGroupName", ""),
                    "target_type":           tg.get("TargetType", ""),
                    "protocol":              tg.get("Protocol", ""),
                    "port":                  tg.get("Port"),
                    "vpc_id":                tg.get("VpcId", ""),
                    "health_check_protocol": hc.get("HealthCheckProtocol"),
                    "health_check_path":     hc.get("HealthCheckPath"),
                    "health_check_port":     hc.get("HealthCheckPort"),
                    "healthy_threshold":     hc.get("HealthyThresholdCount"),
                    "unhealthy_threshold":   hc.get("UnhealthyThresholdCount"),
                    "lb_arns":               json.dumps(tg.get("LoadBalancerArns", [])),
                    "account_name":          account_name,
                    "region":                region,
                    "last_seen":             now,
                })
                tg_arns_in_region.append(tg_arn)
                counts["tgs"] += 1

                # Target health
                try:
                    health_resp = elb.describe_target_health(TargetGroupArn=tg_arn)
                    for thd in health_resp.get("TargetHealthDescriptions", []):
                        target  = thd.get("Target", {})
                        health  = thd.get("TargetHealth", {})
                        cur.execute(UPSERT_TG_TARGET, {
                            "tg_arn":       tg_arn,
                            "target_id":    target.get("Id", ""),
                            "port":         target.get("Port"),
                            "az":           target.get("AvailabilityZone", ""),
                            "health_state": health.get("State", ""),
                            "health_reason": health.get("Reason", ""),
                            "account_name": account_name,
                            "region":       region,
                            "last_seen":    now,
                        })
                        counts["targets"] += 1
                except ClientError as e:
                    print(f"    [WARN] Target health {account_name}/{region} "
                          f"{tg_arn[-40:]}: {e.response['Error']['Message']}")

        # Tags for TGs
        for i in range(0, len(tg_arns_in_region), 20):
            batch = tg_arns_in_region[i:i+20]
            try:
                resp = elb.describe_tags(ResourceArns=batch)
                for td in resp.get("TagDescriptions", []):
                    upsert_tags(cur, td["ResourceArn"], "tg", account_name,
                                td.get("Tags", []), now)
            except ClientError:
                pass

    except ClientError as e:
        print(f"    [WARN] ELBv2 {account_name}/{region}: {e.response['Error']['Message']}")

    return counts


# ─────────────────────────────────────────────
# CLASSIC ELB (CLB)
# ─────────────────────────────────────────────

def collect_classic(session, account_name: str, region: str, cur, now: str) -> dict:
    """Collect Classic Load Balancers via the legacy elb API."""
    counts = {"lbs": 0, "listeners": 0, "instances": 0}
    try:
        elb = session.client("elb", region_name=region)

        pager = elb.get_paginator("describe_load_balancers")
        for page in pager.paginate():
            for lb in page["LoadBalancerDescriptions"]:
                lb_name = lb["LoadBalancerName"]
                # CLBs have no ARN — synthesise one for the primary key
                lb_arn  = f"arn:aws:elasticloadbalancing:{region}:{account_name}:loadbalancer/{lb_name}"

                cur.execute(UPSERT_LB, {
                    "lb_arn":       lb_arn,
                    "lb_name":      lb_name,
                    "lb_type":      "classic",
                    "dns_name":     lb.get("DNSName", ""),
                    "scheme":       lb.get("Scheme", ""),
                    "state":        "active",  # CLB has no state field
                    "vpc_id":       lb.get("VpcId", ""),
                    "account_name": account_name,
                    "region":       region,
                    "last_seen":    now,
                })
                counts["lbs"] += 1

                # ── Listeners ────────────────────────────────────────────
                for ld in lb.get("ListenerDescriptions", []):
                    lst    = ld.get("Listener", {})
                    proto  = lst.get("Protocol", "")
                    port   = lst.get("LoadBalancerPort")
                    # Synthetic ARN (CLBs have no listener ARN)
                    l_arn  = f"{lb_arn}:listener/{proto}:{port}"

                    cur.execute(UPSERT_LISTENER, {
                        "listener_arn":          l_arn,
                        "lb_arn":                lb_arn,
                        "lb_type":               "classic",
                        "protocol":              proto,
                        "port":                  port,
                        "ssl_policy":            (ld.get("PolicyNames") or [None])[0],
                        "default_action_type":   "forward",
                        "default_action_target": (
                            f"{lst.get('InstanceProtocol','')}:{lst.get('InstancePort','')}"
                        ),
                        "account_name": account_name,
                        "region":       region,
                        "last_seen":    now,
                    })
                    counts["listeners"] += 1

                # ── Instance health ──────────────────────────────────────
                try:
                    health_resp = elb.describe_instance_health(
                        LoadBalancerName=lb_name
                    )
                    for inst in health_resp.get("InstanceStates", []):
                        cur.execute(UPSERT_CLB_INST, {
                            "lb_name":      lb_name,
                            "instance_id":  inst.get("InstanceId", ""),
                            "state":        inst.get("State", ""),
                            "reason_code":  inst.get("ReasonCode", ""),
                            "description":  inst.get("Description", ""),
                            "account_name": account_name,
                            "region":       region,
                            "last_seen":    now,
                        })
                        counts["instances"] += 1
                except ClientError as e:
                    print(f"    [WARN] CLB health {account_name}/{region} "
                          f"{lb_name}: {e.response['Error']['Message']}")

                # Tags
                try:
                    tresp = elb.describe_tags(LoadBalancerNames=[lb_name])
                    for td in tresp.get("TagDescriptions", []):
                        upsert_tags(cur, lb_arn, "lb", account_name,
                                    td.get("Tags", []), now)
                except ClientError:
                    pass

    except ClientError as e:
        print(f"    [WARN] CLB {account_name}/{region}: {e.response['Error']['Message']}")

    return counts


# ─────────────────────────────────────────────
# DDL BOOTSTRAP
# ─────────────────────────────────────────────

def ensure_tables(cur):
    for stmt in DDL.strip().split(";\n\n"):
        stmt = stmt.strip()
        if stmt:
            cur.execute(stmt)


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

def main():
    conn = mysql.connector.connect(**DB_CONFIG)
    cur  = conn.cursor()
    cur.execute(f"USE `{DB_CONFIG['database']}`;")
    now  = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    print("Ensuring tables exist...")
    ensure_tables(cur)
    conn.commit()

    totals = {
        "lbs": 0, "listeners": 0, "rules": 0,
        "tgs": 0, "targets": 0, "clb_instances": 0,
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

        for region in account.get("regions", ["us-west-2"]):
            print(f"  → ELBv2 (ALB + NLB) [{region}]")
            c = collect_elbv2(session, account["name"], region, cur, now)
            print(f"       LBs: {c['lbs']}  listeners: {c['listeners']}  "
                  f"rules: {c['rules']}  TGs: {c['tgs']}  targets: {c['targets']}")
            totals["lbs"]       += c["lbs"]
            totals["listeners"] += c["listeners"]
            totals["rules"]     += c["rules"]
            totals["tgs"]       += c["tgs"]
            totals["targets"]   += c["targets"]

            print(f"  → Classic ELB       [{region}]")
            c = collect_classic(session, account["name"], region, cur, now)
            print(f"       LBs: {c['lbs']}  listeners: {c['listeners']}  "
                  f"instances: {c['instances']}")
            totals["lbs"]          += c["lbs"]
            totals["listeners"]    += c["listeners"]
            totals["clb_instances"]+= c["instances"]

            print(f"  → Stale cleanup     [{region}]")
            delete_stale(cur, account["name"], region, now)

        conn.commit()

    print(f"\n{'═'*60}")
    print(f"✅  Sync complete — {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print(f"   Load balancers : {totals['lbs']}")
    print(f"   Listeners      : {totals['listeners']}")
    print(f"   ALB rules      : {totals['rules']}")
    print(f"   Target groups  : {totals['tgs']}")
    print(f"   TG targets     : {totals['targets']}")
    print(f"   CLB instances  : {totals['clb_instances']}")
    print(f"{'═'*60}")

    cur.close()
    conn.close()


if __name__ == "__main__":
    main()
