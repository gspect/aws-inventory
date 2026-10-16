#!/usr/bin/env python3
"""
AWS CloudFront Collector
Collects CloudFront distributions, origins, and cache behaviors across opted-in accounts.

Only runs for accounts with cloudfront_collect = true in config.ini.

CloudFront is a global service — all API calls go to us-east-1 regardless of
where the origins or viewers are located.

Collection strategy:
  - list_distributions (paginated) -> full DistributionConfig is included inline,
    no second describe call needed
  - Origins, cache behaviors, and viewer certificate details extracted from config
  - Tags fetched separately via list_tags_for_resource per distribution ARN

Tables created automatically:
    aws_cf_distributions  — One row per distribution
    aws_cf_origins        — Origins per distribution (one-to-many)
    aws_cf_tags           — Distribution tags

Requirements:
    pip install boto3 mysql-connector-python

Usage:
    python3 collect_cloudfront.py
    python3 collect_cloudfront.py --account my-account-name

config.ini opt-in:
    [account:my-account]
    ...
    cloudfront_collect = true
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
parser = argparse.ArgumentParser(description="AWS CloudFront Collector")
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
DDL_DISTRIBUTIONS = """
CREATE TABLE IF NOT EXISTS `aws_cf_distributions` (
    `id`                        INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `distribution_id`           VARCHAR(50)   NOT NULL,
    `distribution_arn`          VARCHAR(512),
    `domain_name`               VARCHAR(255),
    `comment`                   VARCHAR(512),
    `status`                    VARCHAR(20),
    `enabled`                   TINYINT(1)    DEFAULT 0,
    `http_version`              VARCHAR(20),
    `price_class`               VARCHAR(50),
    `ipv6_enabled`              TINYINT(1)    DEFAULT 0,
    `aliases`                   TEXT,
    `default_root_object`       VARCHAR(255),
    `geo_restriction_type`      VARCHAR(50),
    `geo_restriction_locations` TEXT,
    `viewer_cert_source`        VARCHAR(50),
    `acm_cert_arn`              VARCHAR(512),
    `ssl_support_method`        VARCHAR(50),
    `minimum_protocol_version`  VARCHAR(50),
    `waf_web_acl_id`            VARCHAR(512),
    `web_acl_arn`               VARCHAR(512),
    `default_cache_behavior`    TEXT,
    `cache_behavior_count`      SMALLINT UNSIGNED DEFAULT 0,
    `origin_count`              SMALLINT UNSIGNED DEFAULT 0,
    `account_name`              VARCHAR(255)  NOT NULL,
    `last_modified`             DATETIME,
    `last_seen`                 DATETIME      NOT NULL,
    UNIQUE KEY `uq_cf_dist`     (`distribution_id`),
    INDEX `idx_account`         (`account_name`),
    INDEX `idx_status`          (`status`),
    INDEX `idx_domain`          (`domain_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""

DDL_ORIGINS = """
CREATE TABLE IF NOT EXISTS `aws_cf_origins` (
    `id`                  INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `distribution_id`     VARCHAR(50)   NOT NULL,
    `origin_id`           VARCHAR(255)  NOT NULL,
    `domain_name`         VARCHAR(512),
    `origin_path`         VARCHAR(512),
    `origin_type`         VARCHAR(50),
    `protocol_policy`     VARCHAR(50),
    `https_only`          TINYINT(1)    DEFAULT 0,
    `connection_attempts` TINYINT UNSIGNED,
    `connection_timeout`  TINYINT UNSIGNED,
    `account_name`        VARCHAR(255)  NOT NULL,
    `last_seen`           DATETIME      NOT NULL,
    UNIQUE KEY `uq_cf_origin` (`distribution_id`, `origin_id`(150)),
    INDEX `idx_distribution`  (`distribution_id`),
    INDEX `idx_account`       (`account_name`),
    INDEX `idx_domain`        (`domain_name`(100))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""

DDL_TAGS = """
CREATE TABLE IF NOT EXISTS `aws_cf_tags` (
    `id`               INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `distribution_id`  VARCHAR(50)  NOT NULL,
    `account_name`     VARCHAR(255) NOT NULL,
    `tag_key`          VARCHAR(255) NOT NULL,
    `tag_value`        TEXT,
    `last_seen`        DATETIME     NOT NULL,
    UNIQUE KEY `uq_cf_tag` (`distribution_id`, `tag_key`(150)),
    INDEX `idx_dist`       (`distribution_id`),
    INDEX `idx_account`    (`account_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""

# ─────────────────────────────────────────────
# SQL
# ─────────────────────────────────────────────
UPSERT_DIST = """
INSERT INTO `aws_cf_distributions`
    (distribution_id, distribution_arn, domain_name, comment, status, enabled,
     http_version, price_class, ipv6_enabled, aliases, default_root_object,
     geo_restriction_type, geo_restriction_locations,
     viewer_cert_source, acm_cert_arn, ssl_support_method, minimum_protocol_version,
     waf_web_acl_id, web_acl_arn, default_cache_behavior, cache_behavior_count,
     origin_count, account_name, last_modified, last_seen)
VALUES
    (%(distribution_id)s, %(distribution_arn)s, %(domain_name)s, %(comment)s,
     %(status)s, %(enabled)s, %(http_version)s, %(price_class)s, %(ipv6_enabled)s,
     %(aliases)s, %(default_root_object)s, %(geo_restriction_type)s,
     %(geo_restriction_locations)s, %(viewer_cert_source)s, %(acm_cert_arn)s,
     %(ssl_support_method)s, %(minimum_protocol_version)s, %(waf_web_acl_id)s,
     %(web_acl_arn)s, %(default_cache_behavior)s, %(cache_behavior_count)s,
     %(origin_count)s, %(account_name)s, %(last_modified)s, %(last_seen)s)
ON DUPLICATE KEY UPDATE
    domain_name                = VALUES(domain_name),
    comment                    = VALUES(comment),
    status                     = VALUES(status),
    enabled                    = VALUES(enabled),
    http_version               = VALUES(http_version),
    price_class                = VALUES(price_class),
    ipv6_enabled               = VALUES(ipv6_enabled),
    aliases                    = VALUES(aliases),
    default_root_object        = VALUES(default_root_object),
    geo_restriction_type       = VALUES(geo_restriction_type),
    geo_restriction_locations  = VALUES(geo_restriction_locations),
    viewer_cert_source         = VALUES(viewer_cert_source),
    acm_cert_arn               = VALUES(acm_cert_arn),
    ssl_support_method         = VALUES(ssl_support_method),
    minimum_protocol_version   = VALUES(minimum_protocol_version),
    waf_web_acl_id             = VALUES(waf_web_acl_id),
    web_acl_arn                = VALUES(web_acl_arn),
    default_cache_behavior     = VALUES(default_cache_behavior),
    cache_behavior_count       = VALUES(cache_behavior_count),
    origin_count               = VALUES(origin_count),
    last_modified              = VALUES(last_modified),
    last_seen                  = VALUES(last_seen);
"""

UPSERT_ORIGIN = """
INSERT INTO `aws_cf_origins`
    (distribution_id, origin_id, domain_name, origin_path, origin_type,
     protocol_policy, https_only, connection_attempts, connection_timeout,
     account_name, last_seen)
VALUES
    (%(distribution_id)s, %(origin_id)s, %(domain_name)s, %(origin_path)s,
     %(origin_type)s, %(protocol_policy)s, %(https_only)s,
     %(connection_attempts)s, %(connection_timeout)s,
     %(account_name)s, %(last_seen)s)
ON DUPLICATE KEY UPDATE
    domain_name         = VALUES(domain_name),
    origin_path         = VALUES(origin_path),
    origin_type         = VALUES(origin_type),
    protocol_policy     = VALUES(protocol_policy),
    https_only          = VALUES(https_only),
    connection_attempts = VALUES(connection_attempts),
    connection_timeout  = VALUES(connection_timeout),
    last_seen           = VALUES(last_seen);
"""

UPSERT_TAG = """
INSERT INTO `aws_cf_tags` (distribution_id, account_name, tag_key, tag_value, last_seen)
VALUES (%(distribution_id)s, %(account_name)s, %(tag_key)s, %(tag_value)s, %(last_seen)s)
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
    for ddl in (DDL_DISTRIBUTIONS, DDL_ORIGINS, DDL_TAGS):
        cur.execute(ddl)
    conn.commit()
    return conn, cur


# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────
def classify_origin(domain_name):
    """Return a short origin type string based on the domain name pattern."""
    d = (domain_name or "").lower()
    if d.endswith(".s3.amazonaws.com") or ".s3-website" in d or ".s3." in d:
        return "S3"
    if d.endswith(".elasticloadbalancing.amazonaws.com"):
        return "ALB/ELB"
    if d.endswith(".execute-api.amazonaws.com"):
        return "API Gateway"
    if d.endswith(".mediastore.amazonaws.com"):
        return "MediaStore"
    if d.endswith(".amazonaws.com"):
        return "AWS"
    if d.endswith(".elb.amazonaws.com"):
        return "ELB"
    return "Custom"


def extract_default_cache_behavior(dcb):
    """Pull the key fields from a DefaultCacheBehavior dict for storage."""
    if not dcb:
        return "{}"
    return json.dumps({
        "target_origin_id":       dcb.get("TargetOriginId", ""),
        "viewer_protocol_policy": dcb.get("ViewerProtocolPolicy", ""),
        "compress":               dcb.get("Compress", False),
        "cache_policy_id":        dcb.get("CachePolicyId", ""),
        "origin_request_policy":  dcb.get("OriginRequestPolicyId", ""),
        "allowed_methods":        dcb.get("AllowedMethods", {}).get("Items", []),
    })


def delete_stale(cur, account_name, now):
    cur.execute("""
        DELETE FROM `aws_cf_origins`
        WHERE account_name = %s AND last_seen < %s
    """, (account_name, now))
    cur.execute("""
        DELETE FROM `aws_cf_distributions`
        WHERE account_name = %s AND last_seen < %s
    """, (account_name, now))
    cur.execute("""
        DELETE t FROM `aws_cf_tags` t
        WHERE t.account_name = %s
          AND t.distribution_id NOT IN (
              SELECT distribution_id FROM `aws_cf_distributions` WHERE account_name = %s
          )
    """, (account_name, account_name))


# ─────────────────────────────────────────────
# COLLECTOR
# ─────────────────────────────────────────────
def collect_distributions(cf, account_name, cur, now):
    """
    Paginate through all CloudFront distributions for an account.
    The list_distributions response includes the full DistributionConfig
    inline so no second API call is needed per distribution.
    """
    count     = 0
    paginator = cf.get_paginator("list_distributions")

    for page in paginator.paginate():
        dist_list = page.get("DistributionList", {})
        for item in dist_list.get("Items", []):
            dist_id = item["Id"]
            cfg     = item.get("DistributionConfig", {}) or item  # config is inline

            # ── Aliases (CNAMEs) ─────────────────────────────────────────
            aliases = cfg.get("Aliases", {}).get("Items", []) or \
                      item.get("Aliases", {}).get("Items", [])

            # ── Geo restriction ──────────────────────────────────────────
            geo        = cfg.get("Restrictions", {}).get("GeoRestriction", {})
            geo_type   = geo.get("RestrictionType", "none")
            geo_locs   = json.dumps(geo.get("Items", []))

            # ── Viewer certificate ───────────────────────────────────────
            cert     = cfg.get("ViewerCertificate", {}) or \
                       item.get("ViewerCertificate", {})
            cert_src = ""
            acm_arn  = ""
            ssl_method = cert.get("SSLSupportMethod", "")
            min_proto  = cert.get("MinimumProtocolVersion", "")
            if cert.get("ACMCertificateArn"):
                cert_src = "acm"
                acm_arn  = cert["ACMCertificateArn"]
            elif cert.get("IAMCertificateId"):
                cert_src = "iam"
            elif cert.get("CloudFrontDefaultCertificate"):
                cert_src = "cloudfront"

            # ── WAF ──────────────────────────────────────────────────────
            waf_id  = cfg.get("WebACLId", "") or item.get("WebACLId", "") or ""
            web_acl = ""  # web_acl_arn only available via GetDistribution, skip for now

            # ── Last modified ────────────────────────────────────────────
            last_mod = item.get("LastModifiedTime")
            if last_mod:
                last_mod = last_mod.replace(tzinfo=None)

            # ── Default cache behavior ───────────────────────────────────
            dcb = cfg.get("DefaultCacheBehavior", {}) or \
                  item.get("DefaultCacheBehavior", {})

            # ── Cache behaviors count (additional, not default) ──────────
            cb_count = cfg.get("CacheBehaviors", {}).get("Quantity", 0) or \
                       item.get("CacheBehaviors", {}).get("Quantity", 0)

            # ── Origins ──────────────────────────────────────────────────
            origins_data = cfg.get("Origins", {}).get("Items", []) or \
                           item.get("Origins", {}).get("Items", [])
            origin_count = len(origins_data)

            cur.execute(UPSERT_DIST, {
                "distribution_id":           dist_id,
                "distribution_arn":          item.get("ARN", ""),
                "domain_name":               item.get("DomainName", ""),
                "comment":                   cfg.get("Comment", "") or item.get("Comment", "") or "",
                "status":                    item.get("Status", ""),
                "enabled":                   int(cfg.get("Enabled", True)),
                "http_version":              cfg.get("HttpVersion", "") or item.get("HttpVersion", "") or "",
                "price_class":               cfg.get("PriceClass", "") or item.get("PriceClass", "") or "",
                "ipv6_enabled":              int(cfg.get("IsIPV6Enabled", False) or item.get("IsIPV6Enabled", False)),
                "aliases":                   json.dumps(aliases),
                "default_root_object":       cfg.get("DefaultRootObject", "") or "",
                "geo_restriction_type":      geo_type,
                "geo_restriction_locations": geo_locs,
                "viewer_cert_source":        cert_src,
                "acm_cert_arn":              acm_arn,
                "ssl_support_method":        ssl_method,
                "minimum_protocol_version":  min_proto,
                "waf_web_acl_id":            waf_id,
                "web_acl_arn":               web_acl,
                "default_cache_behavior":    extract_default_cache_behavior(dcb),
                "cache_behavior_count":      cb_count,
                "origin_count":              origin_count,
                "account_name":              account_name,
                "last_modified":             last_mod,
                "last_seen":                 now,
            })

            # ── Upsert origins ───────────────────────────────────────────
            for origin in origins_data:
                o_domain = origin.get("DomainName", "")
                # Protocol policy from CustomOriginConfig (S3 origins don't have it)
                custom   = origin.get("CustomOriginConfig", {})
                protocol = custom.get("OriginProtocolPolicy", "")
                https_only = int(protocol == "https-only")

                cur.execute(UPSERT_ORIGIN, {
                    "distribution_id":    dist_id,
                    "origin_id":          origin.get("Id", ""),
                    "domain_name":        o_domain,
                    "origin_path":        origin.get("OriginPath", "") or "",
                    "origin_type":        classify_origin(o_domain),
                    "protocol_policy":    protocol,
                    "https_only":         https_only,
                    "connection_attempts": origin.get("ConnectionAttempts"),
                    "connection_timeout":  origin.get("ConnectionTimeout"),
                    "account_name":       account_name,
                    "last_seen":          now,
                })

            # ── Tags ─────────────────────────────────────────────────────
            arn = item.get("ARN", "")
            if arn:
                try:
                    tag_resp = cf.list_tags_for_resource(Resource=arn)
                    for tag in tag_resp.get("Tags", {}).get("Items", []):
                        k = tag.get("Key", "").strip()
                        v = tag.get("Value", "").strip()
                        if not k:
                            continue
                        cur.execute(UPSERT_TAG, {
                            "distribution_id": dist_id,
                            "account_name":    account_name,
                            "tag_key":         k,
                            "tag_value":       v,
                            "last_seen":       now,
                        })
                except ClientError:
                    pass

            count += 1

    return count


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
def main():
    conn, cur = init_db(DB_CONFIG)
    now   = datetime.now(timezone.utc).replace(tzinfo=None).strftime("%Y-%m-%d %H:%M:%S")
    total = 0

    for acct in ACCOUNTS:
        name = acct["name"]

        # ── Opt-in check ─────────────────────────────────────────────────
        if not acct.get("cloudfront_collect", False):
            print(f"\n  Skipping {name} — cloudfront_collect not set in config.ini")
            continue

        print(f"\n{'─'*55}")
        print(f"  Account: {name}")
        print(f"{'─'*55}")

        try:
            boto_session = get_session(acct)
            # CloudFront is a global service — always us-east-1
            cf = boto_session.client("cloudfront", region_name="us-east-1")

            count = collect_distributions(cf, name, cur, now)
            delete_stale(cur, name, now)
            conn.commit()

            total += count
            print(f"  ✔  {count} distributions")

        except NoCredentialsError:
            print(f"  ✘  No credentials for {name}")
        except ClientError as e:
            code = e.response["Error"]["Code"]
            print(f"  ✘  ClientError [{code}]: {e}")
        except Exception as e:
            print(f"  ✘  Unexpected error: {e}")

    cur.close()
    conn.close()
    print(f"\n✅  Done — {total} CloudFront distributions collected.")


if __name__ == "__main__":
    main()
