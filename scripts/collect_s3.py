#!/usr/bin/env python3
"""
AWS S3 Bucket Collector
Collects S3 bucket metadata and storage metrics across all accounts.

Strategy: NEVER paginate bucket objects. Storage sizes and object counts are
pulled from CloudWatch daily metrics (AWS/S3 namespace) — the same source the
AWS Console uses. This means collection time is O(buckets), not O(objects),
so a bucket with 50 million files takes the same time as an empty one.

CloudWatch optimization: Uses get_metric_data() to fetch ALL storage class
metrics for ALL buckets in a single batched API call per account (up to 500
metric queries per call). This replaces the old per-bucket, per-storage-type
get_metric_statistics() loop — roughly 14x fewer API calls per bucket.

CloudWatch S3 metrics quirk: BucketSizeBytes and NumberOfObjects are ALWAYS
queried against us-east-1 regardless of where the bucket actually lives.
AWS publishes these metrics globally in us-east-1 only.

Account skipping: Add s3_collect = false to any [account:NAME] section in
config.ini to skip that account entirely. Defaults to true if not set.

Tables created automatically:
    aws_s3_buckets        — One row per bucket: metadata, security posture, location
    aws_s3_storage        — Storage class breakdown per bucket (from CloudWatch)
    aws_s3_tags           — Bucket tags

Requirements:
    pip install boto3 mysql-connector-python

Usage:
    python3 collect_s3.py
    python3 collect_s3.py --account my-account-name
    python3 collect_s3.py --account my-account-name --bucket my-bucket-name
"""

import sys
import argparse
from datetime import datetime, timezone, timedelta

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
parser = argparse.ArgumentParser(description="AWS S3 Bucket Collector")
parser.add_argument("--account", help="Only run for this account name (must match config.ini)", default=None)
parser.add_argument("--bucket",  help="Only collect this specific bucket name (requires --account)", default=None)
args = parser.parse_args()

if args.account:
    ACCOUNTS = [a for a in ACCOUNTS if a["name"] == args.account]
    if not ACCOUNTS:
        print(f"[ERROR] No account named '{args.account}' found in config.ini")
        sys.exit(1)

if args.bucket and not args.account:
    print("[ERROR] --bucket requires --account")
    sys.exit(1)

# ─────────────────────────────────────────────
# DDL
# ─────────────────────────────────────────────
DDL_BUCKETS = """
CREATE TABLE IF NOT EXISTS `aws_s3_buckets` (
    `id`                        INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `bucket_name`               VARCHAR(255)  NOT NULL,
    `region`                    VARCHAR(50),
    `creation_date`             DATETIME,
    `versioning`                VARCHAR(20)   DEFAULT 'Disabled',
    `mfa_delete`                VARCHAR(20)   DEFAULT 'Disabled',
    `encryption_enabled`        TINYINT(1)    DEFAULT 0,
    `encryption_type`           VARCHAR(50),
    `block_public_acls`         TINYINT(1)    DEFAULT 0,
    `ignore_public_acls`        TINYINT(1)    DEFAULT 0,
    `block_public_policy`       TINYINT(1)    DEFAULT 0,
    `restrict_public_buckets`   TINYINT(1)    DEFAULT 0,
    `fully_public_blocked`      TINYINT(1)    DEFAULT 0,
    `lifecycle_rules`           TINYINT(1)    DEFAULT 0,
    `lifecycle_rule_count`      SMALLINT UNSIGNED DEFAULT 0,
    `object_lock_enabled`       TINYINT(1)    DEFAULT 0,
    `replication_enabled`       TINYINT(1)    DEFAULT 0,
    `website_enabled`           TINYINT(1)    DEFAULT 0,
    `logging_enabled`           TINYINT(1)    DEFAULT 0,
    `account_name`              VARCHAR(255)  NOT NULL,
    `last_seen`                 DATETIME      NOT NULL,
    UNIQUE KEY `uq_bucket`      (`bucket_name`),
    INDEX `idx_account`         (`account_name`),
    INDEX `idx_region`          (`region`),
    INDEX `idx_public`          (`fully_public_blocked`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""

DDL_STORAGE = """
CREATE TABLE IF NOT EXISTS `aws_s3_storage` (
    `id`               INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `bucket_name`      VARCHAR(255) NOT NULL,
    `storage_type`     VARCHAR(100) NOT NULL,
    `size_bytes`       BIGINT UNSIGNED DEFAULT 0,
    `object_count`     BIGINT UNSIGNED DEFAULT 0,
    `account_name`     VARCHAR(255) NOT NULL,
    `metric_date`      DATE,
    `last_seen`        DATETIME     NOT NULL,
    UNIQUE KEY `uq_s3_storage` (`bucket_name`, `storage_type`),
    INDEX `idx_bucket`  (`bucket_name`),
    INDEX `idx_account` (`account_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""

DDL_TAGS = """
CREATE TABLE IF NOT EXISTS `aws_s3_tags` (
    `id`           INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `bucket_name`  VARCHAR(255) NOT NULL,
    `account_name` VARCHAR(255) NOT NULL,
    `tag_key`      VARCHAR(255) NOT NULL,
    `tag_value`    TEXT,
    `last_seen`    DATETIME     NOT NULL,
    UNIQUE KEY `uq_s3_tag`  (`bucket_name`, `tag_key`),
    INDEX `idx_bucket`      (`bucket_name`),
    INDEX `idx_account`     (`account_name`),
    INDEX `idx_tag_key`     (`tag_key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""

# ─────────────────────────────────────────────
# SQL
# ─────────────────────────────────────────────
UPSERT_BUCKET = """
INSERT INTO `aws_s3_buckets`
    (bucket_name, region, creation_date, versioning, mfa_delete,
     encryption_enabled, encryption_type,
     block_public_acls, ignore_public_acls, block_public_policy, restrict_public_buckets,
     fully_public_blocked, lifecycle_rules, lifecycle_rule_count,
     object_lock_enabled, replication_enabled, website_enabled, logging_enabled,
     account_name, last_seen)
VALUES
    (%(bucket_name)s, %(region)s, %(creation_date)s, %(versioning)s, %(mfa_delete)s,
     %(encryption_enabled)s, %(encryption_type)s,
     %(block_public_acls)s, %(ignore_public_acls)s, %(block_public_policy)s,
     %(restrict_public_buckets)s, %(fully_public_blocked)s,
     %(lifecycle_rules)s, %(lifecycle_rule_count)s,
     %(object_lock_enabled)s, %(replication_enabled)s,
     %(website_enabled)s, %(logging_enabled)s,
     %(account_name)s, %(last_seen)s)
ON DUPLICATE KEY UPDATE
    region                  = VALUES(region),
    versioning              = VALUES(versioning),
    mfa_delete              = VALUES(mfa_delete),
    encryption_enabled      = VALUES(encryption_enabled),
    encryption_type         = VALUES(encryption_type),
    block_public_acls       = VALUES(block_public_acls),
    ignore_public_acls      = VALUES(ignore_public_acls),
    block_public_policy     = VALUES(block_public_policy),
    restrict_public_buckets = VALUES(restrict_public_buckets),
    fully_public_blocked    = VALUES(fully_public_blocked),
    lifecycle_rules         = VALUES(lifecycle_rules),
    lifecycle_rule_count    = VALUES(lifecycle_rule_count),
    object_lock_enabled     = VALUES(object_lock_enabled),
    replication_enabled     = VALUES(replication_enabled),
    website_enabled         = VALUES(website_enabled),
    logging_enabled         = VALUES(logging_enabled),
    account_name            = VALUES(account_name),
    last_seen               = VALUES(last_seen);
"""

UPSERT_STORAGE = """
INSERT INTO `aws_s3_storage`
    (bucket_name, storage_type, size_bytes, object_count, account_name, metric_date, last_seen)
VALUES
    (%(bucket_name)s, %(storage_type)s, %(size_bytes)s, %(object_count)s,
     %(account_name)s, %(metric_date)s, %(last_seen)s)
ON DUPLICATE KEY UPDATE
    size_bytes   = VALUES(size_bytes),
    object_count = VALUES(object_count),
    account_name = VALUES(account_name),
    metric_date  = VALUES(metric_date),
    last_seen    = VALUES(last_seen);
"""

UPSERT_TAG = """
INSERT INTO `aws_s3_tags`
    (bucket_name, account_name, tag_key, tag_value, last_seen)
VALUES
    (%(bucket_name)s, %(account_name)s, %(tag_key)s, %(tag_value)s, %(last_seen)s)
ON DUPLICATE KEY UPDATE
    tag_value  = VALUES(tag_value),
    last_seen  = VALUES(last_seen);
"""

DELETE_STALE_BUCKETS = "DELETE FROM `aws_s3_buckets` WHERE account_name = %s AND last_seen < %s;"
DELETE_STALE_STORAGE = "DELETE FROM `aws_s3_storage` WHERE account_name = %s AND last_seen < %s;"
DELETE_STALE_TAGS    = "DELETE FROM `aws_s3_tags`    WHERE account_name = %s AND last_seen < %s;"

# ─────────────────────────────────────────────
# CloudWatch storage type dimensions
# ─────────────────────────────────────────────
SIZE_STORAGE_TYPES = [
    "StandardStorage",
    "StandardIAStorage",
    "OneZoneIAStorage",
    "ReducedRedundancyStorage",
    "GlacierInstantRetrievalStorage",
    "GlacierStorage",
    "DeepArchiveStorage",
    "IntelligentTieringFAStorage",
    "IntelligentTieringIAStorage",
    "IntelligentTieringAAStorage",
    "IntelligentTieringAIAStorage",
    "IntelligentTieringDAAStorage",
    "ExpressOneZoneStorage",
]

# get_metric_data allows 500 metric queries per call.
# Each bucket needs 14 queries (13 size types + 1 object count).
# floor(500 / 14) = 35 buckets per API call.
CW_BATCH_SIZE = 35


# ─────────────────────────────────────────────
# DB INIT
# ─────────────────────────────────────────────
def init_db(db_config):
    conn = mysql.connector.connect(**db_config)
    cur  = conn.cursor()
    cur.execute(DDL_BUCKETS)
    cur.execute(DDL_STORAGE)
    cur.execute(DDL_TAGS)
    conn.commit()
    return conn, cur


# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────
def safe_get(s3, method, bucket, **kwargs):
    """Call an s3 bucket config method; return {} on access/config errors."""
    try:
        return getattr(s3, method)(Bucket=bucket, **kwargs)
    except ClientError:
        return {}


def get_bucket_region(s3, bucket_name):
    """Return the region string for a bucket. us-east-1 returns None from AWS — normalize it."""
    try:
        resp = s3.get_bucket_location(Bucket=bucket_name)
        return resp.get("LocationConstraint") or "us-east-1"
    except ClientError:
        return "unknown"


def build_metric_queries(bucket_names):
    """
    Build the MetricDataQueries list for a batch of buckets.

    For each bucket we request:
      - BucketSizeBytes for each of the 13 SIZE_STORAGE_TYPES
      - NumberOfObjects for AllStorageTypes

    Query IDs are positional (s{bi}t{si} and o{bi}) so they stay within the
    32-char ID limit and contain no special characters.

    Returns (queries, id_map, start, end) where id_map maps query_id ->
    (bucket_name, storage_type_or_"AllStorageTypes").
    """
    end   = datetime.now(timezone.utc)
    start = end - timedelta(days=3)

    queries = []
    id_map  = {}

    for bi, bucket_name in enumerate(bucket_names):
        for si, stype in enumerate(SIZE_STORAGE_TYPES):
            qid = f"s{bi}t{si}"
            queries.append({
                "Id":    qid,
                "Label": f"{bucket_name}/{stype}",
                "MetricStat": {
                    "Metric": {
                        "Namespace":  "AWS/S3",
                        "MetricName": "BucketSizeBytes",
                        "Dimensions": [
                            {"Name": "BucketName",  "Value": bucket_name},
                            {"Name": "StorageType", "Value": stype},
                        ],
                    },
                    "Period": 86400,
                    "Stat":   "Average",
                },
                "ReturnData": True,
            })
            id_map[qid] = (bucket_name, stype)

        qid = f"o{bi}"
        queries.append({
            "Id":    qid,
            "Label": f"{bucket_name}/AllStorageTypes",
            "MetricStat": {
                "Metric": {
                    "Namespace":  "AWS/S3",
                    "MetricName": "NumberOfObjects",
                    "Dimensions": [
                        {"Name": "BucketName",  "Value": bucket_name},
                        {"Name": "StorageType", "Value": "AllStorageTypes"},
                    ],
                },
                "Period": 86400,
                "Stat":   "Average",
            },
            "ReturnData": True,
        })
        id_map[qid] = (bucket_name, "AllStorageTypes")

    return queries, id_map, start, end


def fetch_metric_batch(cw, bucket_names):
    """
    Fetch all CW S3 metrics for a list of bucket names using get_metric_data.

    Returns dict: { bucket_name: { storage_type: (size_bytes, metric_date), ... ,
                                   "__obj_count": int, "__obj_date": date } }
    """
    results = {name: {} for name in bucket_names}
    queries, id_map, start, end = build_metric_queries(bucket_names)

    next_token = None
    while True:
        kwargs = {
            "MetricDataQueries": queries,
            "StartTime":         start,
            "EndTime":           end,
            "ScanBy":            "TimestampDescending",
        }
        if next_token:
            kwargs["NextToken"] = next_token

        try:
            resp = cw.get_metric_data(**kwargs)
        except ClientError as e:
            print(f"     ✘  get_metric_data failed: {e}")
            break

        for result in resp.get("MetricDataResults", []):
            qid        = result["Id"]
            timestamps = result.get("Timestamps", [])
            values     = result.get("Values", [])

            if not timestamps:
                continue  # no data for this bucket/storage type

            latest_val = int(values[0])
            latest_ts  = timestamps[0]

            bucket_name, stype = id_map[qid]

            if stype == "AllStorageTypes":
                results[bucket_name]["__obj_count"] = latest_val
                results[bucket_name]["__obj_date"]  = latest_ts.date()
            else:
                results[bucket_name][stype] = (latest_val, latest_ts.date())

        next_token = resp.get("NextToken")
        if not next_token:
            break

    return results


def collect_storage_metrics_batch(cw, bucket_names, account_name, cur, now):
    """
    Fetch CloudWatch storage metrics for all buckets, batched CW_BATCH_SIZE at a time.
    Writes results to aws_s3_storage.
    """
    for i in range(0, len(bucket_names), CW_BATCH_SIZE):
        batch      = bucket_names[i : i + CW_BATCH_SIZE]
        batch_num  = i // CW_BATCH_SIZE + 1
        total_batches = (len(bucket_names) + CW_BATCH_SIZE - 1) // CW_BATCH_SIZE
        print(f"     ↳ CloudWatch batch {batch_num}/{total_batches} ({len(batch)} buckets)")

        metrics = fetch_metric_batch(cw, batch)

        for bucket_name, data in metrics.items():
            obj_count   = data.get("__obj_count", 0)
            obj_date    = data.get("__obj_date")
            total_bytes = 0
            any_data    = False

            for stype in SIZE_STORAGE_TYPES:
                if stype not in data:
                    continue
                size_bytes, metric_date = data[stype]
                if size_bytes <= 0:
                    continue

                any_data     = True
                total_bytes += size_bytes

                cur.execute(UPSERT_STORAGE, {
                    "bucket_name":  bucket_name,
                    "storage_type": stype,
                    "size_bytes":   size_bytes,
                    "object_count": 0,
                    "account_name": account_name,
                    "metric_date":  metric_date,
                    "last_seen":    now,
                })

            if any_data or obj_count > 0:
                cur.execute(UPSERT_STORAGE, {
                    "bucket_name":  bucket_name,
                    "storage_type": "AllStorageTypes",
                    "size_bytes":   total_bytes,
                    "object_count": obj_count,
                    "account_name": account_name,
                    "metric_date":  obj_date,
                    "last_seen":    now,
                })


def upsert_tags(cur, bucket_name, account_name, tags, now):
    for tag in tags:
        cur.execute(UPSERT_TAG, {
            "bucket_name":  bucket_name,
            "account_name": account_name,
            "tag_key":      tag.get("Key", ""),
            "tag_value":    tag.get("Value", ""),
            "last_seen":    now,
        })


# ─────────────────────────────────────────────
# COLLECTOR
# ─────────────────────────────────────────────
def collect_buckets(s3, cw, account_name, cur, now, bucket_filter=None):
    """
    Collect all buckets for an account.
    s3 and cw clients must both target us-east-1.

    Two-phase approach:
      Phase 1 — bucket metadata: serial per-bucket config API calls (fast, O(1) each)
      Phase 2 — CloudWatch metrics: batched get_metric_data (35 buckets per API call)
    """
    try:
        bucket_list = s3.list_buckets().get("Buckets", [])
    except ClientError as e:
        print(f"     ✘  list_buckets failed: {e}")
        return 0

    if bucket_filter:
        bucket_list = [b for b in bucket_list if b["Name"] == bucket_filter]

    print(f"     {len(bucket_list)} buckets — collecting metadata...")

    # ── Phase 1: bucket metadata ─────────────────────────────────────────
    for bucket in bucket_list:
        name    = bucket["Name"]
        created = bucket.get("CreationDate")
        if created:
            created = created.replace(tzinfo=None)

        region = get_bucket_region(s3, name)

        v_resp     = safe_get(s3, "get_bucket_versioning", name)
        versioning = v_resp.get("Status", "Disabled") or "Disabled"
        mfa_delete = v_resp.get("MFADelete", "Disabled") or "Disabled"

        enc_resp       = safe_get(s3, "get_bucket_encryption", name)
        enc_rules      = enc_resp.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
        enc_enabled    = 1 if enc_rules else 0
        enc_type       = ""
        if enc_rules:
            sse      = enc_rules[0].get("ApplyServerSideEncryptionByDefault", {})
            enc_type = sse.get("SSEAlgorithm", "")

        pab_resp = safe_get(s3, "get_public_access_block", name)
        pab      = pab_resp.get("PublicAccessBlockConfiguration", {})
        bpa  = int(pab.get("BlockPublicAcls",      False))
        ipa  = int(pab.get("IgnorePublicAcls",      False))
        bpp  = int(pab.get("BlockPublicPolicy",     False))
        rpb  = int(pab.get("RestrictPublicBuckets", False))

        lc_resp    = safe_get(s3, "get_bucket_lifecycle_configuration", name)
        lc_rules   = lc_resp.get("Rules", [])

        ol_resp    = safe_get(s3, "get_object_lock_configuration", name)
        rep_resp   = safe_get(s3, "get_bucket_replication", name)
        web_resp   = safe_get(s3, "get_bucket_website", name)
        log_resp   = safe_get(s3, "get_bucket_logging", name)
        tag_resp   = safe_get(s3, "get_bucket_tagging", name)

        cur.execute(UPSERT_BUCKET, {
            "bucket_name":             name,
            "region":                  region,
            "creation_date":           created,
            "versioning":              versioning,
            "mfa_delete":              mfa_delete,
            "encryption_enabled":      enc_enabled,
            "encryption_type":         enc_type,
            "block_public_acls":       bpa,
            "ignore_public_acls":      ipa,
            "block_public_policy":     bpp,
            "restrict_public_buckets": rpb,
            "fully_public_blocked":    int(bpa and ipa and bpp and rpb),
            "lifecycle_rules":         1 if lc_rules else 0,
            "lifecycle_rule_count":    len(lc_rules),
            "object_lock_enabled":     1 if ol_resp.get("ObjectLockConfiguration") else 0,
            "replication_enabled":     1 if rep_resp.get("ReplicationConfiguration", {}).get("Rules") else 0,
            "website_enabled":         1 if (web_resp.get("IndexDocument") or web_resp.get("RoutingRules")) else 0,
            "logging_enabled":         1 if log_resp.get("LoggingEnabled") else 0,
            "account_name":            account_name,
            "last_seen":               now,
        })

        upsert_tags(cur, name, account_name, tag_resp.get("TagSet", []), now)

    # ── Phase 2: CloudWatch metrics (batched) ────────────────────────────
    bucket_names = [b["Name"] for b in bucket_list]
    print(f"     Fetching CloudWatch metrics ({len(bucket_names)} buckets, batch size {CW_BATCH_SIZE})...")
    collect_storage_metrics_batch(cw, bucket_names, account_name, cur, now)

    return len(bucket_list)


def delete_stale(cur, account_name, now):
    cur.execute(DELETE_STALE_BUCKETS, (account_name, now))
    cur.execute(DELETE_STALE_STORAGE, (account_name, now))
    cur.execute(DELETE_STALE_TAGS,    (account_name, now))


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
def main():
    conn, cur = init_db(DB_CONFIG)
    now   = datetime.now(timezone.utc).replace(tzinfo=None).strftime("%Y-%m-%d %H:%M:%S")
    total = 0

    for acct in ACCOUNTS:
        name = acct["name"]
        print(f"\n{'─'*55}")
        print(f"  Account: {name}")
        print(f"{'─'*55}")

        # ── Skip accounts opted out in config.ini ────────────────────────
        if not acct.get("s3_collect", True):
            print("  Skipping — s3_collect = false in config.ini")
            continue

        try:
            boto_session = get_session(acct)

            # S3 is a global service — use us-east-1 for both the S3 API and CloudWatch.
            # CloudWatch S3 metrics are ONLY published in us-east-1 regardless of
            # where the bucket actually lives.
            s3 = boto_session.client("s3",         region_name="us-east-1")
            cw = boto_session.client("cloudwatch", region_name="us-east-1")

            count = collect_buckets(s3, cw, name, cur, now, bucket_filter=args.bucket)
            delete_stale(cur, name, now)
            conn.commit()

            total += count
            print(f"  ✔  {count} buckets collected")

        except NoCredentialsError:
            print(f"  ✘  No credentials for {name}")
        except ClientError as e:
            code = e.response["Error"]["Code"]
            print(f"  ✘  ClientError [{code}]: {e}")
        except Exception as e:
            print(f"  ✘  Unexpected error: {e}")

    cur.close()
    conn.close()
    print(f"\n✅  Done — {total} buckets collected across {len(ACCOUNTS)} account(s).")


if __name__ == "__main__":
    main()
