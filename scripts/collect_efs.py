#!/usr/bin/env python3
"""
AWS EFS Collector
Collects EFS file systems and their mount targets across all accounts.

EFS is straightforward — describe_file_systems returns storage size breakdown
(Standard, IA, Archive) directly in the API response, no CloudWatch needed.

Tables created automatically:
    aws_efs_filesystems   — One row per file system
    aws_efs_mount_targets — Mount targets (one per AZ per file system)
    aws_efs_tags          — File system tags

Requirements:
    pip install boto3 mysql-connector-python

Usage:
    python3 collect_efs.py
    python3 collect_efs.py --account my-account-name
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
parser = argparse.ArgumentParser(description="AWS EFS Collector")
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
DDL_FILESYSTEMS = """
CREATE TABLE IF NOT EXISTS `aws_efs_filesystems` (
    `id`                      INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `fs_id`                   VARCHAR(50)   NOT NULL,
    `fs_arn`                  VARCHAR(512),
    `name`                    VARCHAR(255),
    `lifecycle_state`         VARCHAR(50),
    `performance_mode`        VARCHAR(50),
    `throughput_mode`         VARCHAR(50),
    `provisioned_throughput`  DECIMAL(10,2),
    `encrypted`               TINYINT(1)    DEFAULT 0,
    `kms_key_id`              VARCHAR(512),
    `number_of_mount_targets` SMALLINT UNSIGNED DEFAULT 0,
    `size_bytes_total`        BIGINT UNSIGNED  DEFAULT 0,
    `size_bytes_standard`     BIGINT UNSIGNED  DEFAULT 0,
    `size_bytes_ia`           BIGINT UNSIGNED  DEFAULT 0,
    `size_bytes_archive`      BIGINT UNSIGNED  DEFAULT 0,
    `dns_name`                VARCHAR(512),
    `availability_zone`       VARCHAR(100),
    `account_name`            VARCHAR(255)  NOT NULL,
    `region`                  VARCHAR(50)   NOT NULL,
    `created_at`              DATETIME,
    `last_seen`               DATETIME      NOT NULL,
    UNIQUE KEY `uq_efs_fs`    (`fs_id`, `account_name`),
    INDEX `idx_account`       (`account_name`),
    INDEX `idx_region`        (`region`),
    INDEX `idx_state`         (`lifecycle_state`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""

DDL_MOUNT_TARGETS = """
CREATE TABLE IF NOT EXISTS `aws_efs_mount_targets` (
    `id`                  INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `mount_target_id`     VARCHAR(50)   NOT NULL,
    `fs_id`               VARCHAR(50)   NOT NULL,
    `lifecycle_state`     VARCHAR(50),
    `ip_address`          VARCHAR(50),
    `subnet_id`           VARCHAR(100),
    `vpc_id`              VARCHAR(100),
    `availability_zone`   VARCHAR(100),
    `dns_name`            VARCHAR(512),
    `owner_id`            VARCHAR(50),
    `account_name`        VARCHAR(255)  NOT NULL,
    `region`              VARCHAR(50)   NOT NULL,
    `last_seen`           DATETIME      NOT NULL,
    UNIQUE KEY `uq_efs_mt` (`mount_target_id`, `account_name`),
    INDEX `idx_fs_id`      (`fs_id`),
    INDEX `idx_account`    (`account_name`),
    INDEX `idx_subnet`     (`subnet_id`),
    INDEX `idx_vpc`        (`vpc_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""

DDL_TAGS = """
CREATE TABLE IF NOT EXISTS `aws_efs_tags` (
    `id`           INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `fs_id`        VARCHAR(50)  NOT NULL,
    `account_name` VARCHAR(255) NOT NULL,
    `tag_key`      VARCHAR(255) NOT NULL,
    `tag_value`    TEXT,
    `last_seen`    DATETIME     NOT NULL,
    UNIQUE KEY `uq_efs_tag` (`fs_id`, `tag_key`),
    INDEX `idx_fs_id`       (`fs_id`),
    INDEX `idx_account`     (`account_name`),
    INDEX `idx_tag_key`     (`tag_key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""

# ─────────────────────────────────────────────
# SQL
# ─────────────────────────────────────────────
UPSERT_FS = """
INSERT INTO `aws_efs_filesystems`
    (fs_id, fs_arn, name, lifecycle_state, performance_mode, throughput_mode,
     provisioned_throughput, encrypted, kms_key_id, number_of_mount_targets,
     size_bytes_total, size_bytes_standard, size_bytes_ia, size_bytes_archive,
     dns_name, availability_zone, account_name, region, created_at, last_seen)
VALUES
    (%(fs_id)s, %(fs_arn)s, %(name)s, %(lifecycle_state)s, %(performance_mode)s,
     %(throughput_mode)s, %(provisioned_throughput)s, %(encrypted)s, %(kms_key_id)s,
     %(number_of_mount_targets)s, %(size_bytes_total)s, %(size_bytes_standard)s,
     %(size_bytes_ia)s, %(size_bytes_archive)s, %(dns_name)s, %(availability_zone)s,
     %(account_name)s, %(region)s, %(created_at)s, %(last_seen)s)
ON DUPLICATE KEY UPDATE
    name                    = VALUES(name),
    lifecycle_state         = VALUES(lifecycle_state),
    throughput_mode         = VALUES(throughput_mode),
    provisioned_throughput  = VALUES(provisioned_throughput),
    number_of_mount_targets = VALUES(number_of_mount_targets),
    size_bytes_total        = VALUES(size_bytes_total),
    size_bytes_standard     = VALUES(size_bytes_standard),
    size_bytes_ia           = VALUES(size_bytes_ia),
    size_bytes_archive      = VALUES(size_bytes_archive),
    last_seen               = VALUES(last_seen);
"""

UPSERT_MT = """
INSERT INTO `aws_efs_mount_targets`
    (mount_target_id, fs_id, lifecycle_state, ip_address, subnet_id, vpc_id,
     availability_zone, dns_name, owner_id, account_name, region, last_seen)
VALUES
    (%(mount_target_id)s, %(fs_id)s, %(lifecycle_state)s, %(ip_address)s,
     %(subnet_id)s, %(vpc_id)s, %(availability_zone)s, %(dns_name)s,
     %(owner_id)s, %(account_name)s, %(region)s, %(last_seen)s)
ON DUPLICATE KEY UPDATE
    lifecycle_state   = VALUES(lifecycle_state),
    ip_address        = VALUES(ip_address),
    last_seen         = VALUES(last_seen);
"""

UPSERT_TAG = """
INSERT INTO `aws_efs_tags` (fs_id, account_name, tag_key, tag_value, last_seen)
VALUES (%(fs_id)s, %(account_name)s, %(tag_key)s, %(tag_value)s, %(last_seen)s)
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
    for ddl in (DDL_FILESYSTEMS, DDL_MOUNT_TARGETS, DDL_TAGS):
        cur.execute(ddl)
    conn.commit()
    return conn, cur


# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────
def upsert_tags(cur, fs_id, account_name, tags, now):
    for tag in tags:
        k = tag.get("Key", "").strip()
        v = tag.get("Value", "").strip()
        if not k:
            continue
        cur.execute(UPSERT_TAG, {
            "fs_id":        fs_id,
            "account_name": account_name,
            "tag_key":      k,
            "tag_value":    v,
            "last_seen":    now,
        })


def delete_stale(cur, account_name, region, now):
    cur.execute("""
        DELETE FROM `aws_efs_filesystems`
        WHERE account_name = %s AND region = %s AND last_seen < %s
    """, (account_name, region, now))
    cur.execute("""
        DELETE FROM `aws_efs_mount_targets`
        WHERE account_name = %s AND region = %s AND last_seen < %s
    """, (account_name, region, now))
    # Clean up orphaned tags
    cur.execute("""
        DELETE t FROM `aws_efs_tags` t
        WHERE t.account_name = %s
          AND t.fs_id NOT IN (
              SELECT fs_id FROM `aws_efs_filesystems` WHERE account_name = %s
          )
    """, (account_name, account_name))


# ─────────────────────────────────────────────
# COLLECTORS
# ─────────────────────────────────────────────
def collect_filesystems(efs, account_name, region, cur, now):
    count = 0
    paginator = efs.get_paginator("describe_file_systems")
    for page in paginator.paginate():
        for fs in page.get("FileSystems", []):
            fs_id = fs["FileSystemId"]

            # SizeInBytes breakdown — available directly in the API response
            size       = fs.get("SizeInBytes", {})
            size_total = size.get("Value", 0)

            # ValueInStandard was added later — fall back gracefully
            size_std     = size.get("ValueInStandard", 0) or 0
            size_ia      = size.get("ValueInIA", 0) or 0
            size_archive = size.get("ValueInArchive", 0) or 0

            # If ValueInStandard isn't returned (older API), derive it
            if size_std == 0 and size_total > 0:
                size_std = size_total - size_ia - size_archive

            # DNS name follows a predictable pattern
            dns_name = f"{fs_id}.efs.{region}.amazonaws.com"

            created = fs.get("CreationTime")
            if created:
                created = created.replace(tzinfo=None)

            provisioned_tp = fs.get("ProvisionedThroughputInMibps")

            cur.execute(UPSERT_FS, {
                "fs_id":                   fs_id,
                "fs_arn":                  fs.get("FileSystemArn", ""),
                "name":                    fs.get("Name", ""),
                "lifecycle_state":         fs.get("LifeCycleState", ""),
                "performance_mode":        fs.get("PerformanceMode", ""),
                "throughput_mode":         fs.get("ThroughputMode", ""),
                "provisioned_throughput":  provisioned_tp,
                "encrypted":               int(fs.get("Encrypted", False)),
                "kms_key_id":              fs.get("KmsKeyId", "") or "",
                "number_of_mount_targets": fs.get("NumberOfMountTargets", 0),
                "size_bytes_total":        size_total,
                "size_bytes_standard":     size_std,
                "size_bytes_ia":           size_ia,
                "size_bytes_archive":      size_archive,
                "dns_name":                dns_name,
                "availability_zone":       fs.get("AvailabilityZoneName", "") or "",
                "account_name":            account_name,
                "region":                  region,
                "created_at":              created,
                "last_seen":               now,
            })

            # Tags are embedded in the describe_file_systems response
            upsert_tags(cur, fs_id, account_name, fs.get("Tags", []), now)

            # Mount targets
            collect_mount_targets(efs, fs_id, account_name, region, cur, now)

            count += 1
    return count


def collect_mount_targets(efs, fs_id, account_name, region, cur, now):
    try:
        paginator = efs.get_paginator("describe_mount_targets")
        for page in paginator.paginate(FileSystemId=fs_id):
            for mt in page.get("MountTargets", []):
                mt_id = mt["MountTargetId"]
                az    = mt.get("AvailabilityZoneName", "") or ""

                # DNS name for a mount target is AZ-specific
                dns_name = f"{az}.{fs_id}.efs.{region}.amazonaws.com" if az else ""

                cur.execute(UPSERT_MT, {
                    "mount_target_id":  mt_id,
                    "fs_id":            fs_id,
                    "lifecycle_state":  mt.get("LifeCycleState", ""),
                    "ip_address":       mt.get("IpAddress", "") or "",
                    "subnet_id":        mt.get("SubnetId", "") or "",
                    "vpc_id":           mt.get("VpcId", "") or "",
                    "availability_zone": az,
                    "dns_name":         dns_name,
                    "owner_id":         mt.get("OwnerId", "") or "",
                    "account_name":     account_name,
                    "region":           region,
                    "last_seen":        now,
                })
    except ClientError as e:
        print(f"       ✘  describe_mount_targets [{fs_id}]: {e}")


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
def main():
    conn, cur = init_db(DB_CONFIG)
    now   = datetime.now(timezone.utc).replace(tzinfo=None).strftime("%Y-%m-%d %H:%M:%S")
    total = 0

    for acct in ACCOUNTS:
        name    = acct["name"]
        regions = acct["regions"]
        print(f"\n{'─'*55}")
        print(f"  Account: {name}")
        print(f"{'─'*55}")

        for region in regions:
            print(f"  ↳ Region: {region}")
            try:
                boto_session = get_session(acct)
                efs          = boto_session.client("efs", region_name=region)

                count = collect_filesystems(efs, name, region, cur, now)
                delete_stale(cur, name, region, now)
                conn.commit()

                total += count
                print(f"     ✔  {count} file systems")

            except NoCredentialsError:
                print(f"     ✘  No credentials for {name}")
            except ClientError as e:
                code = e.response["Error"]["Code"]
                print(f"     ✘  ClientError [{code}]: {e}")
            except Exception as e:
                print(f"     ✘  Unexpected error: {e}")

    cur.close()
    conn.close()
    print(f"\n✅  Done — {total} EFS file systems collected.")


if __name__ == "__main__":
    main()
