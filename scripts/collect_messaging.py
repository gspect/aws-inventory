#!/usr/bin/env python3
"""
AWS Messaging Collector — SQS / SNS / Lambda Event Source Mappings
Collects SQS queues, SNS topics & subscriptions, and Lambda event source
mappings (ESMs) across all accounts.  Answers questions like:
  • What Lambda is processing queue X?
  • What breaks if this queue backs up?
  • Which SNS topics fan out to which queues / Lambdas?

Tables created automatically:
    aws_sqs_queues          — SQS queue attributes
    aws_sqs_tags            — Tags for SQS queues
    aws_sns_topics          — SNS topic attributes
    aws_sns_tags            — Tags for SNS topics
    aws_sns_subscriptions   — Per-topic subscription list
    aws_lambda_esms         — Lambda event source mappings (SQS, DynamoDB, Kinesis …)

Requirements:
    pip install boto3 mysql-connector-python

Usage:
    python3 collect_messaging.py
    python3 collect_messaging.py --account my-account-name
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
parser = argparse.ArgumentParser(description="AWS Messaging Collector (SQS/SNS/Lambda ESM)")
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

DDL_SQS_QUEUES = """
CREATE TABLE IF NOT EXISTS `aws_sqs_queues` (
    `id`                    INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `queue_name`            VARCHAR(255) NOT NULL,
    `queue_url`             VARCHAR(512) NOT NULL,
    `queue_arn`             VARCHAR(512),
    `queue_type`            VARCHAR(10)  DEFAULT 'standard',
    `approx_messages`       INT UNSIGNED DEFAULT 0,
    `approx_not_visible`    INT UNSIGNED DEFAULT 0,
    `approx_delayed`        INT UNSIGNED DEFAULT 0,
    `visibility_timeout`    SMALLINT UNSIGNED,
    `retention_seconds`     INT UNSIGNED,
    `max_message_size`      INT UNSIGNED,
    `delay_seconds`         SMALLINT UNSIGNED,
    `receive_wait_seconds`  SMALLINT UNSIGNED,
    `dlq_arn`               VARCHAR(512),
    `dlq_max_receives`      SMALLINT UNSIGNED,
    `kms_key_id`            VARCHAR(512),
    `created_timestamp`     VARCHAR(50),
    `account_name`          VARCHAR(255) NOT NULL,
    `region`                VARCHAR(50)  NOT NULL,
    `last_seen`             DATETIME     NOT NULL,
    UNIQUE KEY `uq_queue` (`queue_arn`(200)),
    INDEX `idx_queue_name`  (`queue_name`),
    INDEX `idx_account`     (`account_name`),
    INDEX `idx_region`      (`region`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""

DDL_SQS_TAGS = """
CREATE TABLE IF NOT EXISTS `aws_sqs_tags` (
    `id`           INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `queue_arn`    VARCHAR(512) NOT NULL,
    `account_name` VARCHAR(255) NOT NULL,
    `tag_key`      VARCHAR(255) NOT NULL,
    `tag_value`    TEXT,
    `last_seen`    DATETIME     NOT NULL,
    UNIQUE KEY `uq_sqs_tag` (`queue_arn`(200), `account_name`, `tag_key`),
    INDEX `idx_queue_arn`  ((SUBSTRING(`queue_arn`, 1, 200))),
    INDEX `idx_account`    (`account_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""

DDL_SNS_TOPICS = """
CREATE TABLE IF NOT EXISTS `aws_sns_topics` (
    `id`                    INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `topic_arn`             VARCHAR(512) NOT NULL,
    `topic_name`            VARCHAR(255) NOT NULL,
    `display_name`          VARCHAR(255),
    `subscriptions_pending` INT UNSIGNED DEFAULT 0,
    `subscriptions_confirmed` INT UNSIGNED DEFAULT 0,
    `subscriptions_deleted` INT UNSIGNED DEFAULT 0,
    `kms_key_id`            VARCHAR(512),
    `fifo_topic`            TINYINT(1)   DEFAULT 0,
    `account_name`          VARCHAR(255) NOT NULL,
    `region`                VARCHAR(50)  NOT NULL,
    `last_seen`             DATETIME     NOT NULL,
    UNIQUE KEY `uq_topic` (`topic_arn`(200)),
    INDEX `idx_topic_name`  (`topic_name`),
    INDEX `idx_account`     (`account_name`),
    INDEX `idx_region`      (`region`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""

DDL_SNS_TAGS = """
CREATE TABLE IF NOT EXISTS `aws_sns_tags` (
    `id`           INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `topic_arn`    VARCHAR(512) NOT NULL,
    `account_name` VARCHAR(255) NOT NULL,
    `tag_key`      VARCHAR(255) NOT NULL,
    `tag_value`    TEXT,
    `last_seen`    DATETIME     NOT NULL,
    UNIQUE KEY `uq_sns_tag` (`topic_arn`(200), `account_name`, `tag_key`),
    INDEX `idx_topic_arn`  ((SUBSTRING(`topic_arn`, 1, 200))),
    INDEX `idx_account`    (`account_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""

DDL_SNS_SUBSCRIPTIONS = """
CREATE TABLE IF NOT EXISTS `aws_sns_subscriptions` (
    `id`               INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `subscription_arn` VARCHAR(512) NOT NULL,
    `topic_arn`        VARCHAR(512) NOT NULL,
    `protocol`         VARCHAR(50),
    `endpoint`         TEXT,
    `endpoint_name`    VARCHAR(255),
    `account_name`     VARCHAR(255) NOT NULL,
    `region`           VARCHAR(50)  NOT NULL,
    `last_seen`        DATETIME     NOT NULL,
    UNIQUE KEY `uq_subscription` (`subscription_arn`(200)),
    INDEX `idx_topic_arn`   ((SUBSTRING(`topic_arn`, 1, 200))),
    INDEX `idx_protocol`    (`protocol`),
    INDEX `idx_account`     (`account_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""

DDL_LAMBDA_ESMS = """
CREATE TABLE IF NOT EXISTS `aws_lambda_esms` (
    `id`                    INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `esm_uuid`              VARCHAR(100) NOT NULL,
    `function_arn`          VARCHAR(512) NOT NULL,
    `function_name`         VARCHAR(255),
    `event_source_arn`      VARCHAR(512),
    `event_source_type`     VARCHAR(50),
    `state`                 VARCHAR(50),
    `batch_size`            SMALLINT UNSIGNED,
    `max_batching_window`   SMALLINT UNSIGNED,
    `bisect_on_error`       TINYINT(1)   DEFAULT 0,
    `max_concurrency`       SMALLINT UNSIGNED,
    `starting_position`     VARCHAR(50),
    `last_modified`         DATETIME,
    `account_name`          VARCHAR(255) NOT NULL,
    `region`                VARCHAR(50)  NOT NULL,
    `last_seen`             DATETIME     NOT NULL,
    UNIQUE KEY `uq_esm` (`esm_uuid`, `account_name`),
    INDEX `idx_function_arn`      ((SUBSTRING(`function_arn`, 1, 200))),
    INDEX `idx_event_source_arn`  ((SUBSTRING(`event_source_arn`, 1, 200))),
    INDEX `idx_event_source_type` (`event_source_type`),
    INDEX `idx_account`           (`account_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""

# ─────────────────────────────────────────────
# UPSERTS
# ─────────────────────────────────────────────

UPSERT_SQS_QUEUE = """
INSERT INTO `aws_sqs_queues`
    (queue_name, queue_url, queue_arn, queue_type, approx_messages,
     approx_not_visible, approx_delayed, visibility_timeout, retention_seconds,
     max_message_size, delay_seconds, receive_wait_seconds,
     dlq_arn, dlq_max_receives, kms_key_id, created_timestamp,
     account_name, region, last_seen)
VALUES
    (%(queue_name)s, %(queue_url)s, %(queue_arn)s, %(queue_type)s, %(approx_messages)s,
     %(approx_not_visible)s, %(approx_delayed)s, %(visibility_timeout)s, %(retention_seconds)s,
     %(max_message_size)s, %(delay_seconds)s, %(receive_wait_seconds)s,
     %(dlq_arn)s, %(dlq_max_receives)s, %(kms_key_id)s, %(created_timestamp)s,
     %(account_name)s, %(region)s, %(last_seen)s)
ON DUPLICATE KEY UPDATE
    queue_name           = VALUES(queue_name),
    queue_url            = VALUES(queue_url),
    queue_type           = VALUES(queue_type),
    approx_messages      = VALUES(approx_messages),
    approx_not_visible   = VALUES(approx_not_visible),
    approx_delayed       = VALUES(approx_delayed),
    visibility_timeout   = VALUES(visibility_timeout),
    retention_seconds    = VALUES(retention_seconds),
    max_message_size     = VALUES(max_message_size),
    delay_seconds        = VALUES(delay_seconds),
    receive_wait_seconds = VALUES(receive_wait_seconds),
    dlq_arn              = VALUES(dlq_arn),
    dlq_max_receives     = VALUES(dlq_max_receives),
    kms_key_id           = VALUES(kms_key_id),
    account_name         = VALUES(account_name),
    region               = VALUES(region),
    last_seen            = VALUES(last_seen);
"""

UPSERT_SQS_TAG = """
INSERT INTO `aws_sqs_tags`
    (queue_arn, account_name, tag_key, tag_value, last_seen)
VALUES
    (%(queue_arn)s, %(account_name)s, %(tag_key)s, %(tag_value)s, %(last_seen)s)
ON DUPLICATE KEY UPDATE
    tag_value = VALUES(tag_value),
    last_seen = VALUES(last_seen);
"""

UPSERT_SNS_TOPIC = """
INSERT INTO `aws_sns_topics`
    (topic_arn, topic_name, display_name, subscriptions_pending,
     subscriptions_confirmed, subscriptions_deleted, kms_key_id,
     fifo_topic, account_name, region, last_seen)
VALUES
    (%(topic_arn)s, %(topic_name)s, %(display_name)s, %(subscriptions_pending)s,
     %(subscriptions_confirmed)s, %(subscriptions_deleted)s, %(kms_key_id)s,
     %(fifo_topic)s, %(account_name)s, %(region)s, %(last_seen)s)
ON DUPLICATE KEY UPDATE
    topic_name               = VALUES(topic_name),
    display_name             = VALUES(display_name),
    subscriptions_pending    = VALUES(subscriptions_pending),
    subscriptions_confirmed  = VALUES(subscriptions_confirmed),
    subscriptions_deleted    = VALUES(subscriptions_deleted),
    kms_key_id               = VALUES(kms_key_id),
    fifo_topic               = VALUES(fifo_topic),
    account_name             = VALUES(account_name),
    region                   = VALUES(region),
    last_seen                = VALUES(last_seen);
"""

UPSERT_SNS_TAG = """
INSERT INTO `aws_sns_tags`
    (topic_arn, account_name, tag_key, tag_value, last_seen)
VALUES
    (%(topic_arn)s, %(account_name)s, %(tag_key)s, %(tag_value)s, %(last_seen)s)
ON DUPLICATE KEY UPDATE
    tag_value = VALUES(tag_value),
    last_seen = VALUES(last_seen);
"""

UPSERT_SNS_SUB = """
INSERT INTO `aws_sns_subscriptions`
    (subscription_arn, topic_arn, protocol, endpoint, endpoint_name,
     account_name, region, last_seen)
VALUES
    (%(subscription_arn)s, %(topic_arn)s, %(protocol)s, %(endpoint)s, %(endpoint_name)s,
     %(account_name)s, %(region)s, %(last_seen)s)
ON DUPLICATE KEY UPDATE
    topic_arn     = VALUES(topic_arn),
    protocol      = VALUES(protocol),
    endpoint      = VALUES(endpoint),
    endpoint_name = VALUES(endpoint_name),
    account_name  = VALUES(account_name),
    region        = VALUES(region),
    last_seen     = VALUES(last_seen);
"""

UPSERT_LAMBDA_ESM = """
INSERT INTO `aws_lambda_esms`
    (esm_uuid, function_arn, function_name, event_source_arn, event_source_type,
     state, batch_size, max_batching_window, bisect_on_error, max_concurrency,
     starting_position, last_modified, account_name, region, last_seen)
VALUES
    (%(esm_uuid)s, %(function_arn)s, %(function_name)s, %(event_source_arn)s,
     %(event_source_type)s, %(state)s, %(batch_size)s, %(max_batching_window)s,
     %(bisect_on_error)s, %(max_concurrency)s, %(starting_position)s, %(last_modified)s,
     %(account_name)s, %(region)s, %(last_seen)s)
ON DUPLICATE KEY UPDATE
    function_arn         = VALUES(function_arn),
    function_name        = VALUES(function_name),
    event_source_arn     = VALUES(event_source_arn),
    event_source_type    = VALUES(event_source_type),
    state                = VALUES(state),
    batch_size           = VALUES(batch_size),
    max_batching_window  = VALUES(max_batching_window),
    bisect_on_error      = VALUES(bisect_on_error),
    max_concurrency      = VALUES(max_concurrency),
    starting_position    = VALUES(starting_position),
    last_modified        = VALUES(last_modified),
    account_name         = VALUES(account_name),
    region               = VALUES(region),
    last_seen            = VALUES(last_seen);
"""

# ─────────────────────────────────────────────
# DB INIT
# ─────────────────────────────────────────────

def init_db(cfg: dict):
    try:
        conn = mysql.connector.connect(**cfg)
        cur  = conn.cursor()
        cur.execute(f"CREATE DATABASE IF NOT EXISTS `{cfg['database']}` CHARACTER SET utf8mb4;")
        cur.execute(f"USE `{cfg['database']}`;")
        for ddl in (DDL_SQS_QUEUES, DDL_SQS_TAGS, DDL_SNS_TOPICS,
                    DDL_SNS_TAGS, DDL_SNS_SUBSCRIPTIONS, DDL_LAMBDA_ESMS):
            cur.execute(ddl)
        conn.commit()
        print(f"✅  Connected to MySQL — database `{cfg['database']}` ready.")
        return conn, cur
    except mysql.connector.Error as e:
        print(f"[ERROR] MySQL connection failed: {e}")
        sys.exit(1)


# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────

def _int(val, default=0):
    """Safe int conversion — SQS attribute values are all strings."""
    try:
        return int(val)
    except (TypeError, ValueError):
        return default


def _arn_to_name(arn: str) -> str:
    """Extract the last segment of an ARN as a human-readable name."""
    if not arn:
        return ""
    return arn.rstrip("/").split(":")[-1].split("/")[-1]


def _esm_source_type(source_arn: str) -> str:
    """Infer event source type from the ARN prefix."""
    if not source_arn:
        return "unknown"
    a = source_arn.lower()
    if ":sqs:" in a:
        return "sqs"
    if ":dynamodb:" in a:
        return "dynamodb"
    if ":kinesis:" in a:
        return "kinesis"
    if ":kafka:" in a or "msk" in a:
        return "kafka"
    if ":mq:" in a:
        return "mq"
    return "other"


def delete_stale(cur, account_name: str, region: str, now: str):
    """Remove rows that were not touched during this sync run."""
    for table, arn_col in [
        ("aws_sqs_queues",       None),
        ("aws_sns_topics",       None),
        ("aws_sns_subscriptions",None),
        ("aws_lambda_esms",      None),
    ]:
        cur.execute(f"""
            DELETE FROM `{table}`
            WHERE last_seen < %s AND account_name = %s AND region = %s
        """, (now, account_name, region))

    # Orphaned SQS tags
    cur.execute("""
        DELETE t FROM `aws_sqs_tags` t
        LEFT JOIN `aws_sqs_queues` q
            ON t.queue_arn = q.queue_arn AND t.account_name = q.account_name
        WHERE q.queue_arn IS NULL AND t.account_name = %s
    """, (account_name,))

    # Orphaned SNS tags
    cur.execute("""
        DELETE t FROM `aws_sns_tags` t
        LEFT JOIN `aws_sns_topics` s
            ON t.topic_arn = s.topic_arn AND t.account_name = s.account_name
        WHERE s.topic_arn IS NULL AND t.account_name = %s
    """, (account_name,))


# ─────────────────────────────────────────────
# SQS
# ─────────────────────────────────────────────

def collect_sqs(session, account_name: str, region: str, cur, now: str) -> int:
    count = 0
    try:
        sqs   = session.client("sqs", region_name=region)
        pager = sqs.get_paginator("list_queues")
        for page in pager.paginate():
            for url in page.get("QueueUrls", []):
                try:
                    attrs = sqs.get_queue_attributes(
                        QueueUrl=url,
                        AttributeNames=["All"],
                    ).get("Attributes", {})
                except ClientError as e:
                    print(f"      [WARN] get_queue_attributes {url}: {e.response['Error']['Message']}")
                    continue

                queue_name = url.rstrip("/").split("/")[-1]
                queue_arn  = attrs.get("QueueArn", "")

                # Redrive / DLQ
                dlq_arn         = None
                dlq_max_recvs   = None
                redrive_raw     = attrs.get("RedrivePolicy", "")
                if redrive_raw:
                    try:
                        rd = json.loads(redrive_raw)
                        dlq_arn       = rd.get("deadLetterTargetArn")
                        dlq_max_recvs = _int(rd.get("maxReceiveCount"))
                    except Exception:
                        pass

                queue_type = "fifo" if queue_name.endswith(".fifo") else "standard"

                cur.execute(UPSERT_SQS_QUEUE, {
                    "queue_name":           queue_name,
                    "queue_url":            url,
                    "queue_arn":            queue_arn,
                    "queue_type":           queue_type,
                    "approx_messages":      _int(attrs.get("ApproximateNumberOfMessages")),
                    "approx_not_visible":   _int(attrs.get("ApproximateNumberOfMessagesNotVisible")),
                    "approx_delayed":       _int(attrs.get("ApproximateNumberOfMessagesDelayed")),
                    "visibility_timeout":   _int(attrs.get("VisibilityTimeout")),
                    "retention_seconds":    _int(attrs.get("MessageRetentionPeriod")),
                    "max_message_size":     _int(attrs.get("MaximumMessageSize")),
                    "delay_seconds":        _int(attrs.get("DelaySeconds")),
                    "receive_wait_seconds": _int(attrs.get("ReceiveMessageWaitTimeSeconds")),
                    "dlq_arn":              dlq_arn,
                    "dlq_max_receives":     dlq_max_recvs,
                    "kms_key_id":           attrs.get("KmsMasterKeyId", "") or None,
                    "created_timestamp":    attrs.get("CreatedTimestamp", ""),
                    "account_name":         account_name,
                    "region":               region,
                    "last_seen":            now,
                })

                # Tags
                if queue_arn:
                    try:
                        tag_resp = sqs.list_queue_tags(QueueUrl=url)
                        for k, v in tag_resp.get("Tags", {}).items():
                            cur.execute(UPSERT_SQS_TAG, {
                                "queue_arn":    queue_arn,
                                "account_name": account_name,
                                "tag_key":      k,
                                "tag_value":    v,
                                "last_seen":    now,
                            })
                    except ClientError:
                        pass

                count += 1

    except ClientError as e:
        print(f"    [WARN] SQS {account_name}/{region}: {e.response['Error']['Message']}")
    return count


# ─────────────────────────────────────────────
# SNS
# ─────────────────────────────────────────────

def collect_sns(session, account_name: str, region: str, cur, now: str) -> int:
    topic_count = 0
    sub_count   = 0
    try:
        sns   = session.client("sns", region_name=region)
        pager = sns.get_paginator("list_topics")
        for page in pager.paginate():
            for t in page.get("Topics", []):
                topic_arn = t["TopicArn"]

                # Only collect topics that belong to this region
                # ARN format: arn:aws:sns:<region>:<account>:<name>
                arn_parts = topic_arn.split(":")
                if len(arn_parts) >= 4 and arn_parts[3] != region:
                    continue

                topic_name = arn_parts[-1] if arn_parts else _arn_to_name(topic_arn)

                # Get topic attributes
                attrs = {}
                try:
                    attrs = sns.get_topic_attributes(TopicArn=topic_arn).get("Attributes", {})
                except ClientError:
                    pass

                cur.execute(UPSERT_SNS_TOPIC, {
                    "topic_arn":               topic_arn,
                    "topic_name":              topic_name,
                    "display_name":            attrs.get("DisplayName", "") or None,
                    "subscriptions_pending":   _int(attrs.get("SubscriptionsPending")),
                    "subscriptions_confirmed": _int(attrs.get("SubscriptionsConfirmed")),
                    "subscriptions_deleted":   _int(attrs.get("SubscriptionsDeleted")),
                    "kms_key_id":              attrs.get("KmsMasterKeyId", "") or None,
                    "fifo_topic":              int(attrs.get("FifoTopic", "false").lower() == "true"),
                    "account_name":            account_name,
                    "region":                  region,
                    "last_seen":               now,
                })
                topic_count += 1

                # Tags
                try:
                    tag_resp = sns.list_tags_for_resource(ResourceArn=topic_arn)
                    for tag in tag_resp.get("Tags", []):
                        cur.execute(UPSERT_SNS_TAG, {
                            "topic_arn":    topic_arn,
                            "account_name": account_name,
                            "tag_key":      tag.get("Key", ""),
                            "tag_value":    tag.get("Value", ""),
                            "last_seen":    now,
                        })
                except ClientError:
                    pass

                # Subscriptions for this topic
                try:
                    sub_pager = sns.get_paginator("list_subscriptions_by_topic")
                    for sub_page in sub_pager.paginate(TopicArn=topic_arn):
                        for sub in sub_page.get("Subscriptions", []):
                            sub_arn  = sub.get("SubscriptionArn", "")
                            protocol = sub.get("Protocol", "")
                            endpoint = sub.get("Endpoint", "")

                            # Skip pending-confirmation placeholders
                            if sub_arn in ("PendingConfirmation", "Deleted"):
                                sub_arn = f"{topic_arn}:{protocol}:{endpoint[:80]}"

                            cur.execute(UPSERT_SNS_SUB, {
                                "subscription_arn": sub_arn,
                                "topic_arn":        topic_arn,
                                "protocol":         protocol,
                                "endpoint":         endpoint,
                                "endpoint_name":    _arn_to_name(endpoint),
                                "account_name":     account_name,
                                "region":           region,
                                "last_seen":        now,
                            })
                            sub_count += 1
                except ClientError as e:
                    print(f"      [WARN] SNS subscriptions {topic_arn}: {e.response['Error']['Message']}")

    except ClientError as e:
        print(f"    [WARN] SNS {account_name}/{region}: {e.response['Error']['Message']}")

    return topic_count, sub_count


# ─────────────────────────────────────────────
# LAMBDA EVENT SOURCE MAPPINGS
# ─────────────────────────────────────────────

def collect_lambda_esms(session, account_name: str, region: str, cur, now: str) -> int:
    count = 0
    try:
        lam   = session.client("lambda", region_name=region)
        pager = lam.get_paginator("list_event_source_mappings")
        for page in pager.paginate():
            for esm in page.get("EventSourceMappings", []):
                uuid           = esm.get("UUID", "")
                function_arn   = esm.get("FunctionArn", "")
                source_arn     = esm.get("EventSourceArn", "")
                source_type    = _esm_source_type(source_arn)

                # last_modified is a datetime object from boto3
                last_mod = esm.get("LastModified")
                if last_mod and hasattr(last_mod, "replace"):
                    last_mod = last_mod.replace(tzinfo=None)

                # ScalingConfig.MaximumConcurrency (may not exist)
                max_conc = None
                sc = esm.get("ScalingConfig") or {}
                if sc.get("MaximumConcurrency"):
                    max_conc = _int(sc["MaximumConcurrency"])

                cur.execute(UPSERT_LAMBDA_ESM, {
                    "esm_uuid":           uuid,
                    "function_arn":       function_arn,
                    "function_name":      _arn_to_name(function_arn),
                    "event_source_arn":   source_arn,
                    "event_source_type":  source_type,
                    "state":              esm.get("State", ""),
                    "batch_size":         esm.get("BatchSize"),
                    "max_batching_window":esm.get("MaximumBatchingWindowInSeconds"),
                    "bisect_on_error":    int(esm.get("BisectBatchOnFunctionError", False)),
                    "max_concurrency":    max_conc,
                    "starting_position":  esm.get("StartingPosition", "") or None,
                    "last_modified":      last_mod,
                    "account_name":       account_name,
                    "region":             region,
                    "last_seen":          now,
                })
                count += 1

    except ClientError as e:
        code = e.response["Error"]["Code"]
        # Lambda may not be available in all regions; skip gracefully
        if code not in ("AccessDeniedException", "UnrecognizedClientException"):
            print(f"    [WARN] Lambda ESM {account_name}/{region}: {e.response['Error']['Message']}")
    return count


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

def main():
    conn, cur = init_db(DB_CONFIG)
    now = datetime.now(timezone.utc).replace(tzinfo=None).strftime("%Y-%m-%d %H:%M:%S")

    total_queues  = 0
    total_topics  = 0
    total_subs    = 0
    total_esms    = 0

    for acct in ACCOUNTS:
        name    = acct["name"]
        regions = acct.get("regions", ["us-east-1"])
        print(f"\n{'─'*60}")
        print(f"  Account: {name}")
        print(f"{'─'*60}")

        for region in regions:
            print(f"  ↳ Region: {region}")
            try:
                session = get_session(acct)

                # SQS
                q_count = collect_sqs(session, name, region, cur, now)
                total_queues += q_count
                print(f"     ✔  SQS:    {q_count} queues")

                # SNS
                t_count, s_count = collect_sns(session, name, region, cur, now)
                total_topics += t_count
                total_subs   += s_count
                print(f"     ✔  SNS:    {t_count} topics, {s_count} subscriptions")

                # Lambda ESMs
                e_count = collect_lambda_esms(session, name, region, cur, now)
                total_esms += e_count
                print(f"     ✔  Lambda: {e_count} event source mappings")

                # Stale cleanup
                delete_stale(cur, name, region, now)
                conn.commit()

            except NoCredentialsError:
                print(f"     ✘  No credentials for {name}")
            except ClientError as e:
                code = e.response["Error"]["Code"]
                print(f"     ✘  ClientError [{code}]: {e}")
            except Exception as e:
                print(f"     ✘  Unexpected error: {e}")

    cur.close()
    conn.close()

    print(f"\n{'═'*60}")
    print(f"✅  Sync complete — {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print(f"   SQS queues    : {total_queues}")
    print(f"   SNS topics    : {total_topics}")
    print(f"   Subscriptions : {total_subs}")
    print(f"   Lambda ESMs   : {total_esms}")
    print(f"{'═'*60}")


if __name__ == "__main__":
    main()
