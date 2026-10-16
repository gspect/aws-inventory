#!/usr/bin/env python3
"""
AWS Lambda Collector — Full Function Inventory
Collects Lambda functions, their configurations, layers, environment variables
(keys only, not values), aliases, and tags across all accounts and regions.

Tables created automatically:
    aws_lambda_functions   — Full function configuration
    aws_lambda_layers      — Layers referenced by functions
    aws_lambda_aliases     — Named aliases per function
    aws_lambda_tags        — Tags for functions

Requirements:
    pip install boto3 mysql-connector-python

Usage:
    python3 collect_lambda.py
    python3 collect_lambda.py --account my-account-name
    python3 collect_lambda.py --account my-account-name --region us-west-2
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
parser = argparse.ArgumentParser(description="AWS Lambda Collector (full function inventory)")
parser.add_argument("--account", help="Only run for this account name (must match config.ini)", default=None)
parser.add_argument("--region",  help="Only collect in this region (requires --account)",       default=None)
args = parser.parse_args()

if args.account:
    ACCOUNTS = [a for a in ACCOUNTS if a["name"] == args.account]
    if not ACCOUNTS:
        print(f"[ERROR] No account named '{args.account}' found in config.ini")
        sys.exit(1)

if args.region and not args.account:
    print("[ERROR] --region requires --account")
    sys.exit(1)

# ─────────────────────────────────────────────
# DDL
# ─────────────────────────────────────────────

DDL_FUNCTIONS = """
CREATE TABLE IF NOT EXISTS `aws_lambda_functions` (
    `id`                        INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `function_name`             VARCHAR(255)  NOT NULL,
    `function_arn`              VARCHAR(512)  NOT NULL,
    `description`               TEXT,
    `runtime`                   VARCHAR(50),
    `handler`                   VARCHAR(255),
    `role_arn`                  VARCHAR(512),
    `code_size`                 BIGINT UNSIGNED DEFAULT 0,
    `memory_mb`                 SMALLINT UNSIGNED,
    `timeout_sec`               SMALLINT UNSIGNED,
    `architecture`              VARCHAR(20),
    `package_type`              VARCHAR(20),
    `state`                     VARCHAR(50),
    `state_reason`              TEXT,
    `last_update_status`        VARCHAR(50),
    `last_update_reason`        TEXT,
    `vpc_id`                    VARCHAR(50),
    `subnet_ids`                TEXT,
    `sg_ids`                    TEXT,
    `env_var_keys`              TEXT,
    `env_var_count`             SMALLINT UNSIGNED DEFAULT 0,
    `kms_key_arn`               VARCHAR(512),
    `reserved_concurrency`      INT,
    `layer_arns`                TEXT,
    `layer_count`               TINYINT UNSIGNED DEFAULT 0,
    `image_uri`                 VARCHAR(512),
    `ephemeral_storage_mb`      INT UNSIGNED,
    `code_signing_config_arn`   VARCHAR(512),
    `logging_log_group`         VARCHAR(512),
    `logging_log_format`        VARCHAR(50),
    `logging_app_level`         VARCHAR(20),
    `logging_sys_level`         VARCHAR(20),
    `snap_start_apply_on`       VARCHAR(50),
    `snap_start_optimization`   VARCHAR(50),
    `modified_at`               DATETIME,
    `account_name`              VARCHAR(255)  NOT NULL,
    `region`                    VARCHAR(50)   NOT NULL,
    `last_seen`                 DATETIME      NOT NULL,
    UNIQUE KEY `uq_lambda_fn`   (`function_arn`(300)),
    INDEX `idx_fn_name`         (`function_name`),
    INDEX `idx_runtime`         (`runtime`),
    INDEX `idx_account`         (`account_name`),
    INDEX `idx_region`          (`region`),
    INDEX `idx_state`           (`state`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""

DDL_LAYERS = """
CREATE TABLE IF NOT EXISTS `aws_lambda_layers` (
    `id`            INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `function_arn`  VARCHAR(512)  NOT NULL,
    `layer_arn`     VARCHAR(512)  NOT NULL,
    `layer_name`    VARCHAR(255),
    `layer_version` INT UNSIGNED,
    `code_size`     BIGINT UNSIGNED DEFAULT 0,
    `account_name`  VARCHAR(255)  NOT NULL,
    `region`        VARCHAR(50)   NOT NULL,
    `last_seen`     DATETIME      NOT NULL,
    UNIQUE KEY `uq_lambda_layer` (`function_arn`(200), `layer_arn`(200)),
    INDEX `idx_layer_name`  (`layer_name`),
    INDEX `idx_account`     (`account_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""

DDL_ALIASES = """
CREATE TABLE IF NOT EXISTS `aws_lambda_aliases` (
    `id`              INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `function_name`   VARCHAR(255)  NOT NULL,
    `function_arn`    VARCHAR(512)  NOT NULL,
    `alias_name`      VARCHAR(128)  NOT NULL,
    `alias_arn`       VARCHAR(512)  NOT NULL,
    `function_version`VARCHAR(20),
    `description`     TEXT,
    `routing_config`  TEXT,
    `account_name`    VARCHAR(255)  NOT NULL,
    `region`          VARCHAR(50)   NOT NULL,
    `last_seen`       DATETIME      NOT NULL,
    UNIQUE KEY `uq_lambda_alias` (`alias_arn`(300)),
    INDEX `idx_function_name` (`function_name`),
    INDEX `idx_account`       (`account_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""

DDL_TAGS = """
CREATE TABLE IF NOT EXISTS `aws_lambda_tags` (
    `id`            INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `function_arn`  VARCHAR(512)  NOT NULL,
    `account_name`  VARCHAR(255)  NOT NULL,
    `tag_key`       VARCHAR(255)  NOT NULL,
    `tag_value`     TEXT,
    `last_seen`     DATETIME      NOT NULL,
    UNIQUE KEY `uq_lambda_tag` (`function_arn`(200), `account_name`, `tag_key`),
    INDEX `idx_function_arn`  ((SUBSTRING(`function_arn`, 1, 200))),
    INDEX `idx_account`       (`account_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""

# ─────────────────────────────────────────────
# UPSERTS
# ─────────────────────────────────────────────

UPSERT_FUNCTION = """
INSERT INTO `aws_lambda_functions`
    (function_name, function_arn, description, runtime, handler, role_arn,
     code_size, memory_mb, timeout_sec, architecture, package_type,
     state, state_reason, last_update_status, last_update_reason,
     vpc_id, subnet_ids, sg_ids,
     env_var_keys, env_var_count, kms_key_arn, reserved_concurrency,
     layer_arns, layer_count, image_uri, ephemeral_storage_mb,
     code_signing_config_arn,
     logging_log_group, logging_log_format, logging_app_level, logging_sys_level,
     snap_start_apply_on, snap_start_optimization,
     modified_at, account_name, region, last_seen)
VALUES
    (%(function_name)s, %(function_arn)s, %(description)s, %(runtime)s, %(handler)s,
     %(role_arn)s, %(code_size)s, %(memory_mb)s, %(timeout_sec)s, %(architecture)s,
     %(package_type)s, %(state)s, %(state_reason)s, %(last_update_status)s,
     %(last_update_reason)s, %(vpc_id)s, %(subnet_ids)s, %(sg_ids)s,
     %(env_var_keys)s, %(env_var_count)s, %(kms_key_arn)s, %(reserved_concurrency)s,
     %(layer_arns)s, %(layer_count)s, %(image_uri)s, %(ephemeral_storage_mb)s,
     %(code_signing_config_arn)s,
     %(logging_log_group)s, %(logging_log_format)s,
     %(logging_app_level)s, %(logging_sys_level)s,
     %(snap_start_apply_on)s, %(snap_start_optimization)s,
     %(modified_at)s, %(account_name)s, %(region)s, %(last_seen)s)
ON DUPLICATE KEY UPDATE
    function_name          = VALUES(function_name),
    description            = VALUES(description),
    runtime                = VALUES(runtime),
    handler                = VALUES(handler),
    role_arn               = VALUES(role_arn),
    code_size              = VALUES(code_size),
    memory_mb              = VALUES(memory_mb),
    timeout_sec            = VALUES(timeout_sec),
    architecture           = VALUES(architecture),
    package_type           = VALUES(package_type),
    state                  = VALUES(state),
    state_reason           = VALUES(state_reason),
    last_update_status     = VALUES(last_update_status),
    last_update_reason     = VALUES(last_update_reason),
    vpc_id                 = VALUES(vpc_id),
    subnet_ids             = VALUES(subnet_ids),
    sg_ids                 = VALUES(sg_ids),
    env_var_keys           = VALUES(env_var_keys),
    env_var_count          = VALUES(env_var_count),
    kms_key_arn            = VALUES(kms_key_arn),
    reserved_concurrency   = VALUES(reserved_concurrency),
    layer_arns             = VALUES(layer_arns),
    layer_count            = VALUES(layer_count),
    image_uri              = VALUES(image_uri),
    ephemeral_storage_mb   = VALUES(ephemeral_storage_mb),
    code_signing_config_arn= VALUES(code_signing_config_arn),
    logging_log_group      = VALUES(logging_log_group),
    logging_log_format     = VALUES(logging_log_format),
    logging_app_level      = VALUES(logging_app_level),
    logging_sys_level      = VALUES(logging_sys_level),
    snap_start_apply_on    = VALUES(snap_start_apply_on),
    snap_start_optimization= VALUES(snap_start_optimization),
    modified_at            = VALUES(modified_at),
    account_name           = VALUES(account_name),
    region                 = VALUES(region),
    last_seen              = VALUES(last_seen)
"""

UPSERT_LAYER = """
INSERT INTO `aws_lambda_layers`
    (function_arn, layer_arn, layer_name, layer_version, code_size,
     account_name, region, last_seen)
VALUES
    (%(function_arn)s, %(layer_arn)s, %(layer_name)s, %(layer_version)s,
     %(code_size)s, %(account_name)s, %(region)s, %(last_seen)s)
ON DUPLICATE KEY UPDATE
    layer_name    = VALUES(layer_name),
    layer_version = VALUES(layer_version),
    code_size     = VALUES(code_size),
    last_seen     = VALUES(last_seen)
"""

UPSERT_ALIAS = """
INSERT INTO `aws_lambda_aliases`
    (function_name, function_arn, alias_name, alias_arn, function_version,
     description, routing_config, account_name, region, last_seen)
VALUES
    (%(function_name)s, %(function_arn)s, %(alias_name)s, %(alias_arn)s,
     %(function_version)s, %(description)s, %(routing_config)s,
     %(account_name)s, %(region)s, %(last_seen)s)
ON DUPLICATE KEY UPDATE
    function_version = VALUES(function_version),
    description      = VALUES(description),
    routing_config   = VALUES(routing_config),
    last_seen        = VALUES(last_seen)
"""

UPSERT_TAG = """
INSERT INTO `aws_lambda_tags`
    (function_arn, account_name, tag_key, tag_value, last_seen)
VALUES
    (%(function_arn)s, %(account_name)s, %(tag_key)s, %(tag_value)s, %(last_seen)s)
ON DUPLICATE KEY UPDATE
    tag_value = VALUES(tag_value),
    last_seen = VALUES(last_seen)
"""

# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────

def _int(v, default=None):
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def _arn_layer_name(arn: str) -> str:
    """Extract layer name from a layer version ARN."""
    # arn:aws:lambda:region:acct:layer:name:version
    parts = arn.split(":")
    if len(parts) >= 8:
        return parts[6]
    if len(parts) >= 7:
        return parts[6]
    return arn.split("/")[-1] if "/" in arn else arn


def _parse_dt(val) -> str | None:
    """Normalize a datetime value (string or datetime object) to bare datetime string."""
    if val is None:
        return None
    from datetime import datetime as _dt
    if isinstance(val, _dt):
        return val.replace(tzinfo=None).strftime("%Y-%m-%d %H:%M:%S")
    # boto3 returns Lambda LastModified as an ISO string e.g. "2024-01-15T10:23:45.000+0000"
    try:
        s = str(val)[:19].replace("T", " ")
        return s
    except Exception:
        return None


# ─────────────────────────────────────────────
# DB INIT
# ─────────────────────────────────────────────

def init_db(cfg: dict):
    conn = mysql.connector.connect(**cfg)
    cur  = conn.cursor()
    for ddl in (DDL_FUNCTIONS, DDL_LAYERS, DDL_ALIASES, DDL_TAGS):
        cur.execute(ddl)
    conn.commit()
    return conn, cur


def delete_stale(cur, account_name: str, region: str, now: str):
    """Remove rows that were not seen in the current sync run for this account/region."""
    # Tables with region column
    for table in ("aws_lambda_functions", "aws_lambda_layers", "aws_lambda_aliases"):
        cur.execute(f"""
            DELETE FROM `{table}`
            WHERE account_name = %s AND region = %s AND last_seen < %s
        """, (account_name, region, now))
    # aws_lambda_tags has no region column — scope by account only
    cur.execute("""
        DELETE FROM `aws_lambda_tags`
        WHERE account_name = %s AND last_seen < %s
    """, (account_name, now))


# ─────────────────────────────────────────────
# COLLECTORS
# ─────────────────────────────────────────────

def collect_lambda_functions(session, account_name: str, region: str, cur, now: str) -> int:
    """Collect all Lambda functions in an account/region, with layers, aliases, and tags."""
    fn_count = 0
    try:
        lam   = session.client("lambda", region_name=region)
        pager = lam.get_paginator("list_functions")

        for page in pager.paginate():
            for fn in page.get("Functions", []):
                fn_arn  = fn.get("FunctionArn", "")
                fn_name = fn.get("FunctionName", "")

                # ── VPC config ───────────────────────────────────────────
                vpc_cfg    = fn.get("VpcConfig") or {}
                vpc_id     = vpc_cfg.get("VpcId") or None
                subnet_ids = json.dumps(vpc_cfg.get("SubnetIds", [])) if vpc_cfg.get("SubnetIds") else None
                sg_ids     = json.dumps(vpc_cfg.get("SecurityGroupIds", [])) if vpc_cfg.get("SecurityGroupIds") else None

                # ── Env vars (keys only — no secret values) ──────────────
                env       = fn.get("Environment") or {}
                env_keys  = sorted(env.get("Variables", {}).keys())
                env_count = len(env_keys)

                # ── Layers ───────────────────────────────────────────────
                layers     = fn.get("Layers", [])
                layer_arns = json.dumps([l.get("Arn", "") for l in layers]) if layers else None

                # ── Logging config (newer Lambda logging config) ──────────
                log_cfg    = fn.get("LoggingConfig") or {}
                log_group  = log_cfg.get("LogGroup") or None
                log_format = log_cfg.get("LogFormat") or None
                log_app    = log_cfg.get("ApplicationLogLevel") or None
                log_sys    = log_cfg.get("SystemLogLevel") or None

                # ── SnapStart ────────────────────────────────────────────
                snap       = fn.get("SnapStart") or {}
                snap_apply = snap.get("ApplyOn") or None
                snap_opt   = snap.get("OptimizationStatus") or None

                # ── Ephemeral storage ────────────────────────────────────
                ephem_mb   = _int((fn.get("EphemeralStorage") or {}).get("Size"))

                # ── Image URI (container packages) ───────────────────────
                code       = fn.get("Code") or {}
                image_uri  = code.get("ImageUri") or fn.get("ImageUri") or None

                # ── Modified date ────────────────────────────────────────
                modified_at = _parse_dt(fn.get("LastModified"))

                # ── Architecture (defaults to x86_64) ────────────────────
                arch_list = fn.get("Architectures") or ["x86_64"]
                arch      = arch_list[0] if arch_list else "x86_64"

                # ── Reserved concurrency (separate API call) ──────────────
                reserved_conc = None
                try:
                    cc = lam.get_function_concurrency(FunctionName=fn_arn)
                    reserved_conc = cc.get("ReservedConcurrentExecutions")
                except ClientError:
                    pass

                cur.execute(UPSERT_FUNCTION, {
                    "function_name":         fn_name,
                    "function_arn":          fn_arn,
                    "description":           fn.get("Description") or None,
                    "runtime":               fn.get("Runtime") or None,
                    "handler":               fn.get("Handler") or None,
                    "role_arn":              fn.get("Role") or None,
                    "code_size":             _int(fn.get("CodeSize"), 0),
                    "memory_mb":             _int(fn.get("MemorySize")),
                    "timeout_sec":           _int(fn.get("Timeout")),
                    "architecture":          arch,
                    "package_type":          fn.get("PackageType") or "Zip",
                    "state":                 (fn.get("State") or "Active"),
                    "state_reason":          fn.get("StateReason") or None,
                    "last_update_status":    fn.get("LastUpdateStatus") or None,
                    "last_update_reason":    fn.get("LastUpdateStatusReason") or None,
                    "vpc_id":                vpc_id,
                    "subnet_ids":            subnet_ids,
                    "sg_ids":                sg_ids,
                    "env_var_keys":          json.dumps(env_keys) if env_keys else None,
                    "env_var_count":         env_count,
                    "kms_key_arn":           fn.get("KMSKeyArn") or None,
                    "reserved_concurrency":  reserved_conc,
                    "layer_arns":            layer_arns,
                    "layer_count":           len(layers),
                    "image_uri":             image_uri,
                    "ephemeral_storage_mb":  ephem_mb,
                    "code_signing_config_arn": fn.get("CodeSigningConfigArn") or None,
                    "logging_log_group":     log_group,
                    "logging_log_format":    log_format,
                    "logging_app_level":     log_app,
                    "logging_sys_level":     log_sys,
                    "snap_start_apply_on":   snap_apply,
                    "snap_start_optimization": snap_opt,
                    "modified_at":           modified_at,
                    "account_name":          account_name,
                    "region":                region,
                    "last_seen":             now,
                })

                # ── Layers (detailed) ─────────────────────────────────────
                for layer in layers:
                    larn = layer.get("Arn", "")
                    parts = larn.split(":")
                    lver  = _int(parts[-1]) if parts else None
                    lname = _arn_layer_name(larn)
                    cur.execute(UPSERT_LAYER, {
                        "function_arn":  fn_arn,
                        "layer_arn":     larn,
                        "layer_name":    lname,
                        "layer_version": lver,
                        "code_size":     _int(layer.get("CodeSize"), 0),
                        "account_name":  account_name,
                        "region":        region,
                        "last_seen":     now,
                    })

                # ── Aliases ───────────────────────────────────────────────
                try:
                    alias_pager = lam.get_paginator("list_aliases")
                    for alias_page in alias_pager.paginate(FunctionName=fn_arn):
                        for alias in alias_page.get("Aliases", []):
                            rc = alias.get("RoutingConfig") or {}
                            cur.execute(UPSERT_ALIAS, {
                                "function_name":    fn_name,
                                "function_arn":     fn_arn,
                                "alias_name":       alias.get("Name", ""),
                                "alias_arn":        alias.get("AliasArn", ""),
                                "function_version": alias.get("FunctionVersion") or None,
                                "description":      alias.get("Description") or None,
                                "routing_config":   json.dumps(rc) if rc else None,
                                "account_name":     account_name,
                                "region":           region,
                                "last_seen":        now,
                            })
                except ClientError:
                    pass

                # ── Tags ──────────────────────────────────────────────────
                try:
                    tag_resp = lam.list_tags(Resource=fn_arn)
                    for k, v in tag_resp.get("Tags", {}).items():
                        cur.execute(UPSERT_TAG, {
                            "function_arn":  fn_arn,
                            "account_name":  account_name,
                            "tag_key":       k,
                            "tag_value":     v,
                            "last_seen":     now,
                        })
                except ClientError:
                    pass

                fn_count += 1

    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code not in ("AccessDeniedException", "UnrecognizedClientException"):
            print(f"    [WARN] Lambda {account_name}/{region}: {e.response['Error']['Message']}")
    except Exception as e:
        print(f"    [WARN] Lambda {account_name}/{region}: {e}")

    return fn_count


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

def main():
    conn, cur = init_db(DB_CONFIG)
    now = datetime.now(timezone.utc).replace(tzinfo=None).strftime("%Y-%m-%d %H:%M:%S")

    total_functions = 0

    for acct in ACCOUNTS:
        name    = acct["name"]
        regions = acct.get("regions", ["us-east-1"])

        # Allow single-region override
        if args.region:
            regions = [args.region]

        print(f"\n{'─'*60}")
        print(f"  Account: {name}")
        print(f"{'─'*60}")

        for region in regions:
            print(f"  ↳ Region: {region}")
            try:
                session = get_session(acct)

                fn_count = collect_lambda_functions(session, name, region, cur, now)
                total_functions += fn_count
                print(f"     ✔  Lambda: {fn_count} functions")

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
    print(f"   Lambda functions : {total_functions}")
    print(f"{'═'*60}")


if __name__ == "__main__":
    main()
