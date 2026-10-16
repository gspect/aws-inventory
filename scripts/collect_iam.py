#!/usr/bin/env python3
"""
AWS IAM Collector
Collects IAM users, roles, attached/inline policies, policy documents,
and role trust relationships across multiple AWS accounts.

Requirements:
    pip install boto3 mysql-connector-python
"""

import json
import sys
from datetime import datetime, UTC

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
# ARG-Pass - pass arguments for cli usage
# ─────────────────────────────────────────────

import argparse

parser = argparse.ArgumentParser(description="AWS IAM Collector")
parser.add_argument("--account", help="Only run for this account name (must match config.ini)", default=None)
args = parser.parse_args()

# Filter accounts if --account flag was passed
if args.account:
    ACCOUNTS = [a for a in ACCOUNTS if a["name"] == args.account]
    if not ACCOUNTS:
        print(f"[ERROR] No account named '{args.account}' found in config.ini")
        sys.exit(1)

# ─────────────────────────────────────────────
# SQL
# ─────────────────────────────────────────────
UPSERT_PRINCIPAL = """
INSERT INTO aws_iam_principals
    (principal_id, principal_name, principal_type, arn, account_name,
     created_at, last_used, path, extra, last_seen)
VALUES
    (%(principal_id)s, %(principal_name)s, %(principal_type)s, %(arn)s,
     %(account_name)s, %(created_at)s, %(last_used)s, %(path)s, %(extra)s, %(last_seen)s)
ON DUPLICATE KEY UPDATE
    principal_name = VALUES(principal_name),
    arn            = VALUES(arn),
    last_used      = VALUES(last_used),
    extra          = VALUES(extra),
    last_seen      = VALUES(last_seen);
"""

UPSERT_POLICY = """
INSERT INTO aws_iam_policies
    (principal_id, principal_name, principal_type, account_name,
     policy_name, policy_arn, policy_type, scope, last_seen)
VALUES
    (%(principal_id)s, %(principal_name)s, %(principal_type)s, %(account_name)s,
     %(policy_name)s, %(policy_arn)s, %(policy_type)s, %(scope)s, %(last_seen)s)
ON DUPLICATE KEY UPDATE
    policy_arn  = VALUES(policy_arn),
    scope       = VALUES(scope),
    last_seen   = VALUES(last_seen);
"""

INSERT_STATEMENT = """
INSERT INTO aws_iam_policy_statements
    (policy_name, policy_arn, policy_type, principal_id, account_name,
     effect, actions, resources, conditions, sid, last_seen)
VALUES
    (%(policy_name)s, %(policy_arn)s, %(policy_type)s, %(principal_id)s,
     %(account_name)s, %(effect)s, %(actions)s, %(resources)s,
     %(conditions)s, %(sid)s, %(last_seen)s);
"""

INSERT_TRUST = """
INSERT INTO aws_iam_trust_relationships
    (role_id, role_name, account_name, trusted_type,
     trusted_arn, actions, conditions, last_seen)
VALUES
    (%(role_id)s, %(role_name)s, %(account_name)s, %(trusted_type)s,
     %(trusted_arn)s, %(actions)s, %(conditions)s, %(last_seen)s);
"""

DELETE_STATEMENTS = """
DELETE FROM aws_iam_policy_statements
WHERE principal_id = %s AND account_name = %s AND policy_name = %s;
"""

DELETE_TRUST = """
DELETE FROM aws_iam_trust_relationships
WHERE role_id = %s AND account_name = %s;
"""


# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────




def fmt_dt(dt) -> str | None:
    """Convert a datetime object to a MySQL-safe string."""
    if dt is None:
        return None
    if hasattr(dt, "strftime"):
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    return str(dt)


def to_list(val) -> list:
    """Ensure a value is always a list."""
    if isinstance(val, list):
        return val
    return [val] if val else []


def parse_policy_document(doc, policy_name, policy_arn,
                           policy_type, principal_id, account_name, now) -> list:
    """Flatten a policy document into statement rows."""
    rows = []
    if isinstance(doc, str):
        try:
            doc = json.loads(doc)
        except Exception:
            return rows

    statements = doc.get("Statement", [])
    # Normalize — some policies have a single dict instead of a list
    if isinstance(statements, dict):
        statements = [statements]

    for stmt in statements:
        if not isinstance(stmt, dict):
            continue
        effect    = stmt.get("Effect", "Allow")
        actions   = json.dumps(to_list(stmt.get("Action",   stmt.get("NotAction",   []))))
        resources = json.dumps(to_list(stmt.get("Resource", stmt.get("NotResource", []))))
        conds     = json.dumps(stmt.get("Condition", {})) if stmt.get("Condition") else None
        sid       = stmt.get("Sid", "")

        rows.append({
            "policy_name":  policy_name,
            "policy_arn":   policy_arn,
            "policy_type":  policy_type,
            "principal_id": principal_id,
            "account_name": account_name,
            "effect":       effect,
            "actions":      actions,
            "resources":    resources,
            "conditions":   conds,
            "sid":          sid,
            "last_seen":    now,
        })
    return rows


# ─────────────────────────────────────────────
# POLICY DOCUMENT FETCH
# ─────────────────────────────────────────────

def fetch_managed_policy_doc(iam, policy_arn: str) -> dict | None:
    """Fetch the default version document of a managed policy."""
    try:
        pol     = iam.get_policy(PolicyArn=policy_arn)["Policy"]
        version = pol["DefaultVersionId"]
        doc     = iam.get_policy_version(
                      PolicyArn=policy_arn,
                      VersionId=version
                  )["PolicyVersion"]["Document"]
        return doc
    except ClientError as e:
        print(f"      [WARN] Could not fetch policy doc {policy_arn}: {e.response['Error']['Message']}")
        return None


# ─────────────────────────────────────────────
# USERS
# ─────────────────────────────────────────────

def collect_users(iam, account_name, cur, now) -> int:
    count = 0
    try:
        pager = iam.get_paginator("list_users")
        for page in pager.paginate():
            for user in page["Users"]:
                uid   = user["UserId"]
                uname = user["UserName"]

                # Last used / password last used
                last_used = user.get("PasswordLastUsed")

                # Access key last used
                try:
                    keys = iam.list_access_keys(UserName=uname)["AccessKeyMetadata"]
                    key_info = []
                    for k in keys:
                        lu = iam.get_access_key_last_used(AccessKeyId=k["AccessKeyId"])
                        lud = lu["AccessKeyLastUsed"].get("LastUsedDate")
                        key_info.append(f"{k['AccessKeyId'][:8]}…={fmt_dt(lud) or 'Never'}")
                    extra = "AccessKeys=" + (", ".join(key_info) if key_info else "None")
                except ClientError:
                    extra = ""

                cur.execute(UPSERT_PRINCIPAL, {
                    "principal_id":   uid,
                    "principal_name": uname,
                    "principal_type": "user",
                    "arn":            user.get("Arn"),
                    "account_name":   account_name,
                    "created_at":     fmt_dt(user.get("CreateDate")),
                    "last_used":      fmt_dt(last_used),
                    "path":           user.get("Path", "/"),
                    "extra":          extra,
                    "last_seen":      now,
                })

                # ── Attached managed policies ────────
                try:
                    ppager = iam.get_paginator("list_attached_user_policies")
                    for pp in ppager.paginate(UserName=uname):
                        for pol in pp["AttachedPolicies"]:
                            scope = "aws" if pol["PolicyArn"].startswith("arn:aws:iam::aws:") else "local"
                            cur.execute(UPSERT_POLICY, {
                                "principal_id":   uid,
                                "principal_name": uname,
                                "principal_type": "user",
                                "account_name":   account_name,
                                "policy_name":    pol["PolicyName"],
                                "policy_arn":     pol["PolicyArn"],
                                "policy_type":    "managed",
                                "scope":          scope,
                                "last_seen":      now,
                            })
                            doc = fetch_managed_policy_doc(iam, pol["PolicyArn"])
                            if doc:
                                cur.execute(DELETE_STATEMENTS, (uid, account_name, pol["PolicyName"]))
                                for row in parse_policy_document(
                                    doc, pol["PolicyName"], pol["PolicyArn"],
                                    "managed", uid, account_name, now
                                ):
                                    cur.execute(INSERT_STATEMENT, row)
                except ClientError as e:
                    print(f"      [WARN] Attached policies for {uname}: {e.response['Error']['Message']}")

                # ── Inline policies ──────────────────
                try:
                    ipager = iam.get_paginator("list_user_policies")
                    for ip in ipager.paginate(UserName=uname):
                        for pol_name in ip["PolicyNames"]:
                            doc = iam.get_user_policy(
                                      UserName=uname,
                                      PolicyName=pol_name
                                  )["PolicyDocument"]
                            cur.execute(UPSERT_POLICY, {
                                "principal_id":   uid,
                                "principal_name": uname,
                                "principal_type": "user",
                                "account_name":   account_name,
                                "policy_name":    pol_name,
                                "policy_arn":     None,
                                "policy_type":    "inline",
                                "scope":          "local",
                                "last_seen":      now,
                            })
                            cur.execute(DELETE_STATEMENTS, (uid, account_name, pol_name))
                            for row in parse_policy_document(
                                doc, pol_name, None,
                                "inline", uid, account_name, now
                            ):
                                cur.execute(INSERT_STATEMENT, row)
                except ClientError as e:
                    print(f"      [WARN] Inline policies for {uname}: {e.response['Error']['Message']}")

                # ── Group memberships (adds group policies to user view) ──
                try:
                    groups = iam.list_groups_for_user(UserName=uname)["Groups"]
                    for grp in groups:
                        gname = grp["GroupName"]
                        # Attached group policies
                        gppager = iam.get_paginator("list_attached_group_policies")
                        for gpp in gppager.paginate(GroupName=gname):
                            for pol in gpp["AttachedPolicies"]:
                                scope = "aws" if pol["PolicyArn"].startswith("arn:aws:iam::aws:") else "local"
                                cur.execute(UPSERT_POLICY, {
                                    "principal_id":   uid,
                                    "principal_name": uname,
                                    "principal_type": "user",
                                    "account_name":   account_name,
                                    "policy_name":    f"{pol['PolicyName']} (via group: {gname})",
                                    "policy_arn":     pol["PolicyArn"],
                                    "policy_type":    "managed",
                                    "scope":          scope,
                                    "last_seen":      now,
                                })
                except ClientError:
                    pass

                count += 1
    except ClientError as e:
        print(f"    [WARN] Users {account_name}: {e.response['Error']['Message']}")
    return count


# ─────────────────────────────────────────────
# ROLES
# ─────────────────────────────────────────────

def collect_roles(iam, account_name, cur, now) -> int:
    count = 0
    try:
        pager = iam.get_paginator("list_roles")
        for page in pager.paginate():
            for role in page["Roles"]:
                rid   = role["RoleId"]
                rname = role["RoleName"]

                # Last used
                last_used = None
                try:
                    lu = iam.get_role(RoleName=rname)["Role"].get("RoleLastUsed", {})
                    last_used = fmt_dt(lu.get("LastUsedDate"))
                except ClientError:
                    pass

                cur.execute(UPSERT_PRINCIPAL, {
                    "principal_id":   rid,
                    "principal_name": rname,
                    "principal_type": "role",
                    "arn":            role.get("Arn"),
                    "account_name":   account_name,
                    "created_at":     fmt_dt(role.get("CreateDate")),
                    "last_used":      last_used,
                    "path":           role.get("Path", "/"),
                    "extra":          "",
                    "last_seen":      now,
                })

                # ── Trust relationships ──────────────
                try:
                    trust_doc = role.get("AssumeRolePolicyDocument", {})
                    cur.execute(DELETE_TRUST, (rid, account_name))
                    for stmt in trust_doc.get("Statement", []):
                        principal = stmt.get("Principal", {})
                        actions   = json.dumps(to_list(stmt.get("Action", [])))
                        conds     = json.dumps(stmt.get("Condition", {})) if stmt.get("Condition") else None

                        if isinstance(principal, str):
                            principal = {"AWS": principal}

                        for ptype, parns in principal.items():
                            for parn in to_list(parns):
                                cur.execute(INSERT_TRUST, {
                                    "role_id":      rid,
                                    "role_name":    rname,
                                    "account_name": account_name,
                                    "trusted_type": ptype,
                                    "trusted_arn":  parn,
                                    "actions":      actions,
                                    "conditions":   conds,
                                    "last_seen":    now,
                                })
                except Exception as e:
                    print(f"      [WARN] Trust policy for {rname}: {e}")

                # ── Attached managed policies ────────
                try:
                    ppager = iam.get_paginator("list_attached_role_policies")
                    for pp in ppager.paginate(RoleName=rname):
                        for pol in pp["AttachedPolicies"]:
                            scope = "aws" if pol["PolicyArn"].startswith("arn:aws:iam::aws:") else "local"
                            cur.execute(UPSERT_POLICY, {
                                "principal_id":   rid,
                                "principal_name": rname,
                                "principal_type": "role",
                                "account_name":   account_name,
                                "policy_name":    pol["PolicyName"],
                                "policy_arn":     pol["PolicyArn"],
                                "policy_type":    "managed",
                                "scope":          scope,
                                "last_seen":      now,
                            })
                            doc = fetch_managed_policy_doc(iam, pol["PolicyArn"])
                            if doc:
                                cur.execute(DELETE_STATEMENTS, (rid, account_name, pol["PolicyName"]))
                                for row in parse_policy_document(
                                    doc, pol["PolicyName"], pol["PolicyArn"],
                                    "managed", rid, account_name, now
                                ):
                                    cur.execute(INSERT_STATEMENT, row)
                except ClientError as e:
                    print(f"      [WARN] Attached policies for {rname}: {e.response['Error']['Message']}")

                # ── Inline policies ──────────────────
                try:
                    ipager = iam.get_paginator("list_role_policies")
                    for ip in ipager.paginate(RoleName=rname):
                        for pol_name in ip["PolicyNames"]:
                            doc = iam.get_role_policy(
                                      RoleName=rname,
                                      PolicyName=pol_name
                                  )["PolicyDocument"]
                            cur.execute(UPSERT_POLICY, {
                                "principal_id":   rid,
                                "principal_name": rname,
                                "principal_type": "role",
                                "account_name":   account_name,
                                "policy_name":    pol_name,
                                "policy_arn":     None,
                                "policy_type":    "inline",
                                "scope":          "local",
                                "last_seen":      now,
                            })
                            cur.execute(DELETE_STATEMENTS, (rid, account_name, pol_name))
                            for row in parse_policy_document(
                                doc, pol_name, None,
                                "inline", rid, account_name, now
                            ):
                                cur.execute(INSERT_STATEMENT, row)
                except ClientError as e:
                    print(f"      [WARN] Inline policies for {rname}: {e.response['Error']['Message']}")

                count += 1
    except ClientError as e:
        print(f"    [WARN] Roles {account_name}: {e.response['Error']['Message']}")
    return count


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

def main():
    conn = mysql.connector.connect(**DB_CONFIG)
    cur  = conn.cursor()
    ensure_tables(cur, "iam")
    now  = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S")

    totals = {"users": 0, "roles": 0}

    for account in ACCOUNTS:
        print(f"\n{'─'*60}")
        print(f"🔍  Account: {account['name']}")
        print(f"{'─'*60}")

        try:
            session = get_session(account)
        except (NoCredentialsError, ClientError) as e:
            print(f"  [ERROR] Auth failed for {account['name']}: {e}")
            continue

        # IAM is global — one client per account, no region loop needed
        iam = session.client("iam", region_name="us-east-1")

        print("  → IAM Users")
        n = collect_users(iam, account["name"], cur, now)
        totals["users"] += n
        print(f"       {n} users upserted")

        print("  → IAM Roles")
        n = collect_roles(iam, account["name"], cur, now)
        totals["roles"] += n
        print(f"       {n} roles upserted")

        conn.commit()

    print(f"\n{'═'*60}")
    print("✅  Done")
    print(f"   Users: {totals['users']}")
    print(f"   Roles: {totals['roles']}")
    print(f"{'═'*60}")

    cur.close()
    conn.close()


if __name__ == "__main__":
    main()
