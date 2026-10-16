#!/usr/bin/env python3
"""
AWS IAM Identity Center (SSO) Collector
Collects users, groups, memberships, permission sets and account
assignments from the payer account's IAM Identity Center instance.

Requirements:
    pip install boto3 mysql-connector-python

IAM permissions needed on the payer account profile:
    sso:ListInstances
    sso:ListPermissionSets
    sso:DescribePermissionSet
    sso:ListAccountAssignments
    sso:ListAccountsForProvisionedPermissionSet
    sso:ListManagedPoliciesInPermissionSet
    sso:ListCustomerManagedPolicyReferencesInPermissionSet
    sso:GetInlinePolicyForPermissionSet
    identitystore:ListUsers
    identitystore:ListGroups
    identitystore:ListGroupMemberships
    organizations:ListAccounts  (to resolve account IDs to names)
"""

import json
import sys
import argparse
from datetime import datetime, UTC

import mysql.connector
from botocore.exceptions import ClientError, NoCredentialsError

import os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from config_loader import get_db_config, get_identity_center_config, get_session
from schema import ensure_tables

DB_CONFIG = get_db_config()
IC_CONFIG = get_identity_center_config()

# ─────────────────────────────────────────────
# SQL
# ─────────────────────────────────────────────
UPSERT_USER = """
INSERT INTO sso_users
    (user_id, username, display_name, email, account_name, identity_store_id, last_seen)
VALUES
    (%(user_id)s, %(username)s, %(display_name)s, %(email)s,
     %(account_name)s, %(identity_store_id)s, %(last_seen)s)
ON DUPLICATE KEY UPDATE
    username         = VALUES(username),
    display_name     = VALUES(display_name),
    email            = VALUES(email),
    last_seen        = VALUES(last_seen);
"""

UPSERT_GROUP = """
INSERT INTO sso_groups
    (group_id, group_name, description, account_name, identity_store_id, last_seen)
VALUES
    (%(group_id)s, %(group_name)s, %(description)s,
     %(account_name)s, %(identity_store_id)s, %(last_seen)s)
ON DUPLICATE KEY UPDATE
    group_name   = VALUES(group_name),
    description  = VALUES(description),
    last_seen    = VALUES(last_seen);
"""

UPSERT_MEMBERSHIP = """
INSERT INTO sso_group_memberships
    (user_id, username, group_id, group_name, account_name, last_seen)
VALUES
    (%(user_id)s, %(username)s, %(group_id)s, %(group_name)s,
     %(account_name)s, %(last_seen)s)
ON DUPLICATE KEY UPDATE
    username   = VALUES(username),
    group_name = VALUES(group_name),
    last_seen  = VALUES(last_seen);
"""

UPSERT_PS = """
INSERT INTO sso_permission_sets
    (permission_set_arn, name, description, session_duration,
     account_name, instance_arn, last_seen)
VALUES
    (%(permission_set_arn)s, %(name)s, %(description)s, %(session_duration)s,
     %(account_name)s, %(instance_arn)s, %(last_seen)s)
ON DUPLICATE KEY UPDATE
    name             = VALUES(name),
    description      = VALUES(description),
    session_duration = VALUES(session_duration),
    last_seen        = VALUES(last_seen);
"""

UPSERT_PS_POLICY = """
INSERT INTO sso_permission_set_policies
    (permission_set_arn, permission_set_name, policy_name, policy_arn,
     policy_type, policy_document, account_name, last_seen)
VALUES
    (%(permission_set_arn)s, %(permission_set_name)s, %(policy_name)s,
     %(policy_arn)s, %(policy_type)s, %(policy_document)s,
     %(account_name)s, %(last_seen)s)
ON DUPLICATE KEY UPDATE
    permission_set_name = VALUES(permission_set_name),
    policy_arn          = VALUES(policy_arn),
    policy_document     = VALUES(policy_document),
    last_seen           = VALUES(last_seen);
"""

UPSERT_ASSIGNMENT = """
INSERT INTO sso_account_assignments
    (instance_arn, permission_set_arn, permission_set_name,
     target_account_id, target_account_name, principal_type,
     principal_id, principal_name, account_name, last_seen)
VALUES
    (%(instance_arn)s, %(permission_set_arn)s, %(permission_set_name)s,
     %(target_account_id)s, %(target_account_name)s, %(principal_type)s,
     %(principal_id)s, %(principal_name)s, %(account_name)s, %(last_seen)s)
ON DUPLICATE KEY UPDATE
    permission_set_name = VALUES(permission_set_name),
    target_account_name = VALUES(target_account_name),
    principal_name      = VALUES(principal_name),
    last_seen           = VALUES(last_seen);
"""


# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────

def get_account_name_map(session) -> dict:
    """Return {account_id: account_name} from AWS Organizations."""
    mapping = {}
    try:
        org = session.client("organizations", region_name="us-west-2")
        pager = org.get_paginator("list_accounts")
        for page in pager.paginate():
            for acct in page["Accounts"]:
                mapping[acct["Id"]] = acct["Name"]
    except ClientError as e:
        print(f"  [WARN] Could not list org accounts: {e.response['Error']['Message']}")
    return mapping


def get_managed_policy_doc(iam, policy_arn: str) -> str | None:
    """Fetch and return a managed policy document as a JSON string."""
    try:
        pol     = iam.get_policy(PolicyArn=policy_arn)["Policy"]
        version = pol["DefaultVersionId"]
        doc     = iam.get_policy_version(
                      PolicyArn=policy_arn, VersionId=version
                  )["PolicyVersion"]["Document"]
        return json.dumps(doc, indent=2)
    except Exception:
        return None


# ─────────────────────────────────────────────
# USERS
# ─────────────────────────────────────────────

def collect_users(id_store, store_id, account_name, cur, now) -> int:
    count   = 0
    user_map = {}   # user_id → username (returned for membership lookups)
    try:
        pager = id_store.get_paginator("list_users")
        for page in pager.paginate(IdentityStoreId=store_id):
            for user in page["Users"]:
                uid      = user["UserId"]
                username = user.get("UserName", uid)
                email    = ""
                for e in user.get("Emails", []):
                    if e.get("Primary"):
                        email = e.get("Value", "")
                        break
                display = user.get("DisplayName") or \
                          f"{user.get('Name',{}).get('GivenName','')} {user.get('Name',{}).get('FamilyName','')}".strip()

                cur.execute(UPSERT_USER, {
                    "user_id":           uid,
                    "username":          username,
                    "display_name":      display,
                    "email":             email,
                    "account_name":      account_name,
                    "identity_store_id": store_id,
                    "last_seen":         now,
                })
                user_map[uid] = username
                count += 1
    except ClientError as e:
        print(f"  [WARN] Users: {e.response['Error']['Message']}")
    return count, user_map


# ─────────────────────────────────────────────
# GROUPS & MEMBERSHIPS
# ─────────────────────────────────────────────

def collect_groups(id_store, store_id, account_name, user_map, cur, now) -> int:
    count = 0
    try:
        pager = id_store.get_paginator("list_groups")
        for page in pager.paginate(IdentityStoreId=store_id):
            for grp in page["Groups"]:
                gid   = grp["GroupId"]
                gname = grp.get("DisplayName", gid)
                desc  = grp.get("Description", "")

                cur.execute(UPSERT_GROUP, {
                    "group_id":          gid,
                    "group_name":        gname,
                    "description":       desc,
                    "account_name":      account_name,
                    "identity_store_id": store_id,
                    "last_seen":         now,
                })

                # Group memberships
                try:
                    mpager = id_store.get_paginator("list_group_memberships")
                    for mp in mpager.paginate(IdentityStoreId=store_id, GroupId=gid):
                        for member in mp["GroupMemberships"]:
                            mid = member["MemberId"].get("UserId", "")
                            cur.execute(UPSERT_MEMBERSHIP, {
                                "user_id":      mid,
                                "username":     user_map.get(mid, mid),
                                "group_id":     gid,
                                "group_name":   gname,
                                "account_name": account_name,
                                "last_seen":    now,
                            })
                except ClientError:
                    pass

                count += 1
    except ClientError as e:
        print(f"  [WARN] Groups: {e.response['Error']['Message']}")
    return count


# ─────────────────────────────────────────────
# PERMISSION SETS
# ─────────────────────────────────────────────

def collect_permission_sets(sso, iam, instance_arn, account_name, cur, now) -> dict:
    """Collect all permission sets and their policies. Returns {arn: name} map."""
    ps_map = {}
    try:
        pager = sso.get_paginator("list_permission_sets")
        for page in pager.paginate(InstanceArn=instance_arn):
            for ps_arn in page["PermissionSets"]:
                try:
                    detail = sso.describe_permission_set(
                        InstanceArn=instance_arn,
                        PermissionSetArn=ps_arn
                    )["PermissionSet"]
                except ClientError:
                    continue

                ps_name = detail.get("Name", ps_arn.split("/")[-1])
                ps_map[ps_arn] = ps_name

                cur.execute(UPSERT_PS, {
                    "permission_set_arn": ps_arn,
                    "name":              ps_name,
                    "description":       detail.get("Description", ""),
                    "session_duration":  detail.get("SessionDuration", ""),
                    "account_name":      account_name,
                    "instance_arn":      instance_arn,
                    "last_seen":         now,
                })

                # ── AWS managed policies ─────────────
                try:
                    mp_pager = sso.get_paginator("list_managed_policies_in_permission_set")
                    for mp in mp_pager.paginate(InstanceArn=instance_arn, PermissionSetArn=ps_arn):
                        for pol in mp["AttachedManagedPolicies"]:
                            doc = get_managed_policy_doc(iam, pol["Arn"])
                            cur.execute(UPSERT_PS_POLICY, {
                                "permission_set_arn":  ps_arn,
                                "permission_set_name": ps_name,
                                "policy_name":         pol["Name"],
                                "policy_arn":          pol["Arn"],
                                "policy_type":         "managed",
                                "policy_document":     doc,
                                "account_name":        account_name,
                                "last_seen":           now,
                            })
                except ClientError:
                    pass

                # ── Customer managed policies ────────
                try:
                    cmp_pager = sso.get_paginator(
                        "list_customer_managed_policy_references_in_permission_set"
                    )
                    for cmp in cmp_pager.paginate(InstanceArn=instance_arn, PermissionSetArn=ps_arn):
                        for ref in cmp["CustomerManagedPolicyReferences"]:
                            cur.execute(UPSERT_PS_POLICY, {
                                "permission_set_arn":  ps_arn,
                                "permission_set_name": ps_name,
                                "policy_name":         ref["Name"],
                                "policy_arn":          None,
                                "policy_type":         "customer",
                                "policy_document":     None,
                                "account_name":        account_name,
                                "last_seen":           now,
                            })
                except ClientError:
                    pass

                # ── Inline policy ────────────────────
                try:
                    inline = sso.get_inline_policy_for_permission_set(
                        InstanceArn=instance_arn,
                        PermissionSetArn=ps_arn
                    )
                    doc = inline.get("InlinePolicy", "")
                    if doc:
                        cur.execute(UPSERT_PS_POLICY, {
                            "permission_set_arn":  ps_arn,
                            "permission_set_name": ps_name,
                            "policy_name":         f"{ps_name}-inline",
                            "policy_arn":          None,
                            "policy_type":         "inline",
                            "policy_document":     doc,
                            "account_name":        account_name,
                            "last_seen":           now,
                        })
                except ClientError:
                    pass

    except ClientError as e:
        print(f"  [WARN] Permission sets: {e.response['Error']['Message']}")

    return ps_map


# ─────────────────────────────────────────────
# ACCOUNT ASSIGNMENTS
# ─────────────────────────────────────────────

def collect_assignments(sso, id_store, store_id, instance_arn,
                        ps_map, user_map, account_map,
                        account_name, cur, now) -> int:
    count    = 0
    group_cache = {}

    # Build group name cache
    try:
        gpager = id_store.get_paginator("list_groups")
        for gp in gpager.paginate(IdentityStoreId=store_id):
            for g in gp["Groups"]:
                group_cache[g["GroupId"]] = g.get("DisplayName", g["GroupId"])
    except ClientError:
        pass

    try:
        for ps_arn, ps_name in ps_map.items():
            try:
                acct_pager = sso.get_paginator(
                    "list_accounts_for_provisioned_permission_set"
                )
                for ap in acct_pager.paginate(
                    InstanceArn=instance_arn,
                    PermissionSetArn=ps_arn
                ):
                    for acct_id in ap["AccountIds"]:
                        acct_name = account_map.get(acct_id, acct_id)
                        try:
                            assign_pager = sso.get_paginator("list_account_assignments")
                            for asgn in assign_pager.paginate(
                                InstanceArn=instance_arn,
                                AccountId=acct_id,
                                PermissionSetArn=ps_arn
                            ):
                                for a in asgn["AccountAssignments"]:
                                    pid   = a["PrincipalId"]
                                    ptype = a["PrincipalType"]

                                    if ptype == "USER":
                                        pname = user_map.get(pid, pid)
                                    else:
                                        pname = group_cache.get(pid, pid)

                                    cur.execute(UPSERT_ASSIGNMENT, {
                                        "instance_arn":        instance_arn,
                                        "permission_set_arn":  ps_arn,
                                        "permission_set_name": ps_name,
                                        "target_account_id":   acct_id,
                                        "target_account_name": acct_name,
                                        "principal_type":      ptype,
                                        "principal_id":        pid,
                                        "principal_name":      pname,
                                        "account_name":        account_name,
                                        "last_seen":           now,
                                    })
                                    count += 1
                        except ClientError:
                            pass
            except ClientError:
                pass
    except Exception as e:
        print(f"  [WARN] Assignments: {e}")

    return count


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

def main():
    if not IC_CONFIG:
        print("[ERROR] No [identity_center] section found in config.ini")
        sys.exit(1)

    parser = argparse.ArgumentParser(description="AWS IAM Identity Center Collector")
    parser.add_argument("--dry-run", action="store_true", help="Print config and exit")
    args = parser.parse_args()

    if args.dry_run:
        print(f"Identity Center config: {IC_CONFIG}")
        return

    conn = mysql.connector.connect(**DB_CONFIG)
    cur  = conn.cursor()
    ensure_tables(cur, "sso")
    now  = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S")

    instance_arn = IC_CONFIG["instance_arn"]
    store_id     = IC_CONFIG["identity_store_id"]
    acct_name    = "sso_management_account"

    print(f"\n{'─'*60}")
    print(f"🔍  IAM Identity Center — {acct_name}")
    print(f"    Instance : {instance_arn}")
    print(f"    Store ID : {store_id}")
    print(f"{'─'*60}")

    try:
        session = get_session(IC_CONFIG)
    except (NoCredentialsError, ClientError) as e:
        print(f"[ERROR] Auth failed: {e}")
        sys.exit(1)

    sso      = session.client("sso-admin",       region_name="us-west-2")
    id_store = session.client("identitystore",   region_name="us-west-2")
    iam      = session.client("iam",             region_name="us-west-2")

    # Account ID → Name map from Organizations
    print("  → Resolving account names from Organizations")
    account_map = get_account_name_map(session)
    print(f"       {len(account_map)} accounts found")

    print("  → Users")
    n, user_map = collect_users(id_store, store_id, acct_name, cur, now)
    print(f"       {n} users upserted")

    print("  → Groups & Memberships")
    n = collect_groups(id_store, store_id, acct_name, user_map, cur, now)
    print(f"       {n} groups upserted")

    print("  → Permission Sets & Policies")
    ps_map = collect_permission_sets(sso, iam, instance_arn, acct_name, cur, now)
    print(f"       {len(ps_map)} permission sets upserted")

    print("  → Account Assignments")
    n = collect_assignments(
        sso, id_store, store_id, instance_arn,
        ps_map, user_map, account_map,
        acct_name, cur, now
    )
    print(f"       {n} assignments upserted")

    conn.commit()

    print(f"\n{'═'*60}")
    print("✅  Identity Center sync complete")
    print(f"{'═'*60}")

    cur.close()
    conn.close()


if __name__ == "__main__":
    main()
