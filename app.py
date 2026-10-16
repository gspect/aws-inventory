#!/usr/bin/env python3
"""
AWS Inventory Search — Flask App
File: app.py
"""

from flask import Flask, render_template, request, session, jsonify
import mysql.connector
import json
import sys
import os
import subprocess
import threading
from datetime import datetime
from functools import wraps
from okta_auth import init_okta, okta_bp, login_required, AUTH_DISABLED

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)
from config_loader import get_db_config, get_accounts as _get_accounts

DB_CONFIG = get_db_config()

try:
    from schema import ensure_tables
    _c = mysql.connector.connect(**DB_CONFIG)
    ensure_tables(_c.cursor(), "sync")
    _c.close()
except Exception as _e:   # DB not created yet — run scripts/collect_inventory.py first
    print(f"WARNING: could not ensure sync_jobs table: {_e}", file=sys.stderr)


def api_login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not AUTH_DISABLED and "user" not in session:
            return jsonify({"error": "Authentication required"}), 401
        return f(*args, **kwargs)
    return decorated


app = Flask(__name__)
_secret = os.environ.get("FLASK_SECRET_KEY")
if not _secret:
    import secrets
    _secret = secrets.token_hex(32)
    print("WARNING: FLASK_SECRET_KEY is not set; using a random key. "
          "Sessions will not survive restarts or work across multiple workers.", file=sys.stderr)
app.secret_key = _secret
app.register_blueprint(okta_bp)
init_okta(app)

# Optional links shown in the UI. Leave unset to hide them.
PROJECT_URL    = os.environ.get("PROJECT_URL", "")      # e.g. https://github.com/<you>/aws-inventory

@app.context_processor
def inject_links():
    return dict(project_url=PROJECT_URL)

@app.context_processor
def inject_user():
    return {"current_user": session.get("user")}

@app.context_processor
def inject_stats():
    try:
        return dict(stats=get_stats())
    except Exception:
        return dict(stats={})

@app.template_filter('fromjson')
def fromjson_filter(s):
    try:
        return json.loads(s) if isinstance(s, str) else s
    except Exception:
        return {}

from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.middleware.dispatcher import DispatcherMiddleware
from werkzeug.wrappers import Response

app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)
app.wsgi_app = DispatcherMiddleware(
    Response("Not Found", status=404),
    {
        "/aws-inventory": app.wsgi_app,
    }
)


def get_db():
    return mysql.connector.connect(**DB_CONFIG)


# ─────────────────────────────────────────────
# TAG HELPERS
# ─────────────────────────────────────────────

def attach_tags(cur, rows: list, id_field: str = "aws_id") -> list:
    if not rows:
        return rows
    pairs = list({(r[id_field], r["account_name"]) for r in rows})
    placeholders = " OR ".join(
        "(aws_id = %s AND account_name = %s)" for _ in pairs
    )
    params = [val for pair in pairs for val in pair]
    cur.execute(f"""
        SELECT aws_id, account_name, tag_key, tag_value
        FROM aws_resource_tags
        WHERE {placeholders}
        ORDER BY aws_id, tag_key
    """, params)
    tag_map = {}
    for t in cur.fetchall():
        key = (t["aws_id"], t["account_name"])
        if key not in tag_map:
            tag_map[key] = []
        tag_map[key].append({"k": t["tag_key"], "v": t["tag_value"] or ""})
    for r in rows:
        r["tags"] = tag_map.get((r[id_field], r["account_name"]), [])
    return rows


def attach_sg_tags(cur, rows: list) -> list:
    if not rows:
        return rows
    pairs = list({(r["sg_id"], r["account_name"]) for r in rows})
    placeholders = " OR ".join(
        "(aws_id = %s AND account_name = %s)" for _ in pairs
    )
    params = [val for pair in pairs for val in pair]
    cur.execute(f"""
        SELECT aws_id, account_name, tag_key, tag_value
        FROM aws_sg_tags
        WHERE {placeholders}
        ORDER BY aws_id, tag_key
    """, params)
    tag_map = {}
    for t in cur.fetchall():
        key = (t["aws_id"], t["account_name"])
        if key not in tag_map:
            tag_map[key] = []
        tag_map[key].append({"k": t["tag_key"], "v": t["tag_value"] or ""})
    for r in rows:
        r["tags"] = tag_map.get((r["sg_id"], r["account_name"]), [])
    return rows


def attach_subnet_tags(cur, rows: list, id_field: str = "subnet_id") -> list:
    if not rows:
        return rows
    pairs = list({(r[id_field], r["account_name"]) for r in rows})
    placeholders = " OR ".join(
        "(aws_id = %s AND account_name = %s)" for _ in pairs
    )
    params = [val for pair in pairs for val in pair]
    cur.execute(f"""
        SELECT aws_id, account_name, tag_key, tag_value
        FROM aws_subnet_tags
        WHERE {placeholders}
        ORDER BY aws_id, tag_key
    """, params)
    tag_map = {}
    for t in cur.fetchall():
        key = (t["aws_id"], t["account_name"])
        if key not in tag_map:
            tag_map[key] = []
        tag_map[key].append({"k": t["tag_key"], "v": t["tag_value"] or ""})
    for r in rows:
        r["tags"] = tag_map.get((r[id_field], r["account_name"]), [])
    return rows


# ─────────────────────────────────────────────
# STATS
# ─────────────────────────────────────────────

def get_stats() -> dict:
    conn = get_db()
    cur  = conn.cursor(dictionary=True)
    stats = {}

    cur.execute("SELECT type, COUNT(*) AS cnt FROM aws_inventory_resources GROUP BY type")
    for row in cur.fetchall():
        stats[row["type"]] = row["cnt"]

    cur.execute("SELECT COUNT(*) AS cnt FROM aws_domains")
    stats["dns_records"] = cur.fetchone()["cnt"]

    cur.execute("SELECT COUNT(DISTINCT account_name) AS cnt FROM aws_inventory_resources")
    stats["accounts"] = cur.fetchone()["cnt"]

    cur.execute("SELECT MAX(last_seen) AS ts FROM aws_inventory_resources")
    row = cur.fetchone()
    stats["last_sync"] = str(row["ts"]) if row["ts"] else "Never"

    try:
        cur.execute("SELECT COUNT(DISTINCT sg_id) AS cnt FROM aws_security_groups")
        stats["security_groups"] = cur.fetchone()["cnt"]
        cur.execute("SELECT COUNT(*) AS cnt FROM aws_security_groups")
        stats["sg_rules"] = cur.fetchone()["cnt"]
    except Exception:
        stats.setdefault("security_groups", 0)
        stats.setdefault("sg_rules", 0)

    try:
        cur.execute("SELECT COUNT(*) AS cnt FROM aws_iam_principals WHERE principal_type='user'")
        stats["iam_users"] = cur.fetchone()["cnt"]
        cur.execute("SELECT COUNT(*) AS cnt FROM aws_iam_principals WHERE principal_type='role'")
        stats["iam_roles"] = cur.fetchone()["cnt"]
    except Exception:
        stats.setdefault("iam_users", 0)
        stats.setdefault("iam_roles", 0)

    # Network page stats
    try:
        cur.execute("SELECT COUNT(*) AS cnt FROM aws_subnets")
        stats["subnets"] = cur.fetchone()["cnt"]
        cur.execute("SELECT COUNT(DISTINCT route_table_id) AS cnt FROM aws_route_tables")
        stats["route_tables"] = cur.fetchone()["cnt"]
        cur.execute("SELECT COUNT(*) AS cnt FROM aws_nat_gateways")
        stats["nat_gws"] = cur.fetchone()["cnt"]
    except Exception:
        stats.setdefault("subnets", 0)
        stats.setdefault("route_tables", 0)
        stats.setdefault("nat_gws", 0)

    # SSO page stats
    try:
        cur.execute("SELECT COUNT(*) AS cnt FROM sso_users")
        stats["sso_users"] = cur.fetchone()["cnt"]
        cur.execute("SELECT COUNT(*) AS cnt FROM sso_groups")
        stats["sso_groups"] = cur.fetchone()["cnt"]
        cur.execute("SELECT COUNT(DISTINCT permission_set_arn) AS cnt FROM sso_permission_sets")
        stats["permission_sets"] = cur.fetchone()["cnt"]
    except Exception:
        stats.setdefault("sso_users", 0)
        stats.setdefault("sso_groups", 0)
        stats.setdefault("permission_sets", 0)

    # RDS page stats
    try:
        cur.execute("SELECT COUNT(*) AS cnt FROM aws_rds_clusters")
        stats["rds_clusters"] = cur.fetchone()["cnt"]
        cur.execute("SELECT COUNT(*) AS cnt FROM aws_rds_instances")
        stats["rds_instances"] = cur.fetchone()["cnt"]
    except Exception:
        stats.setdefault("rds_clusters", 0)
        stats.setdefault("rds_instances", 0)

    # Messaging page stats
    try:
        cur.execute("SELECT COUNT(*) AS cnt FROM aws_sqs_queues")
        stats["sqs_queues"] = cur.fetchone()["cnt"]
        cur.execute("SELECT COUNT(*) AS cnt FROM aws_sns_topics")
        stats["sns_topics"] = cur.fetchone()["cnt"]
        cur.execute("SELECT COUNT(*) AS cnt FROM aws_lambda_esms")
        stats["lambda_esms"] = cur.fetchone()["cnt"]
    except Exception:
        stats.setdefault("sqs_queues", 0)
        stats.setdefault("sns_topics", 0)
        stats.setdefault("lambda_esms", 0)

    # S3 page stats
    try:
        s3_stats = get_s3_stats()
        stats.update(s3_stats)
    except Exception:
        stats.setdefault("s3_buckets", 0)
        stats.setdefault("s3_total_gb", 0)

    # EFS page stats
    try:
        cur.execute("SELECT COUNT(*) AS cnt FROM aws_efs_filesystems")
        stats["efs_filesystems"] = cur.fetchone()["cnt"]
        cur.execute("SELECT COALESCE(SUM(size_bytes_total), 0) AS total FROM aws_efs_filesystems")
        stats["efs_total_gb"] = round(cur.fetchone()["total"] / 1_073_741_824, 1)
    except Exception:
        stats.setdefault("efs_filesystems", 0)
        stats.setdefault("efs_total_gb", 0)

    # ECS page stats
    try:
        cur.execute("SELECT COUNT(*) AS cnt FROM aws_ecs_clusters")
        stats["ecs_clusters"] = cur.fetchone()["cnt"]
        cur.execute("SELECT COUNT(*) AS cnt FROM aws_ecs_services")
        stats["ecs_services"] = cur.fetchone()["cnt"]
    except Exception:
        stats.setdefault("ecs_clusters", 0)
        stats.setdefault("ecs_services", 0)

    # EKS page stats
    try:
        cur.execute("SELECT COUNT(*) AS cnt FROM aws_eks_clusters")
        stats["eks_clusters"] = cur.fetchone()["cnt"]
        cur.execute("SELECT COUNT(*) AS cnt FROM aws_eks_nodegroups")
        stats["eks_nodegroups"] = cur.fetchone()["cnt"]
    except Exception:
        stats.setdefault("eks_clusters", 0)
        stats.setdefault("eks_nodegroups", 0)

    # CloudFront page stats
    try:
        cur.execute("SELECT COUNT(*) AS cnt FROM aws_cf_distributions")
        stats["cf_distributions"] = cur.fetchone()["cnt"]
        cur.execute("SELECT COUNT(*) AS cnt FROM aws_cf_origins")
        stats["cf_origins"] = cur.fetchone()["cnt"]
    except Exception:
        stats.setdefault("cf_distributions", 0)
        stats.setdefault("cf_origins", 0)

    # Lambda page stats
    try:
        cur.execute("SELECT COUNT(*) AS cnt FROM aws_lambda_functions")
        stats["lambda_functions"] = cur.fetchone()["cnt"]
        cur.execute("SELECT COUNT(DISTINCT runtime) AS cnt FROM aws_lambda_functions WHERE runtime IS NOT NULL")
        stats["lambda_runtimes"] = cur.fetchone()["cnt"]
    except Exception:
        stats.setdefault("lambda_functions", 0)
        stats.setdefault("lambda_runtimes", 0)


    cur.close()
    conn.close()
    return stats

# ─────────────────────────────────────────────
# RESOURCES & DNS
# ─────────────────────────────────────────────

def search_inventory(query: str) -> dict:
    term = f"%{query.strip()}%"
    results = {"resources": [], "domains": []}
    conn = get_db()
    cur  = conn.cursor(dictionary=True)

    cur.execute("""
        SELECT account_name, type, name, aws_id, ipadd, region, extra, last_seen
        FROM aws_inventory_resources
        WHERE name LIKE %s OR aws_id LIKE %s OR ipadd LIKE %s OR extra LIKE %s
        ORDER BY account_name, type, name
    """, (term, term, term, term))
    resources = cur.fetchall()
    results["resources"] = attach_tags(cur, resources)

    cur.execute("""
        SELECT account_name, hosted_zone_name, hosted_zone_id, record_name,
               record_type, record_alias_name, record_value, record_ttl, last_seen
        FROM aws_domains
        WHERE record_name LIKE %s OR record_value LIKE %s
           OR record_alias_name LIKE %s OR hosted_zone_name LIKE %s
           OR hosted_zone_id LIKE %s
        ORDER BY account_name, hosted_zone_name, record_name
    """, (term, term, term, term, term))
    results["domains"] = cur.fetchall()

    cur.close()
    conn.close()
    return results


@app.route("/")
@app.route("/aws-inventory/")
@app.route("/aws-inventory")
@login_required
def index():
    query   = ""
    results = None
    error   = None
    try:
        stats = get_stats()
    except Exception as e:
        stats = {}
        error = f"Database connection error: {e}"

    query = request.args.get("q", "").strip()
    if query:
        if len(query) < 2:
            error = "Please enter at least 2 characters."
        else:
            try:
                results = search_inventory(query)
            except Exception as e:
                error = f"Search error: {e}"

    return render_template("index.html", query=query, results=results, active_page="resources",
                           stats=stats, error=error,
                           sync_script="collect_inventory")


# ─────────────────────────────────────────────
# SECURITY GROUPS
# ─────────────────────────────────────────────

def search_security_groups(query: str) -> dict:
    term = f"%{query.strip()}%"
    results = {"groups": []}
    conn = get_db()
    cur  = conn.cursor(dictionary=True)

    cur.execute("""
        SELECT DISTINCT sg_id, sg_name, description, vpc_id, account_name, region
        FROM aws_security_groups
        WHERE sg_id LIKE %s OR sg_name LIKE %s
        ORDER BY account_name, sg_name
    """, (term, term))
    groups = cur.fetchall()

    cur.execute("""
        SELECT DISTINCT sg_id, sg_name, description, vpc_id, account_name, region
        FROM aws_security_groups
        WHERE target LIKE %s
        ORDER BY account_name, sg_name
    """, (term,))
    existing = {(r["sg_id"], r["account_name"]) for r in groups}
    for r in cur.fetchall():
        if (r["sg_id"], r["account_name"]) not in existing:
            groups.append(r)
            existing.add((r["sg_id"], r["account_name"]))

    results["groups"] = attach_sg_tags(cur, groups)
    cur.close()
    conn.close()
    return results


def get_sg_detail(sg_id: str, account_name: str) -> dict:
    conn = get_db()
    cur  = conn.cursor(dictionary=True)

    cur.execute("""
        SELECT sg_id, sg_name, description, vpc_id, account_name, region,
               direction, protocol, from_port, to_port,
               target, target_type, description_rule, last_seen
        FROM aws_security_groups
        WHERE sg_id = %s AND account_name = %s
        ORDER BY direction, protocol, from_port
    """, (sg_id, account_name))
    rules = cur.fetchall()

    cur.execute("""
        SELECT tag_key, tag_value FROM aws_sg_tags
        WHERE aws_id = %s AND account_name = %s
        ORDER BY tag_key
    """, (sg_id, account_name))
    tags = [{"k": t["tag_key"], "v": t["tag_value"] or ""} for t in cur.fetchall()]

    cur.execute("""
        SELECT name, aws_id, type, account_name, ipadd
        FROM aws_inventory_resources
        WHERE extra LIKE %s OR extra LIKE %s
    """, (f"%{sg_id}%", f"%{sg_id}%"))
    attachments = cur.fetchall()

    cur.close()
    conn.close()
    return {"rules": rules, "attachments": attachments, "tags": tags}


@app.route("/sg")
@app.route("/sg/")
@login_required
def sg_index():
    query         = request.args.get("q", "").strip()
    results       = None
    detail        = None
    multi_compare = None
    error         = None
    sg_id         = request.args.get("sg_id", "").strip()
    account       = request.args.get("account", "").strip()
    multi_param   = request.args.get("multi", "").strip()

    if multi_param:
        try:
            pairs = []
            for token in multi_param.split(","):
                token = token.strip()
                if ":" in token:
                    sid, acct = token.split(":", 1)
                    pairs.append((sid.strip(), acct.strip()))
                else:
                    pairs.append((token, None))

            if pairs:
                conn = get_db()
                cur  = conn.cursor(dictionary=True)

                sg_meta = {}
                for sid, acct in pairs:
                    if acct:
                        cur.execute(
                            "SELECT DISTINCT sg_id, sg_name, account_name, vpc_id, region "
                            "FROM aws_security_groups WHERE sg_id=%s AND account_name=%s LIMIT 1",
                            (sid, acct))
                    else:
                        cur.execute(
                            "SELECT DISTINCT sg_id, sg_name, account_name, vpc_id, region "
                            "FROM aws_security_groups WHERE sg_id=%s LIMIT 1",
                            (sid,))
                    row = cur.fetchone()
                    if row:
                        sg_meta[(row["sg_id"], row["account_name"])] = row

                if sg_meta:
                    conditions = " OR ".join(
                        "(sg_id = %s AND account_name = %s)" for _ in sg_meta)
                    params = [v for k in sg_meta for v in k]
                    sql = ("SELECT sg_id, account_name, direction, protocol, from_port, to_port,"
                           " target, target_type, description_rule FROM aws_security_groups"
                           " WHERE " + conditions +
                           " ORDER BY direction, protocol, from_port, target")
                    cur.execute(sql, params)
                    raw_rules = cur.fetchall()

                    rule_map  = {}
                    rule_srcs = {}
                    for r in raw_rules:
                        key = (r["direction"] or "", r["protocol"] or "",
                               r["from_port"], r["to_port"],
                               r["target"] or "", r["target_type"] or "")
                        if key not in rule_map:
                            rule_map[key]  = r
                            rule_srcs[key] = []
                        if r["sg_id"] not in rule_srcs[key]:
                            rule_srcs[key].append(r["sg_id"])

                    merged = []
                    for key, rule in rule_map.items():
                        sources = rule_srcs[key]
                        merged.append({
                            "direction":        rule["direction"],
                            "protocol":         rule["protocol"],
                            "from_port":        rule["from_port"],
                            "to_port":          rule["to_port"],
                            "target":           rule["target"],
                            "target_type":      rule["target_type"],
                            "description_rule": rule["description_rule"],
                            "sources":          sources,
                            "is_duplicate":     len(sources) > 1,
                        })
                    merged.sort(key=lambda r: (
                        0 if r["direction"] == "inbound" else 1,
                        r["protocol"] or "",
                        r["from_port"] if r["from_port"] is not None else -1,
                    ))

                    total_raw  = len(raw_rules)
                    unique     = len(merged)
                    duplicates = sum(1 for r in merged if r["is_duplicate"])

                    multi_compare = {
                        "sgs":   list(sg_meta.values()),
                        "rules": merged,
                        "stats": {"total_raw": total_raw,
                                  "unique": unique,
                                  "duplicates": duplicates},
                    }
                cur.close()
                conn.close()
        except Exception as e:
            error = f"Compare error: {e}"

    elif sg_id and account:
        detail = get_sg_detail(sg_id, account)
    elif query:
        if len(query) < 2:
            error = "Please enter at least 2 characters."
        else:
            try:
                results = search_security_groups(query)
            except Exception as e:
                error = f"Search error: {e}"

    return render_template("sg.html", query=query, results=results,
                           detail=detail, multi_compare=multi_compare,
                           error=error, active_page="sg",
                           sg_id=sg_id,
                           sync_script="collect_sg")



# ─────────────────────────────────────────────
# SECURITY GROUP COMPARE (multi-SG view)
# ─────────────────────────────────────────────

@app.route("/sg/search")
@api_login_required
def sg_search_api():
    q     = request.args.get("q", "").strip()
    limit = min(int(request.args.get("limit", 10)), 50)
    if len(q) < 2:
        return jsonify([])

    term = f"%{q}%"
    conn = get_db()
    cur  = conn.cursor(dictionary=True)
    cur.execute("""
        SELECT DISTINCT sg_id, sg_name, account_name, vpc_id, region
        FROM aws_security_groups
        WHERE sg_id   LIKE %s
           OR sg_name LIKE %s
        ORDER BY account_name, sg_name
        LIMIT %s
    """, (term, term, limit))
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify(rows)


@app.route("/sg/compare")
@api_login_required
def sg_compare_api():
    sgs_param = request.args.get("sgs", "").strip()
    if not sgs_param:
        return jsonify({"error": "sgs parameter is required"}), 400

    pairs = []
    for token in sgs_param.split(","):
        token = token.strip()
        if ":" in token:
            sg_id, acct = token.split(":", 1)
            pairs.append((sg_id.strip(), acct.strip()))
        else:
            pairs.append((token, None))

    if not pairs:
        return jsonify({"error": "No valid SG pairs parsed"}), 400

    conn = get_db()
    cur  = conn.cursor(dictionary=True)

    sg_meta = {}
    for sg_id, acct in pairs:
        if acct:
            cur.execute("""
                SELECT DISTINCT sg_id, sg_name, account_name, vpc_id, region
                FROM aws_security_groups
                WHERE sg_id = %s AND account_name = %s
                LIMIT 1
            """, (sg_id, acct))
        else:
            cur.execute("""
                SELECT DISTINCT sg_id, sg_name, account_name, vpc_id, region
                FROM aws_security_groups
                WHERE sg_id = %s
                LIMIT 1
            """, (sg_id,))
        row = cur.fetchone()
        if row:
            key = (row["sg_id"], row["account_name"])
            sg_meta[key] = row

    if not sg_meta:
        cur.close()
        conn.close()
        return jsonify({"error": "No matching security groups found"}), 404

    conditions = " OR ".join(
        "(sg_id = %s AND account_name = %s)" for _ in sg_meta
    )
    params = [val for k in sg_meta for val in k]
    cur.execute(f"""
        SELECT sg_id, account_name,
               direction, protocol, from_port, to_port,
               target, target_type, description_rule
        FROM aws_security_groups
        WHERE {conditions}
        ORDER BY direction, protocol, from_port, target
    """, params)
    raw_rules = cur.fetchall()

    cur.close()
    conn.close()

    rule_map   = {}
    rule_srcs  = {}

    for r in raw_rules:
        key = (
            r["direction"]   or "",
            r["protocol"]    or "",
            r["from_port"],
            r["to_port"],
            r["target"]      or "",
            r["target_type"] or "",
        )
        if key not in rule_map:
            rule_map[key]  = r
            rule_srcs[key] = []
        if r["sg_id"] not in rule_srcs[key]:
            rule_srcs[key].append(r["sg_id"])

    merged_rules = []
    for key, rule in rule_map.items():
        sources      = rule_srcs[key]
        is_duplicate = len(sources) > 1
        merged_rules.append({
            "direction":       rule["direction"],
            "protocol":        rule["protocol"],
            "from_port":       rule["from_port"],
            "to_port":         rule["to_port"],
            "target":          rule["target"],
            "target_type":     rule["target_type"],
            "description_rule": rule["description_rule"],
            "sources":         sources,
            "is_duplicate":    is_duplicate,
        })

    merged_rules.sort(key=lambda r: (
        0 if r["direction"] == "inbound" else 1,
        r["protocol"] or "",
        r["from_port"] if r["from_port"] is not None else -1,
    ))

    total_raw  = len(raw_rules)
    unique     = len(merged_rules)
    duplicates = sum(1 for r in merged_rules if r["is_duplicate"])

    return jsonify({
        "sgs":   list(sg_meta.values()),
        "rules": merged_rules,
        "stats": {
            "total_raw":  total_raw,
            "unique":     unique,
            "duplicates": duplicates,
        },
    })

# ─────────────────────────────────────────────
# IAM
# ─────────────────────────────────────────────

def search_iam(query: str) -> dict:
    term = f"%{query.strip()}%"
    conn = get_db()
    cur  = conn.cursor(dictionary=True)
    cur.execute("""
        SELECT principal_id, principal_name, principal_type,
               arn, account_name, created_at, last_used, extra
        FROM aws_iam_principals
        WHERE principal_name LIKE %s OR arn LIKE %s
           OR principal_id LIKE %s OR account_name LIKE %s
        ORDER BY account_name, principal_type, principal_name
    """, (term, term, term, term))
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return {
        "users": [r for r in rows if r["principal_type"] == "user"],
        "roles": [r for r in rows if r["principal_type"] == "role"],
    }


def get_iam_detail(principal_id: str, account_name: str) -> dict:
    conn = get_db()
    cur  = conn.cursor(dictionary=True)

    cur.execute("""
        SELECT * FROM aws_iam_principals
        WHERE principal_id = %s AND account_name = %s
    """, (principal_id, account_name))
    principal = cur.fetchone()

    cur.execute("""
        SELECT policy_name, policy_arn, policy_type, scope
        FROM aws_iam_policies
        WHERE principal_id = %s AND account_name = %s
        ORDER BY policy_type, policy_name
    """, (principal_id, account_name))
    policies = cur.fetchall()

    cur.execute("""
        SELECT policy_name, policy_arn, policy_type, effect,
               actions, resources, conditions, sid
        FROM aws_iam_policy_statements
        WHERE principal_id = %s AND account_name = %s
        ORDER BY policy_name, effect
    """, (principal_id, account_name))
    statements = cur.fetchall()
    stmt_map = {}
    for s in statements:
        key = s["policy_name"]
        if key not in stmt_map:
            stmt_map[key] = []
        try:
            s["actions"]    = json.loads(s["actions"]    or "[]")
            s["resources"]  = json.loads(s["resources"]  or "[]")
            s["conditions"] = json.loads(s["conditions"] or "{}")
        except Exception:
            pass
        stmt_map[key].append(s)

    cur.execute("""
        SELECT trusted_type, trusted_arn, actions, conditions
        FROM aws_iam_trust_relationships
        WHERE role_id = %s AND account_name = %s
    """, (principal_id, account_name))
    trusts = cur.fetchall()

    ec2_associations = []
    if principal and principal.get("principal_type") == "role":
        rname = principal.get("principal_name", "")
        cur.execute("""
            SELECT name, aws_id, type, account_name, ipadd, region
            FROM aws_inventory_resources WHERE extra LIKE %s
        """, (f"%{rname}%",))
        ec2_associations = cur.fetchall()

    cur.close()
    conn.close()
    return {"principal": principal, "policies": policies, "stmt_map": stmt_map,
            "trusts": trusts, "ec2_associations": ec2_associations}


@app.route("/iam")
@app.route("/iam/")
@login_required
def iam_index():
    query   = request.args.get("q", "").strip()
    results = None
    detail  = None
    error   = None
    pid     = request.args.get("principal_id", "").strip()
    account = request.args.get("account", "").strip()

    if pid and account:
        detail = get_iam_detail(pid, account)
    elif query:
        if len(query) < 2:
            error = "Please enter at least 2 characters."
        else:
            try:
                results = search_iam(query)
            except Exception as e:
                error = f"Search error: {e}"

    return render_template("iam.html", query=query, results=results,
                           detail=detail, pid=pid, account=account, error=error,
                           active_page="iam", sync_script="collect_iam",
                           sync_show_account_dropdown=True)


# ─────────────────────────────────────────────
# NETWORK
# ─────────────────────────────────────────────

def _group_routes(rows: list) -> list:
    seen, order = {}, []
    for r in rows:
        key = (r["route_table_id"], r["account_name"])
        if key not in seen:
            seen[key] = {k: r[k] for k in
                         ("route_table_id","name","vpc_id","associated_subnets",
                          "main","account_name","region","last_seen")}
            seen[key]["routes"] = []
            order.append(key)
        if r["destination"]:
            seen[key]["routes"].append({
                "destination": r["destination"],
                "target":      r["target"],
                "target_type": r["target_type"],
                "state":       r["state"],
            })
    return [seen[k] for k in order]


def _group_nacls(rows: list) -> list:
    seen, order = {}, []
    for r in rows:
        key = (r["nacl_id"], r["account_name"])
        if key not in seen:
            seen[key] = {k: r[k] for k in
                         ("nacl_id","name","vpc_id","associated_subnets",
                          "is_default","account_name","region","last_seen")}
            seen[key]["inbound"]  = []
            seen[key]["outbound"] = []
            order.append(key)
        if r["rule_number"] is not None:
            rule = {k: r[k] for k in
                    ("rule_number","protocol","from_port","to_port","cidr_block","action")}
            seen[key]["inbound" if r["direction"] == "inbound" else "outbound"].append(rule)
    return [seen[k] for k in order]


def search_network(query: str) -> dict:
    term = f"%{query.strip()}%"
    conn = get_db()
    cur  = conn.cursor(dictionary=True)
    results = {
        "subnets": [], "routes": [], "nacls": [],
        "nat_gws": [], "igws": [], "peering": [], "tgws": [],
    }

    cur.execute("""
        SELECT subnet_id, name, vpc_id, cidr_block, availability_zone,
               available_ips, state, map_public_ip, default_for_az,
               account_name, region, last_seen
        FROM aws_subnets
        WHERE subnet_id LIKE %s OR name LIKE %s OR vpc_id LIKE %s
           OR cidr_block LIKE %s OR availability_zone LIKE %s
        ORDER BY account_name, region, name
    """, (term,)*5)
    results["subnets"] = attach_subnet_tags(cur, cur.fetchall())

    cur.execute("""
        SELECT route_table_id, name, vpc_id, associated_subnets, main,
               destination, target, target_type, state,
               account_name, region, last_seen
        FROM aws_route_tables
        WHERE route_table_id LIKE %s OR name LIKE %s OR vpc_id LIKE %s
           OR destination LIKE %s OR target LIKE %s
           OR associated_subnets LIKE %s
        ORDER BY account_name, region, route_table_id, destination
    """, (term,)*6)
    results["routes"] = _group_routes(cur.fetchall())

    cur.execute("""
        SELECT nacl_id, name, vpc_id, associated_subnets, is_default,
               rule_number, direction, protocol, from_port, to_port,
               cidr_block, action, account_name, region, last_seen
        FROM aws_network_acls
        WHERE nacl_id LIKE %s OR name LIKE %s OR vpc_id LIKE %s
           OR cidr_block LIKE %s OR associated_subnets LIKE %s
        ORDER BY account_name, region, nacl_id, direction, rule_number
    """, (term,)*5)
    results["nacls"] = _group_nacls(cur.fetchall())

    cur.execute("""
        SELECT nat_gw_id, name, vpc_id, subnet_id, state, type,
               public_ip, private_ip, account_name, region, last_seen
        FROM aws_nat_gateways
        WHERE nat_gw_id LIKE %s OR name LIKE %s OR vpc_id LIKE %s
           OR subnet_id LIKE %s OR public_ip LIKE %s OR private_ip LIKE %s
        ORDER BY account_name, region, name
    """, (term,)*6)
    results["nat_gws"] = cur.fetchall()

    cur.execute("""
        SELECT igw_id, name, vpc_id, state, account_name, region, last_seen
        FROM aws_internet_gateways
        WHERE igw_id LIKE %s OR name LIKE %s OR vpc_id LIKE %s
        ORDER BY account_name, region, name
    """, (term,)*3)
    results["igws"] = cur.fetchall()

    cur.execute("""
        SELECT peering_id, name, status,
               requester_vpc_id, requester_cidr, requester_account, requester_region,
               accepter_vpc_id,  accepter_cidr,  accepter_account,  accepter_region,
               account_name, region, last_seen
        FROM aws_vpc_peering
        WHERE peering_id LIKE %s OR name LIKE %s
           OR requester_vpc_id LIKE %s OR requester_cidr LIKE %s
           OR accepter_vpc_id  LIKE %s OR accepter_cidr  LIKE %s
        ORDER BY account_name, region, name
    """, (term,)*6)
    results["peering"] = cur.fetchall()

    cur.execute("""
        SELECT tgw_id, name, description, state, account_name, region, last_seen
        FROM aws_transit_gateways
        WHERE tgw_id LIKE %s OR name LIKE %s OR description LIKE %s
        ORDER BY account_name, region, name
    """, (term,)*3)
    tgws = cur.fetchall()
    for tgw in tgws:
        cur.execute("""
            SELECT attachment_id, resource_type, resource_id,
                   resource_account, state
            FROM aws_tgw_attachments
            WHERE tgw_id = %s AND account_name = %s
            ORDER BY resource_type, resource_id
        """, (tgw["tgw_id"], tgw["account_name"]))
        tgw["attachments"] = cur.fetchall()
    results["tgws"] = tgws

    cur.close()
    conn.close()
    return results


@app.route("/network")
@app.route("/network/")
@login_required
def network_index():
    query   = request.args.get("q", "").strip()
    results = None
    error   = None
    tab     = request.args.get("tab", "subnets")

    if query:
        if len(query) < 2:
            error = "Please enter at least 2 characters."
        else:
            try:
                results = search_network(query)
                tab_order = ["subnets", "routes", "nacls", "nat_gws", "igws", "peering", "tgws"]
                if results:
                    for t in tab_order:
                        if results.get(t):
                            tab = t
                            break
            except Exception as e:
                error = f"Search error: {e}"

    return render_template("network.html", query=query, results=results,
                           error=error, tab=tab, active_page="network",
                           sync_script="collect_network")


# ─────────────────────────────────────────────
# IAM IDENTITY CENTER (SSO)
# ─────────────────────────────────────────────

def search_sso(query: str) -> dict:
    term    = f"%{query.strip()}%"
    results = {"users": [], "groups": []}
    conn    = get_db()
    cur     = conn.cursor(dictionary=True)

    cur.execute("""
        SELECT u.user_id, u.username, u.display_name, u.email, u.account_name,
               GROUP_CONCAT(DISTINCT m.group_name ORDER BY m.group_name SEPARATOR ', ') AS `groups`
        FROM sso_users u
        LEFT JOIN sso_group_memberships m ON u.user_id = m.user_id
        WHERE u.username LIKE %s OR u.display_name LIKE %s OR u.email LIKE %s
        GROUP BY u.user_id, u.username, u.display_name, u.email, u.account_name
        ORDER BY u.username
    """, (term, term, term))
    results["users"] = cur.fetchall()

    cur.execute("""
        SELECT g.group_id, g.group_name, g.description, g.account_name,
               COUNT(DISTINCT m.user_id) AS member_count
        FROM sso_groups g
        LEFT JOIN sso_group_memberships m ON g.group_id = m.group_id
        WHERE g.group_name LIKE %s OR g.description LIKE %s
        GROUP BY g.group_id, g.group_name, g.description, g.account_name
        ORDER BY g.group_name
    """, (term, term))
    results["groups"] = cur.fetchall()

    cur.close()
    conn.close()
    return results


def get_sso_user_detail(user_id: str) -> dict:
    conn = get_db()
    cur  = conn.cursor(dictionary=True)

    cur.execute("SELECT * FROM sso_users WHERE user_id = %s LIMIT 1", (user_id,))
    user = cur.fetchone()

    cur.execute("""
        SELECT group_id, group_name FROM sso_group_memberships
        WHERE user_id = %s ORDER BY group_name
    """, (user_id,))
    groups    = cur.fetchall()
    group_ids = [g["group_id"] for g in groups]

    cur.execute("""
        SELECT a.target_account_id, a.target_account_name,
               a.permission_set_name, a.permission_set_arn,
               a.principal_type, 'direct' AS assignment_source
        FROM sso_account_assignments a
        WHERE a.principal_id = %s AND a.principal_type = 'USER'
        ORDER BY a.target_account_name, a.permission_set_name
    """, (user_id,))
    direct_assignments = cur.fetchall()

    group_assignments = []
    if group_ids:
        fmt = ",".join(["%s"] * len(group_ids))
        cur.execute(f"""
            SELECT a.target_account_id, a.target_account_name,
                   a.permission_set_name, a.permission_set_arn,
                   a.principal_type, a.principal_name AS assignment_source
            FROM sso_account_assignments a
            WHERE a.principal_id IN ({fmt}) AND a.principal_type = 'GROUP'
            ORDER BY a.target_account_name, a.permission_set_name
        """, group_ids)
        group_assignments = cur.fetchall()

    all_assignments = {}
    for a in direct_assignments + group_assignments:
        key = (a["target_account_id"], a["permission_set_arn"])
        if key not in all_assignments:
            all_assignments[key] = a

    ps_arns     = list({a["permission_set_arn"] for a in all_assignments.values()})
    ps_policies = {}
    if ps_arns:
        fmt = ",".join(["%s"] * len(ps_arns))
        cur.execute(f"""
            SELECT permission_set_arn, permission_set_name,
                   policy_name, policy_arn, policy_type, policy_document
            FROM sso_permission_set_policies
            WHERE permission_set_arn IN ({fmt})
            ORDER BY permission_set_name, policy_name
        """, ps_arns)
        for row in cur.fetchall():
            k = row["permission_set_arn"]
            if k not in ps_policies:
                ps_policies[k] = []
            ps_policies[k].append(row)

    cur.close()
    conn.close()
    return {
        "user":        user,
        "groups":      groups,
        "assignments": list(all_assignments.values()),
        "ps_policies": ps_policies,
    }


def get_sso_group_detail(group_id: str) -> dict:
    conn = get_db()
    cur  = conn.cursor(dictionary=True)

    cur.execute("SELECT * FROM sso_groups WHERE group_id = %s LIMIT 1", (group_id,))
    group = cur.fetchone()

    cur.execute("""
        SELECT user_id, username FROM sso_group_memberships
        WHERE group_id = %s ORDER BY username
    """, (group_id,))
    members = cur.fetchall()

    cur.execute("""
        SELECT target_account_id, target_account_name,
               permission_set_name, permission_set_arn
        FROM sso_account_assignments
        WHERE principal_id = %s AND principal_type = 'GROUP'
        ORDER BY target_account_name, permission_set_name
    """, (group_id,))
    assignments = cur.fetchall()

    cur.close()
    conn.close()
    return {"group": group, "members": members, "assignments": assignments}


@app.route("/sso")
@app.route("/sso/")
@login_required
def sso_index():
    query   = request.args.get("q", "").strip()
    results = None
    error   = None
    detail  = None
    uid     = request.args.get("user_id", "").strip()
    gid     = request.args.get("group_id", "").strip()

    if uid:
        detail = {"type": "user", "data": get_sso_user_detail(uid)}
    elif gid:
        detail = {"type": "group", "data": get_sso_group_detail(gid)}
    elif query:
        if len(query) < 2:
            error = "Please enter at least 2 characters."
        else:
            try:
                results = search_sso(query)
            except Exception as e:
                error = f"Search error: {e}"

    return render_template("sso.html", query=query, results=results,
                           detail=detail, error=error, active_page="sso",
                           sync_script="collect_sso")


# ─────────────────────────────────────────────
# RDS / DATABASES
# ─────────────────────────────────────────────

@app.route("/rds")
@app.route("/rds/")
@login_required
def rds_index():
    q           = request.args.get("q", "").strip()
    tab         = request.args.get("tab", "clusters")
    cluster_id  = request.args.get("cluster_id", "").strip()
    instance_id = request.args.get("instance_id", "").strip()
    account     = request.args.get("account", "").strip()

    conn = get_db()
    cur  = conn.cursor(dictionary=True)

    if cluster_id and account:
        cur.execute("""
            SELECT * FROM aws_rds_clusters
            WHERE cluster_id = %s AND account_name = %s LIMIT 1
        """, (cluster_id, account))
        cluster = cur.fetchone()
        if cluster:
            cur.execute("""
                SELECT tag_key, tag_value FROM aws_rds_tags
                WHERE resource_id = %s AND account_name = %s
            """, (cluster_id, account))
            cluster["tags"] = [{"k": r["tag_key"], "v": r["tag_value"] or ""}
                                for r in cur.fetchall()]
        cur.close(); conn.close()
        return render_template("rds.html", view="cluster_detail", cluster=cluster,
                               query=q, active_tab="clusters", active_page="rds",
                               sync_script="collect_rds")

    if instance_id and account:
        cur.execute("""
            SELECT * FROM aws_rds_instances
            WHERE instance_id = %s AND account_name = %s LIMIT 1
        """, (instance_id, account))
        instance = cur.fetchone()
        if instance:
            cur.execute("""
                SELECT tag_key, tag_value FROM aws_rds_tags
                WHERE resource_id = %s AND account_name = %s
            """, (instance_id, account))
            instance["tags"] = [{"k": r["tag_key"], "v": r["tag_value"] or ""}
                                 for r in cur.fetchall()]
        cur.close(); conn.close()
        return render_template("rds.html", view="instance_detail", instance=instance,
                               query=q, active_tab="instances", active_page="rds",
                               sync_script="collect_rds")

    like = f"%{q}%" if q else "%"

    cur.execute("""
        SELECT * FROM aws_rds_clusters
        WHERE cluster_id      LIKE %s OR endpoint         LIKE %s
           OR reader_endpoint LIKE %s OR engine           LIKE %s
           OR engine_version  LIKE %s OR vpc_id           LIKE %s
           OR subnet_group    LIKE %s OR account_name     LIKE %s
           OR status          LIKE %s
        ORDER BY account_name, cluster_id
        LIMIT 200
    """, (like,)*9)
    clusters = cur.fetchall()

    cur.execute("""
        SELECT * FROM aws_rds_instances
        WHERE instance_id    LIKE %s OR endpoint       LIKE %s
           OR engine         LIKE %s OR engine_version LIKE %s
           OR instance_class LIKE %s OR vpc_id         LIKE %s
           OR subnet_group   LIKE %s OR cluster_id     LIKE %s
           OR account_name   LIKE %s OR status         LIKE %s
        ORDER BY account_name, instance_id
        LIMIT 200
    """, (like,)*10)
    instances = cur.fetchall()

    cur.close(); conn.close()
    return render_template("rds.html", view="list",
                           clusters=clusters, instances=instances,
                           query=q, active_tab=tab, active_page="rds",
                           sync_script="collect_rds")


# ─────────────────────────────────────────────
# MESSAGING (SQS / SNS / Lambda ESMs)
# ─────────────────────────────────────────────

def search_sqs(query: str) -> list:
    term = f"%{query.strip()}%"
    conn = get_db()
    cur  = conn.cursor(dictionary=True)
    cur.execute("""
        SELECT queue_name, queue_url, queue_arn, queue_type,
               approx_messages, approx_not_visible, approx_delayed,
               visibility_timeout, retention_seconds, delay_seconds,
               dlq_arn, dlq_max_receives, kms_key_id,
               account_name, region, last_seen
        FROM aws_sqs_queues
        WHERE queue_name LIKE %s OR queue_arn LIKE %s
           OR account_name LIKE %s OR dlq_arn LIKE %s
        ORDER BY account_name, region, queue_name
        LIMIT 300
    """, (term, term, term, term))
    rows = cur.fetchall()
    cur.close(); conn.close()
    return rows


def search_sns(query: str) -> list:
    term = f"%{query.strip()}%"
    conn = get_db()
    cur  = conn.cursor(dictionary=True)
    cur.execute("""
        SELECT topic_arn, topic_name, display_name,
               subscriptions_confirmed, subscriptions_pending,
               fifo_topic, kms_key_id, account_name, region, last_seen
        FROM aws_sns_topics
        WHERE topic_name LIKE %s OR topic_arn LIKE %s
           OR display_name LIKE %s OR account_name LIKE %s
        ORDER BY account_name, region, topic_name
        LIMIT 300
    """, (term, term, term, term))
    rows = cur.fetchall()
    cur.close(); conn.close()
    return rows


def search_lambda_esms(query: str) -> list:
    term = f"%{query.strip()}%"
    conn = get_db()
    cur  = conn.cursor(dictionary=True)
    cur.execute("""
        SELECT esm_uuid, function_arn, function_name, event_source_arn,
               event_source_type, state, batch_size, max_batching_window,
               bisect_on_error, max_concurrency, starting_position,
               last_modified, account_name, region, last_seen
        FROM aws_lambda_esms
        WHERE function_name LIKE %s OR function_arn LIKE %s
           OR event_source_arn LIKE %s OR account_name LIKE %s
        ORDER BY account_name, region, function_name
        LIMIT 300
    """, (term, term, term, term))
    rows = cur.fetchall()
    cur.close(); conn.close()
    return rows


def get_queue_detail(queue_arn: str, account_name: str) -> dict:
    conn = get_db()
    cur  = conn.cursor(dictionary=True)

    cur.execute("""
        SELECT * FROM aws_sqs_queues
        WHERE queue_arn = %s AND account_name = %s LIMIT 1
    """, (queue_arn, account_name))
    queue = cur.fetchone()

    if not queue:
        cur.close(); conn.close()
        return {}

    cur.execute("""
        SELECT function_arn, function_name, state, batch_size,
               max_batching_window, bisect_on_error, max_concurrency,
               esm_uuid, account_name, region
        FROM aws_lambda_esms
        WHERE event_source_arn = %s
        ORDER BY function_name
    """, (queue_arn,))
    consumers = cur.fetchall()

    cur.execute("""
        SELECT t.topic_name, t.topic_arn, s.subscription_arn, s.account_name, s.region
        FROM aws_sns_subscriptions s
        JOIN aws_sns_topics t ON s.topic_arn = t.topic_arn
        WHERE s.endpoint = %s AND s.protocol = 'sqs'
        ORDER BY t.topic_name
    """, (queue_arn,))
    sns_sources = cur.fetchall()

    cur.execute("""
        SELECT queue_name, queue_arn, account_name, region
        FROM aws_sqs_queues
        WHERE dlq_arn = %s
        ORDER BY queue_name
    """, (queue_arn,))
    dlq_sources = cur.fetchall()

    cur.execute("""
        SELECT tag_key, tag_value FROM aws_sqs_tags
        WHERE queue_arn = %s AND account_name = %s ORDER BY tag_key
    """, (queue_arn, account_name))
    tags = [{"k": r["tag_key"], "v": r["tag_value"] or ""} for r in cur.fetchall()]
    queue["tags"] = tags

    dlq_name = None
    if queue.get("dlq_arn"):
        cur.execute("""
            SELECT queue_name FROM aws_sqs_queues WHERE queue_arn = %s LIMIT 1
        """, (queue["dlq_arn"],))
        dlq_row = cur.fetchone()
        if dlq_row:
            dlq_name = dlq_row["queue_name"]

    cur.close(); conn.close()
    return {
        "queue":       queue,
        "consumers":   consumers,
        "sns_sources": sns_sources,
        "dlq_sources": dlq_sources,
        "dlq_name":    dlq_name,
    }


def get_topic_detail(topic_arn: str, account_name: str) -> dict:
    conn = get_db()
    cur  = conn.cursor(dictionary=True)

    cur.execute("""
        SELECT * FROM aws_sns_topics
        WHERE topic_arn = %s AND account_name = %s LIMIT 1
    """, (topic_arn, account_name))
    topic = cur.fetchone()

    if not topic:
        cur.close(); conn.close()
        return {}

    cur.execute("""
        SELECT subscription_arn, protocol, endpoint, endpoint_name,
               account_name, region
        FROM aws_sns_subscriptions
        WHERE topic_arn = %s
        ORDER BY protocol, endpoint_name
    """, (topic_arn,))
    subscriptions = cur.fetchall()

    cur.execute("""
        SELECT tag_key, tag_value FROM aws_sns_tags
        WHERE topic_arn = %s AND account_name = %s ORDER BY tag_key
    """, (topic_arn, account_name))
    tags = [{"k": r["tag_key"], "v": r["tag_value"] or ""} for r in cur.fetchall()]
    topic["tags"] = tags

    cur.close(); conn.close()
    return {"topic": topic, "subscriptions": subscriptions}


def get_dlq_summary() -> list:
    conn = get_db()
    cur  = conn.cursor(dictionary=True)
    cur.execute("""
        SELECT
            src.queue_name         AS src_name,
            src.queue_arn          AS src_arn,
            src.approx_messages    AS src_depth,
            src.approx_not_visible AS src_inflight,
            src.dlq_max_receives   AS max_receives,
            src.account_name,
            src.region,
            dlq.queue_name         AS dlq_name,
            dlq.queue_arn          AS dlq_arn,
            dlq.approx_messages    AS dlq_depth
        FROM aws_sqs_queues src
        LEFT JOIN aws_sqs_queues dlq ON src.dlq_arn = dlq.queue_arn
        WHERE src.dlq_arn IS NOT NULL AND src.dlq_arn != ''
        ORDER BY dlq.approx_messages DESC, src.account_name, src.queue_name
    """)
    rows = cur.fetchall()
    cur.close(); conn.close()
    return rows


@app.route("/messaging")
@app.route("/messaging/")
@login_required
def messaging_index():
    tab       = request.args.get("tab", "queues")
    q         = request.args.get("q", "").strip()
    queue_arn = request.args.get("queue_arn", "").strip()
    topic_arn = request.args.get("topic_arn", "").strip()
    account   = request.args.get("account", "").strip()
    error     = None

    if queue_arn and account:
        detail = get_queue_detail(queue_arn, account)
        return render_template("messaging.html", view="queue_detail",
                               detail=detail, query=q, active_tab="queues",
                               active_page="messaging",
                               sync_script="collect_messaging")

    if topic_arn and account:
        detail = get_topic_detail(topic_arn, account)
        return render_template("messaging.html", view="topic_detail",
                               detail=detail, query=q, active_tab="topics",
                               active_page="messaging",
                               sync_script="collect_messaging")

    like = f"%{q}%" if q else "%"

    conn = get_db()
    cur  = conn.cursor(dictionary=True)

    try:
        cur.execute("""
            SELECT queue_name, queue_url, queue_arn, queue_type,
                   approx_messages, approx_not_visible, approx_delayed,
                   visibility_timeout, retention_seconds, delay_seconds,
                   dlq_arn, dlq_max_receives, kms_key_id,
                   account_name, region, last_seen
            FROM aws_sqs_queues
            WHERE queue_name LIKE %s OR queue_arn LIKE %s
               OR account_name LIKE %s OR dlq_arn LIKE %s
            ORDER BY account_name, region, queue_name
            LIMIT 300
        """, (like, like, like, like))
        queues = cur.fetchall()
    except Exception as e:
        queues = []
        error  = f"SQS query error: {e}"

    try:
        cur.execute("""
            SELECT topic_arn, topic_name, display_name,
                   subscriptions_confirmed, subscriptions_pending,
                   fifo_topic, kms_key_id, account_name, region, last_seen
            FROM aws_sns_topics
            WHERE topic_name LIKE %s OR topic_arn LIKE %s
               OR display_name LIKE %s OR account_name LIKE %s
            ORDER BY account_name, region, topic_name
            LIMIT 300
        """, (like, like, like, like))
        topics = cur.fetchall()
    except Exception as e:
        topics = []
        if not error:
            error = f"SNS query error: {e}"

    try:
        cur.execute("""
            SELECT esm_uuid, function_arn, function_name, event_source_arn,
                   event_source_type, state, batch_size, max_batching_window,
                   bisect_on_error, max_concurrency, starting_position,
                   last_modified, account_name, region, last_seen
            FROM aws_lambda_esms
            WHERE function_name LIKE %s OR function_arn LIKE %s
               OR event_source_arn LIKE %s OR account_name LIKE %s
            ORDER BY account_name, region, function_name
            LIMIT 300
        """, (like, like, like, like))
        esms = cur.fetchall()
    except Exception as e:
        esms = []
        if not error:
            error = f"Lambda ESM query error: {e}"

    try:
        dlq_summary = get_dlq_summary()
    except Exception:
        dlq_summary = []

    cur.close(); conn.close()

    return render_template("messaging.html", view="list",
                           queues=queues, topics=topics, esms=esms,
                           dlq_summary=dlq_summary,
                           query=q, active_tab=tab,
                           active_page="messaging", error=error,
                           sync_script="collect_messaging")

# ─────────────────────────────────────────────
# FORCE SYNC
# ─────────────────────────────────────────────

SYNC_COOLDOWNS = {
    "collect_inventory":       30,
    "collect_sg":              30,
    "collect_network":         30,
    "collect_sso":             30,
    "collect_messaging":       30,
    "collect_iam":             90,
    "collect_rds":            120,
    "collect_eks":             60,
    "collect_eks_node_history": 60,
    "collect_ecs":             60,
    "collect_efs":             60,
    "collect_s3":             120,
    "collect_cloudfront":      60,
    "collect_lambda":          60,
    "collect_lb":              60,
}

ACCOUNT_SCOPED_SCRIPTS = {
    "collect_inventory",
    "collect_sg",
    "collect_network",
    "collect_iam",
    "collect_rds",
    "collect_messaging",
    "collect_eks",
    "collect_eks_node_history",
    "collect_ecs",
    "collect_efs",
    "collect_s3",
    "collect_cloudfront",
    "collect_lambda",
    "collect_lb",
}

SCRIPTS_DIR = os.path.join(BASE_DIR, "scripts")
VENV_PYTHON = sys.executable


def get_sync_status(script: str, account_name: str | None = None):
    conn = get_db()
    cur  = conn.cursor(dictionary=True)
    if account_name:
        cur.execute("""
            SELECT * FROM sync_jobs
            WHERE script = %s AND account_name = %s
            ORDER BY triggered_at DESC LIMIT 1
        """, (script, account_name))
    else:
        cur.execute("""
            SELECT * FROM sync_jobs
            WHERE script = %s AND account_name IS NULL
            ORDER BY triggered_at DESC LIMIT 1
        """, (script,))
    row = cur.fetchone()
    cur.close()
    conn.close()
    return row


def is_on_cooldown(script: str, account_name: str | None = None):
    conn = get_db()
    cur  = conn.cursor(dictionary=True)

    cur.execute("""
        SELECT * FROM sync_jobs
        WHERE script = %s AND status = 'running'
        ORDER BY triggered_at DESC LIMIT 1
    """, (script,))
    running = cur.fetchone()
    if running:
        cur.close()
        conn.close()
        return True, -1

    if account_name:
        cur.execute("""
            SELECT * FROM sync_jobs
            WHERE script = %s AND account_name = %s
            ORDER BY triggered_at DESC LIMIT 1
        """, (script, account_name))
    else:
        cur.execute("""
            SELECT * FROM sync_jobs
            WHERE script = %s
            ORDER BY triggered_at DESC LIMIT 1
        """, (script,))
    last = cur.fetchone()
    cur.close()
    conn.close()

    if not last:
        return False, 0

    cooldown_secs = SYNC_COOLDOWNS.get(script, 30) * 60
    from datetime import datetime as _dt, timezone
    last_run  = last["triggered_at"]
    now       = _dt.now(timezone.utc).replace(tzinfo=None)
    elapsed   = (now - last_run).total_seconds()
    remaining = cooldown_secs - elapsed

    if remaining > 0:
        return True, int(remaining)
    return False, 0


@app.route("/api/sync/<script>", methods=["POST"])
@api_login_required
def api_sync_trigger(script):
    if script not in SYNC_COOLDOWNS:
        return jsonify({"error": "Unknown script"}), 400

    data         = request.get_json(silent=True) or {}
    account_name = data.get("account_name") or None

    if account_name:
        if script not in ACCOUNT_SCOPED_SCRIPTS:
            return jsonify({"error": "This script does not support account scoping"}), 400
        valid_accounts = [a["name"] for a in _get_accounts()]
        if account_name not in valid_accounts:
            return jsonify({"error": f"Unknown account: {account_name}"}), 400

    on_cooldown, remaining = is_on_cooldown(script, account_name)
    if on_cooldown:
        if remaining == -1:
            return jsonify({"error": "A sync is already running for this script"}), 429
        mins = remaining // 60
        secs = remaining % 60
        return jsonify({"error": f"Cooldown active — available in {mins}m {secs}s"}), 429

    triggered_by = (session.get("user") or {}).get("email", "unknown")
    cooldown     = SYNC_COOLDOWNS.get(script, 30)
    now          = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    conn = get_db()
    cur  = conn.cursor()
    cur.execute("""
        INSERT INTO sync_jobs (script, account_name, triggered_by, triggered_at, status, cooldown_minutes)
        VALUES (%s, %s, %s, %s, 'running', %s)
    """, (script, account_name, triggered_by, now, cooldown))
    job_id = cur.lastrowid
    conn.commit()
    cur.close()
    conn.close()

    log_path = f"/tmp/{script}_{job_id}.log"

    cmd = [VENV_PYTHON, f"{SCRIPTS_DIR}/{script}.py"]
    if account_name:
        cmd += ["--account", account_name]

    def _watch(proc, job_id):
        proc.wait()
        finish  = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        outcome = "done" if proc.returncode == 0 else "failed"
        try:
            wconn = get_db()
            wcur  = wconn.cursor()
            wcur.execute("""
                UPDATE sync_jobs SET status=%s, finished_at=%s WHERE id=%s
            """, (outcome, finish, job_id))
            wconn.commit()
            wcur.close()
            wconn.close()
        except Exception:
            pass

    try:
        log_file = open(log_path, "w")
        proc = subprocess.Popen(
            cmd,
            stdout=log_file,
            stderr=subprocess.STDOUT,
            close_fds=True,
            start_new_session=True,
        )
        threading.Thread(target=_watch, args=(proc, job_id), daemon=True).start()
    except Exception as e:
        finish = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        conn2 = get_db()
        cur2  = conn2.cursor()
        cur2.execute(
            "UPDATE sync_jobs SET status='failed', finished_at=%s WHERE id=%s",
            (finish, job_id)
        )
        conn2.commit()
        cur2.close()
        conn2.close()
        return jsonify({"error": f"Failed to spawn process: {e}"}), 500

    return jsonify({
        "job_id":       job_id,
        "script":       script,
        "account_name": account_name,
        "triggered_by": triggered_by,
        "triggered_at": now,
        "log_path":     log_path,
        "status":       "running",
    }), 202


@app.route("/api/sync/status/<script>")
@api_login_required
def api_sync_status(script):
    if script not in SYNC_COOLDOWNS:
        return jsonify({"error": "Unknown script"}), 400

    account_name = request.args.get("account_name") or None
    job          = get_sync_status(script, account_name)

    if not job:
        return jsonify({"status": "never", "script": script}), 200

    on_cooldown, remaining = is_on_cooldown(script, account_name)

    def fmt(dt):
        return str(dt) if dt else None

    return jsonify({
        "job_id":                  job["id"],
        "script":                  script,
        "account_name":            job["account_name"],
        "triggered_by":            job["triggered_by"],
        "triggered_at":            fmt(job["triggered_at"]),
        "finished_at":             fmt(job["finished_at"]),
        "status":                  job["status"],
        "on_cooldown":             on_cooldown,
        "cooldown_remaining_secs": remaining,
    }), 200


@app.route("/api/accounts")
@api_login_required
def api_accounts():
    accounts = [a["name"] for a in _get_accounts()]
    return jsonify({"accounts": sorted(accounts)}), 200


# ─────────────────────────────────────────────
# S3
# ─────────────────────────────────────────────

def get_s3_stats() -> dict:
    conn = get_db()
    cur  = conn.cursor(dictionary=True)
    out  = {"s3_buckets": 0, "s3_total_gb": 0}
    try:
        cur.execute("SELECT COUNT(*) AS cnt FROM aws_s3_buckets")
        out["s3_buckets"] = cur.fetchone()["cnt"]
        cur.execute("""
            SELECT COALESCE(SUM(size_bytes), 0) AS total
            FROM aws_s3_storage
            WHERE storage_type = 'AllStorageTypes'
        """)
        total_bytes = cur.fetchone()["total"] or 0
        out["s3_total_gb"] = round(total_bytes / 1_073_741_824, 1)
    except Exception:
        pass
    cur.close()
    conn.close()
    return out


def get_s3_buckets(query: str = "") -> list:
    conn = get_db()
    cur  = conn.cursor(dictionary=True)
    term = f"%{query.strip()}%" if query else "%"

    cur.execute("""
        SELECT
            b.bucket_name,
            b.account_name,
            b.region,
            b.creation_date,
            b.versioning,
            b.encryption_enabled,
            b.encryption_type,
            b.fully_public_blocked,
            b.block_public_acls,
            b.ignore_public_acls,
            b.block_public_policy,
            b.restrict_public_buckets,
            b.lifecycle_rules,
            b.lifecycle_rule_count,
            b.object_lock_enabled,
            b.replication_enabled,
            b.website_enabled,
            b.logging_enabled,
            b.last_seen,
            COALESCE(s.size_bytes, 0)   AS total_bytes,
            COALESCE(s.object_count, 0) AS object_count,
            s.metric_date
        FROM aws_s3_buckets b
        LEFT JOIN aws_s3_storage s
            ON s.bucket_name = b.bucket_name
           AND s.storage_type = 'AllStorageTypes'
        WHERE b.bucket_name LIKE %s
           OR b.account_name LIKE %s
           OR b.region       LIKE %s
        ORDER BY b.account_name, b.bucket_name
        LIMIT 500
    """, (term, term, term))
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return rows


def get_s3_bucket_detail(bucket_name: str) -> dict:
    conn = get_db()
    cur  = conn.cursor(dictionary=True)

    cur.execute("""
        SELECT * FROM aws_s3_buckets
        WHERE bucket_name = %s
        LIMIT 1
    """, (bucket_name,))
    bucket = cur.fetchone()

    if not bucket:
        cur.close()
        conn.close()
        return {}

    cur.execute("""
        SELECT storage_type, size_bytes, object_count, metric_date
        FROM aws_s3_storage
        WHERE bucket_name = %s
          AND storage_type != 'AllStorageTypes'
          AND size_bytes > 0
        ORDER BY size_bytes DESC
    """, (bucket_name,))
    storage_breakdown = cur.fetchall()

    cur.execute("""
        SELECT size_bytes, object_count, metric_date
        FROM aws_s3_storage
        WHERE bucket_name = %s AND storage_type = 'AllStorageTypes'
        LIMIT 1
    """, (bucket_name,))
    summary = cur.fetchone() or {"size_bytes": 0, "object_count": 0, "metric_date": None}

    cur.execute("""
        SELECT tag_key, tag_value FROM aws_s3_tags
        WHERE bucket_name = %s
        ORDER BY tag_key
    """, (bucket_name,))
    tags = [{"k": r["tag_key"], "v": r["tag_value"] or ""} for r in cur.fetchall()]

    cur.close()
    conn.close()
    return {
        "bucket":            bucket,
        "storage_breakdown": storage_breakdown,
        "summary":           summary,
        "tags":              tags,
    }


@app.route("/s3")
@app.route("/s3/")
@login_required
def s3_index():
    q           = request.args.get("q", "").strip()
    bucket_name = request.args.get("bucket", "").strip()

    if bucket_name:
        detail = get_s3_bucket_detail(bucket_name)
        if not detail:
            return render_template("s3.html", view="list", buckets=[],
                                   query=q, active_page="s3",
                                   sync_script="collect_s3",
                                   error=f"Bucket '{bucket_name}' not found.")
        return render_template("s3.html", view="detail",
                               detail=detail, query=q,
                               active_page="s3",
                               sync_script="collect_s3")

    buckets = get_s3_buckets(q)
    return render_template("s3.html", view="list",
                           buckets=buckets, query=q,
                           active_page="s3",
                           sync_script="collect_s3")

# ─────────────────────────────────────────────
# EFS
# ─────────────────────────────────────────────

def get_efs_filesystems(query: str = "") -> list:
    conn = get_db()
    cur  = conn.cursor(dictionary=True)
    term = f"%{query.strip()}%" if query else "%"

    cur.execute("""
        SELECT
            fs_id, fs_arn, name, lifecycle_state, performance_mode, throughput_mode,
            provisioned_throughput, encrypted, number_of_mount_targets,
            size_bytes_total, size_bytes_standard, size_bytes_ia, size_bytes_archive,
            dns_name, availability_zone, account_name, region, created_at, last_seen
        FROM aws_efs_filesystems
        WHERE fs_id        LIKE %s
           OR name         LIKE %s
           OR account_name LIKE %s
           OR region       LIKE %s
           OR dns_name     LIKE %s
        ORDER BY account_name, region, name, fs_id
        LIMIT 500
    """, (term, term, term, term, term))
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return rows


def get_efs_detail(fs_id: str, account_name: str) -> dict:
    conn = get_db()
    cur  = conn.cursor(dictionary=True)

    cur.execute("""
        SELECT * FROM aws_efs_filesystems
        WHERE fs_id = %s AND account_name = %s
        LIMIT 1
    """, (fs_id, account_name))
    fs = cur.fetchone()

    if not fs:
        cur.close()
        conn.close()
        return {}

    cur.execute("""
        SELECT mount_target_id, lifecycle_state, ip_address,
               subnet_id, vpc_id, availability_zone, dns_name
        FROM aws_efs_mount_targets
        WHERE fs_id = %s AND account_name = %s
        ORDER BY availability_zone
    """, (fs_id, account_name))
    mount_targets = cur.fetchall()

    cur.execute("""
        SELECT tag_key, tag_value FROM aws_efs_tags
        WHERE fs_id = %s AND account_name = %s
        ORDER BY tag_key
    """, (fs_id, account_name))
    tags = [{"k": r["tag_key"], "v": r["tag_value"] or ""} for r in cur.fetchall()]

    cur.close()
    conn.close()
    return {
        "fs":            fs,
        "mount_targets": mount_targets,
        "tags":          tags,
    }


@app.route("/efs")
@app.route("/efs/")
@login_required
def efs_index():
    q        = request.args.get("q", "").strip()
    fs_id    = request.args.get("fs_id", "").strip()
    account  = request.args.get("account", "").strip()

    if fs_id and account:
        detail = get_efs_detail(fs_id, account)
        if not detail:
            return render_template("efs.html", view="list", filesystems=[],
                                   query=q, active_page="efs",
                                   sync_script="collect_efs",
                                   error=f"File system '{fs_id}' not found.")
        return render_template("efs.html", view="detail",
                               detail=detail, query=q,
                               active_page="efs",
                               sync_script="collect_efs")

    filesystems = get_efs_filesystems(q)
    return render_template("efs.html", view="list",
                           filesystems=filesystems, query=q,
                           active_page="efs",
                           sync_script="collect_efs")

# ─────────────────────────────────────────────
# ECS
# ─────────────────────────────────────────────

def get_ecs_clusters(query: str = "") -> list:
    conn = get_db()
    cur  = conn.cursor(dictionary=True)
    term = f"%{query.strip()}%" if query else "%"
    cur.execute("""
        SELECT cluster_arn, cluster_name, status, active_services,
               running_tasks, pending_tasks, registered_container_instances,
               container_insights, account_name, region, last_seen
        FROM aws_ecs_clusters
        WHERE cluster_name LIKE %s
           OR account_name LIKE %s
           OR region       LIKE %s
        ORDER BY account_name, region, cluster_name
        LIMIT 500
    """, (term, term, term))
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return rows


def get_ecs_services(query: str = "", cluster_arn: str = "") -> list:
    conn = get_db()
    cur  = conn.cursor(dictionary=True)
    term = f"%{query.strip()}%" if query else "%"

    if cluster_arn:
        cur.execute("""
            SELECT service_arn, service_name, cluster_arn, cluster_name,
                   status, desired_count, running_count, pending_count,
                   task_definition, launch_type, scheduling_strategy,
                   platform_family, platform_version, deployment_controller,
                   load_balancers, subnets, security_groups, assign_public_ip,
                   account_name, region, created_at, last_seen
            FROM aws_ecs_services
            WHERE cluster_arn = %s
            ORDER BY service_name
            LIMIT 500
        """, (cluster_arn,))
    else:
        cur.execute("""
            SELECT service_arn, service_name, cluster_arn, cluster_name,
                   status, desired_count, running_count, pending_count,
                   task_definition, launch_type, scheduling_strategy,
                   platform_family, platform_version, deployment_controller,
                   load_balancers, subnets, security_groups, assign_public_ip,
                   account_name, region, created_at, last_seen
            FROM aws_ecs_services
            WHERE service_name   LIKE %s
               OR cluster_name   LIKE %s
               OR account_name   LIKE %s
               OR task_definition LIKE %s
            ORDER BY account_name, region, cluster_name, service_name
            LIMIT 500
        """, (term, term, term, term))
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return rows


def get_ecs_cluster_detail(cluster_arn: str, account_name: str) -> dict:
    conn = get_db()
    cur  = conn.cursor(dictionary=True)

    cur.execute("""
        SELECT * FROM aws_ecs_clusters
        WHERE cluster_arn = %s AND account_name = %s
        LIMIT 1
    """, (cluster_arn, account_name))
    cluster = cur.fetchone()

    if not cluster:
        cur.close()
        conn.close()
        return {}

    cur.execute("""
        SELECT service_arn, service_name, status, desired_count, running_count,
               pending_count, task_definition, launch_type, scheduling_strategy,
               platform_family, deployment_controller, load_balancers,
               assign_public_ip, created_at, last_seen
        FROM aws_ecs_services
        WHERE cluster_arn = %s AND account_name = %s
        ORDER BY service_name
    """, (cluster_arn, account_name))
    services = cur.fetchall()

    cur.execute("""
        SELECT tag_key, tag_value FROM aws_ecs_tags
        WHERE resource_arn = %s AND account_name = %s
        ORDER BY tag_key
    """, (cluster_arn, account_name))
    tags = [{"k": r["tag_key"], "v": r["tag_value"] or ""} for r in cur.fetchall()]

    cur.close()
    conn.close()
    return {"cluster": cluster, "services": services, "tags": tags}


def get_ecs_service_detail(service_arn: str, account_name: str) -> dict:
    conn = get_db()
    cur  = conn.cursor(dictionary=True)

    cur.execute("""
        SELECT * FROM aws_ecs_services
        WHERE service_arn = %s AND account_name = %s
        LIMIT 1
    """, (service_arn, account_name))
    service = cur.fetchone()

    if not service:
        cur.close()
        conn.close()
        return {}

    task_def = None
    if service.get("task_definition"):
        cur.execute("""
            SELECT * FROM aws_ecs_task_definitions
            WHERE task_def_arn = %s AND account_name = %s
            LIMIT 1
        """, (service["task_definition"], account_name))
        task_def = cur.fetchone()

    cur.execute("""
        SELECT tag_key, tag_value FROM aws_ecs_tags
        WHERE resource_arn = %s AND account_name = %s
        ORDER BY tag_key
    """, (service_arn, account_name))
    tags = [{"k": r["tag_key"], "v": r["tag_value"] or ""} for r in cur.fetchall()]

    cur.close()
    conn.close()
    return {"service": service, "task_def": task_def, "tags": tags}


@app.route("/ecs")
@app.route("/ecs/")
@login_required
def ecs_index():
    q           = request.args.get("q", "").strip()
    cluster_arn = request.args.get("cluster_arn", "").strip()
    service_arn = request.args.get("service_arn", "").strip()
    account     = request.args.get("account", "").strip()
    active_tab  = request.args.get("tab", "clusters")

    if service_arn and account:
        detail = get_ecs_service_detail(service_arn, account)
        if not detail:
            return render_template("ecs.html", view="list",
                                   clusters=[], services=[],
                                   query=q, active_tab="services",
                                   active_page="ecs",
                                   sync_script="collect_ecs",
                                   error="Service not found.")
        return render_template("ecs.html", view="service_detail",
                               detail=detail, query=q,
                               active_page="ecs",
                               sync_script="collect_ecs")

    if cluster_arn and account:
        detail = get_ecs_cluster_detail(cluster_arn, account)
        if not detail:
            return render_template("ecs.html", view="list",
                                   clusters=[], services=[],
                                   query=q, active_tab="clusters",
                                   active_page="ecs",
                                   sync_script="collect_ecs",
                                   error="Cluster not found.")
        return render_template("ecs.html", view="cluster_detail",
                               detail=detail, query=q,
                               active_page="ecs",
                               sync_script="collect_ecs")

    clusters = get_ecs_clusters(q)
    services = get_ecs_services(q)
    return render_template("ecs.html", view="list",
                           clusters=clusters, services=services,
                           query=q, active_tab=active_tab,
                           active_page="ecs",
                           sync_script="collect_ecs")

# ─────────────────────────────────────────────
# EKS
# ─────────────────────────────────────────────

def get_eks_clusters(query: str = "") -> list:
    conn = get_db()
    cur  = conn.cursor(dictionary=True)
    term = f"%{query.strip()}%" if query else "%"
    cur.execute("""
        SELECT cluster_name, cluster_arn, status, kubernetes_version,
               platform_version, endpoint_public_access, endpoint_private_access,
               vpc_id, cluster_sg_id, secrets_encrypted, logging_enabled,
               service_ipv4_cidr, ip_family, account_name, region, created_at, last_seen
        FROM aws_eks_clusters
        WHERE cluster_name LIKE %s
           OR account_name LIKE %s
           OR region       LIKE %s
           OR vpc_id       LIKE %s
           OR kubernetes_version LIKE %s
        ORDER BY account_name, region, cluster_name
        LIMIT 300
    """, (term, term, term, term, term))
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return rows


def get_eks_cluster_detail(cluster_name: str, account_name: str, region: str) -> dict:
    conn = get_db()
    cur  = conn.cursor(dictionary=True)

    cur.execute("""
        SELECT * FROM aws_eks_clusters
        WHERE cluster_name = %s AND account_name = %s AND region = %s
        LIMIT 1
    """, (cluster_name, account_name, region))
    cluster = cur.fetchone()

    if not cluster:
        cur.close()
        conn.close()
        return {}

    cur.execute("""
        SELECT nodegroup_name, nodegroup_arn, status, capacity_type,
               instance_types, ami_type, ami_release_version, disk_size_gb,
               desired_size, min_size, max_size, node_role_arn,
               subnet_ids, labels, taints, update_config, created_at
        FROM aws_eks_nodegroups
        WHERE cluster_name = %s AND account_name = %s AND region = %s
        ORDER BY nodegroup_name
    """, (cluster_name, account_name, region))
    nodegroups = cur.fetchall()

    cur.execute("""
        SELECT tag_key, tag_value FROM aws_eks_tags
        WHERE resource_arn = %s AND account_name = %s
        ORDER BY tag_key
    """, (cluster.get("cluster_arn", ""), account_name))
    tags = [{"k": r["tag_key"], "v": r["tag_value"] or ""} for r in cur.fetchall()]

    cur.close()
    conn.close()
    return {"cluster": cluster, "nodegroups": nodegroups, "tags": tags}


def get_eks_fleet_summary() -> dict:
    try:
        conn = get_db()
        cur  = conn.cursor(dictionary=True)

        cur.execute("""
            SELECT
                COUNT(*)                                              AS total_clusters,
                SUM(status = 'ACTIVE')                               AS active_clusters,
                SUM(endpoint_public_access = 1)                      AS public_api_count,
                SUM(secrets_encrypted = 1)                           AS secrets_enc_count,
                SUM(logging_enabled IS NULL OR logging_enabled = '[]') AS no_logging_count
            FROM aws_eks_clusters
        """)
        cluster_row = cur.fetchone() or {}

        cur.execute("""
            SELECT kubernetes_version, COUNT(*) AS cnt
            FROM aws_eks_clusters
            GROUP BY kubernetes_version
            ORDER BY kubernetes_version DESC
        """)
        version_dist = cur.fetchall()

        cur.execute("""
            SELECT
                SUM(desired_size)                    AS total_desired,
                SUM(min_size)                        AS total_min,
                SUM(max_size)                        AS total_max,
                SUM(capacity_type = 'ON_DEMAND')     AS on_demand_ngs,
                SUM(capacity_type = 'SPOT')          AS spot_ngs,
                COUNT(*)                             AS total_ngs
            FROM aws_eks_nodegroups
        """)
        ng_row = cur.fetchone() or {}

        cur.close()
        conn.close()

        return {
            "total_clusters":    int(cluster_row.get("total_clusters") or 0),
            "active_clusters":   int(cluster_row.get("active_clusters") or 0),
            "public_api_count":  int(cluster_row.get("public_api_count") or 0),
            "secrets_enc_count": int(cluster_row.get("secrets_enc_count") or 0),
            "no_logging_count":  int(cluster_row.get("no_logging_count") or 0),
            "version_dist":      version_dist,
            "total_desired":     int(ng_row.get("total_desired") or 0),
            "total_min":         int(ng_row.get("total_min") or 0),
            "total_max":         int(ng_row.get("total_max") or 0),
            "on_demand_ngs":     int(ng_row.get("on_demand_ngs") or 0),
            "spot_ngs":          int(ng_row.get("spot_ngs") or 0),
            "total_ngs":         int(ng_row.get("total_ngs") or 0),
        }
    except Exception:
        return {}


@app.route("/eks")
@app.route("/eks/")
@login_required
def eks_index():
    q            = request.args.get("q", "").strip()
    cluster_name = request.args.get("cluster_name", "").strip()
    account      = request.args.get("account", "").strip()
    region       = request.args.get("region", "").strip()

    if cluster_name and account and region:
        detail = get_eks_cluster_detail(cluster_name, account, region)
        if not detail:
            return render_template("eks.html", view="list", clusters=[],
                                   query=q, active_page="eks",
                                   sync_script="collect_eks",
                                   error=f"Cluster '{cluster_name}' not found.")
        return render_template("eks.html", view="detail",
                               detail=detail, query=q,
                               active_page="eks",
                               sync_script="collect_eks")

    clusters      = get_eks_clusters(q)
    fleet_summary = get_eks_fleet_summary() if not q else None
    return render_template("eks.html", view="list",
                           clusters=clusters, query=q,
                           fleet_summary=fleet_summary,
                           active_page="eks",
                           sync_script="collect_eks")

# ─────────────────────────────────────────────
# EKS NODE HISTORY
# ─────────────────────────────────────────────

@app.route("/eks/node-history")
@api_login_required
def eks_node_history():
    """
    JSON API — returns hourly node-count history for a specific cluster,
    broken down by the requested group_by dimension.

    Query params:
        cluster  — cluster_name  (required)
        account  — account_name  (required)
        region   — region        (required)
        days     — 7 | 30 | 90   (default 30)
        group_by — 'instance_type' | 'node_group' | 'capacity_type' | 'asg_name'
                   (default 'instance_type')
    """
    cluster_name = request.args.get("cluster",  "").strip()
    account_name = request.args.get("account",  "").strip()
    region       = request.args.get("region",   "").strip()
    group_by     = request.args.get("group_by", "instance_type").strip()

    try:
        days = int(request.args.get("days", 30))
    except ValueError:
        days = 30

    days     = days     if days     in (7, 30, 90)                                          else 30
    group_by = group_by if group_by in ("instance_type", "node_group",
                                        "capacity_type", "asg_name")                        else "instance_type"

    if not cluster_name or not account_name or not region:
        return jsonify({"error": "cluster, account, and region are required"}), 400

    conn = get_db()
    cur  = conn.cursor(dictionary=True)

    # ── Choose time bucketing ─────────────────────────────────────────────
    if days <= 30:
        bucket_expr = "DATE_FORMAT(recorded_at, '%Y-%m-%d %H:00:00')"
    else:
        bucket_expr = (
            "DATE_FORMAT("
            "  DATE_SUB(recorded_at, INTERVAL MOD(HOUR(recorded_at), 4) HOUR),"
            "  '%Y-%m-%d %H:00:00'"
            ")"
        )

    # ── Fetch distinct group values in window ─────────────────────────────
    cur.execute(f"""
        SELECT DISTINCT `{group_by}` AS grp_val
        FROM aws_eks_node_history
        WHERE cluster_name = %s
          AND account_name = %s
          AND region       = %s
          AND recorded_at >= NOW() - INTERVAL %s DAY
        ORDER BY `{group_by}`
    """, (cluster_name, account_name, region, days))
    group_values = [r["grp_val"] for r in cur.fetchall()]

    series_out = []

    for grp_val in group_values:
        cur.execute(f"""
            SELECT
                {bucket_expr}                    AS t,
                COUNT(DISTINCT instance_id)      AS node_count
            FROM aws_eks_node_history
            WHERE cluster_name = %s
              AND account_name = %s
              AND region       = %s
              AND `{group_by}` = %s
              AND recorded_at >= NOW() - INTERVAL %s DAY
            GROUP BY {bucket_expr}
            ORDER BY t ASC
        """, (cluster_name, account_name, region, grp_val, days))

        rows = cur.fetchall()
        data = [{"t": str(r["t"]), "count": int(r["node_count"])} for r in rows]
        if data:
            series_out.append({"label": grp_val or "unknown", "data": data})

    # ── Summary stats ─────────────────────────────────────────────────────
    cur.execute(f"""
        SELECT
            {bucket_expr}               AS t,
            COUNT(DISTINCT instance_id) AS total
        FROM aws_eks_node_history
        WHERE cluster_name = %s
          AND account_name = %s
          AND region       = %s
          AND recorded_at >= NOW() - INTERVAL %s DAY
        GROUP BY {bucket_expr}
        ORDER BY t DESC
    """, (cluster_name, account_name, region, days))
    totals_rows = cur.fetchall()

    totals        = [r["total"] for r in totals_rows]
    current_total = totals[0] if totals else 0
    period_peak   = max(totals) if totals else 0
    period_avg    = round(sum(totals) / len(totals), 1) if totals else 0

    cur.close()
    conn.close()

    return jsonify({
        "cluster":  cluster_name,
        "account":  account_name,
        "region":   region,
        "days":     days,
        "group_by": group_by,
        "series":   series_out,
        "summary": {
            "current_total": current_total,
            "period_peak":   period_peak,
            "period_avg":    period_avg,
            "data_points":   len(totals),
        },
    })

# ─────────────────────────────────────────────
# CLOUDFRONT
# ─────────────────────────────────────────────

def get_cf_distributions(query: str = "") -> list:
    conn = get_db()
    cur  = conn.cursor(dictionary=True)
    term = f"%{query.strip()}%" if query else "%"
    cur.execute("""
        SELECT
            d.distribution_id, d.distribution_arn, d.domain_name, d.comment,
            d.status, d.enabled, d.http_version, d.price_class, d.ipv6_enabled,
            d.aliases, d.viewer_cert_source, d.acm_cert_arn, d.minimum_protocol_version,
            d.waf_web_acl_id, d.cache_behavior_count, d.origin_count,
            d.geo_restriction_type, d.account_name, d.last_modified, d.last_seen
        FROM aws_cf_distributions d
        WHERE d.distribution_id LIKE %s
           OR d.domain_name     LIKE %s
           OR d.comment         LIKE %s
           OR d.account_name    LIKE %s
           OR d.aliases         LIKE %s
        ORDER BY d.account_name, d.domain_name
        LIMIT 300
    """, (term, term, term, term, term))
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return rows


def get_cf_detail(distribution_id: str, account_name: str) -> dict:
    conn = get_db()
    cur  = conn.cursor(dictionary=True)

    cur.execute("""
        SELECT * FROM aws_cf_distributions
        WHERE distribution_id = %s AND account_name = %s
        LIMIT 1
    """, (distribution_id, account_name))
    dist = cur.fetchone()

    if not dist:
        cur.close()
        conn.close()
        return {}

    cur.execute("""
        SELECT origin_id, domain_name, origin_path, origin_type,
               protocol_policy, https_only, connection_attempts, connection_timeout
        FROM aws_cf_origins
        WHERE distribution_id = %s AND account_name = %s
        ORDER BY origin_id
    """, (distribution_id, account_name))
    origins = cur.fetchall()

    cur.execute("""
        SELECT tag_key, tag_value FROM aws_cf_tags
        WHERE distribution_id = %s AND account_name = %s
        ORDER BY tag_key
    """, (distribution_id, account_name))
    tags = [{"k": r["tag_key"], "v": r["tag_value"] or ""} for r in cur.fetchall()]

    cur.close()
    conn.close()
    return {"dist": dist, "origins": origins, "tags": tags}


@app.route("/cloudfront")
@app.route("/cloudfront/")
@login_required
def cloudfront_index():
    q               = request.args.get("q", "").strip()
    distribution_id = request.args.get("dist_id", "").strip()
    account         = request.args.get("account", "").strip()

    if distribution_id and account:
        detail = get_cf_detail(distribution_id, account)
        if not detail:
            return render_template("cloudfront.html", view="list", distributions=[],
                                   query=q, active_page="cloudfront",
                                   sync_script="collect_cloudfront",
                                   error=f"Distribution '{distribution_id}' not found.")
        return render_template("cloudfront.html", view="detail",
                               detail=detail, query=q,
                               active_page="cloudfront",
                               sync_script="collect_cloudfront")

    distributions = get_cf_distributions(q)
    return render_template("cloudfront.html", view="list",
                           distributions=distributions, query=q,
                           active_page="cloudfront",
                           sync_script="collect_cloudfront")

# ─────────────────────────────────────────────
# LAMBDA
# ─────────────────────────────────────────────

def get_lambda_functions(query: str = "", runtime: str = "", account: str = "") -> list:
    conn = get_db()
    cur  = conn.cursor(dictionary=True)
    term = f"%{query.strip()}%" if query else "%"

    conditions = [
        "(f.function_name LIKE %s OR f.function_arn LIKE %s OR f.description LIKE %s OR f.account_name LIKE %s)"
    ]
    params = [term, term, term, term]

    if runtime:
        conditions.append("f.runtime = %s")
        params.append(runtime)
    if account:
        conditions.append("f.account_name = %s")
        params.append(account)

    where = " AND ".join(conditions)
    cur.execute(f"""
        SELECT f.function_name, f.function_arn, f.description, f.runtime, f.handler,
               f.memory_mb, f.timeout_sec, f.architecture, f.package_type,
               f.code_size, f.state, f.last_update_status,
               f.vpc_id, f.env_var_count, f.layer_count, f.reserved_concurrency,
               f.ephemeral_storage_mb, f.image_uri,
               f.logging_log_format, f.logging_app_level, f.logging_sys_level,
               f.snap_start_apply_on, f.snap_start_optimization,
               f.modified_at, f.account_name, f.region, f.last_seen
        FROM aws_lambda_functions f
        WHERE {where}
        ORDER BY f.account_name, f.region, f.function_name
        LIMIT 500
    """, params)
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return rows


def get_lambda_function_detail(function_arn: str, account_name: str) -> dict:
    conn = get_db()
    cur  = conn.cursor(dictionary=True)

    cur.execute("""
        SELECT * FROM aws_lambda_functions
        WHERE function_arn = %s AND account_name = %s
        LIMIT 1
    """, (function_arn, account_name))
    fn = cur.fetchone()
    if not fn:
        cur.close(); conn.close()
        return {}

    cur.execute("""
        SELECT layer_arn, layer_name, layer_version, code_size
        FROM aws_lambda_layers
        WHERE function_arn = %s AND account_name = %s
        ORDER BY layer_name
    """, (function_arn, account_name))
    layers = cur.fetchall()

    cur.execute("""
        SELECT alias_name, alias_arn, function_version, description, routing_config
        FROM aws_lambda_aliases
        WHERE function_arn = %s AND account_name = %s
        ORDER BY alias_name
    """, (function_arn, account_name))
    aliases = cur.fetchall()

    cur.execute("""
        SELECT tag_key, tag_value
        FROM aws_lambda_tags
        WHERE function_arn = %s AND account_name = %s
        ORDER BY tag_key
    """, (function_arn, account_name))
    tags = [{"k": r["tag_key"], "v": r["tag_value"] or ""} for r in cur.fetchall()]

    esms = []
    try:
        cur.execute("""
            SELECT esm_uuid, event_source_arn, event_source_type,
                   state, batch_size, max_batching_window, starting_position
            FROM aws_lambda_esms
            WHERE function_arn = %s AND account_name = %s
            ORDER BY event_source_type, event_source_arn
        """, (function_arn, account_name))
        esms = cur.fetchall()
    except Exception:
        pass

    cur.close(); conn.close()
    return {"fn": fn, "layers": layers, "aliases": aliases, "tags": tags, "esms": esms}


def get_lambda_runtime_summary() -> list:
    try:
        conn = get_db()
        cur  = conn.cursor(dictionary=True)
        cur.execute("""
            SELECT
                COALESCE(runtime, 'container') AS runtime,
                COUNT(*) AS fn_count,
                SUM(memory_mb) AS total_memory_mb,
                ROUND(AVG(memory_mb), 0) AS avg_memory_mb,
                SUM(code_size) AS total_code_bytes
            FROM aws_lambda_functions
            GROUP BY runtime
            ORDER BY fn_count DESC
        """)
        rows = cur.fetchall()
        cur.close(); conn.close()
        return rows
    except Exception:
        return []


def get_lambda_account_summary() -> list:
    try:
        conn = get_db()
        cur  = conn.cursor(dictionary=True)
        cur.execute("""
            SELECT
                account_name,
                COUNT(*) AS fn_count,
                COUNT(DISTINCT region) AS region_count,
                SUM(vpc_id IS NOT NULL) AS vpc_count,
                SUM(reserved_concurrency IS NOT NULL) AS reserved_count,
                MAX(last_seen) AS last_seen
            FROM aws_lambda_functions
            GROUP BY account_name
            ORDER BY fn_count DESC
        """)
        rows = cur.fetchall()
        cur.close(); conn.close()
        return rows
    except Exception:
        return []


def get_lambda_distinct_runtimes() -> list:
    try:
        conn = get_db()
        cur  = conn.cursor(dictionary=True)
        cur.execute("""
            SELECT DISTINCT runtime FROM aws_lambda_functions
            WHERE runtime IS NOT NULL
            ORDER BY runtime
        """)
        rows = [r["runtime"] for r in cur.fetchall()]
        cur.close(); conn.close()
        return rows
    except Exception:
        return []


def get_lambda_distinct_accounts() -> list:
    try:
        conn = get_db()
        cur  = conn.cursor(dictionary=True)
        cur.execute("""
            SELECT DISTINCT account_name FROM aws_lambda_functions
            ORDER BY account_name
        """)
        rows = [r["account_name"] for r in cur.fetchall()]
        cur.close(); conn.close()
        return rows
    except Exception:
        return []


@app.route("/lambda")
@app.route("/lambda/")
@login_required
def lambda_index():
    q            = request.args.get("q", "").strip()
    function_arn = request.args.get("function_arn", "").strip()
    account      = request.args.get("account", "").strip()
    runtime_flt  = request.args.get("runtime", "").strip()
    active_tab   = request.args.get("tab", "functions")

    if function_arn and account:
        detail = get_lambda_function_detail(function_arn, account)
        if not detail:
            return render_template("lambda.html", view="list",
                                   functions=[], runtime_summary=[],
                                   account_summary=[], runtimes=[], accounts=[],
                                   query=q, active_tab="functions",
                                   active_page="lambda",
                                   sync_script="collect_lambda",
                                   error="Function not found.")
        return render_template("lambda.html", view="detail",
                               detail=detail, query=q,
                               active_page="lambda",
                               sync_script="collect_lambda")

    functions       = get_lambda_functions(q, runtime_flt, account)
    runtime_summary = get_lambda_runtime_summary()
    account_summary = get_lambda_account_summary()
    runtimes        = get_lambda_distinct_runtimes()
    accounts        = get_lambda_distinct_accounts()

    return render_template("lambda.html", view="list",
                           functions=functions,
                           runtime_summary=runtime_summary,
                           account_summary=account_summary,
                           runtimes=runtimes,
                           accounts=accounts,
                           query=q,
                           runtime_filter=runtime_flt,
                           account_filter=account,
                           active_tab=active_tab,
                           active_page="lambda",
                           sync_script="collect_lambda")


# ─────────────────────────────────────────────
# TRAFFIC TRACE
# ─────────────────────────────────────────────
#
# Resolves a hostname through the full chain:
#   DNS record → ELB →
#   ALB listener rule (redirect or forward) → target group → instances


def trace_resolve(hostname: str, lb_name: str = "", account: str = "", region: str = "") -> dict:
    """
    Walk the traffic chain for a given hostname and return a structured list
    of hops. Each hop is a dict with at minimum:
        type        — dns | elb | alb_listener |
                      alb_rule | alb_redirect | nlb_listener |
                      clb_listener | target_group | target | note
        label       — short human label
        detail      — dict of display fields
        account     — account_name (if applicable)
        region      — region (if applicable)

    Stops gracefully at any point data is missing, appending a 'note' hop.
    Max redirect depth: 3 (prevents infinite loops).
    """
    hops      = []
    seen_elbs = set()   # prevent cycles

    def _conn():
        return mysql.connector.connect(**DB_CONFIG)

    # ── Step 1: DNS lookup ──────────────────────────────────────────────
    def resolve_dns(name: str) -> list:
        """Return all matching DNS rows for a hostname."""
        conn = _conn()
        cur  = conn.cursor(dictionary=True)
        cur.execute("""
            SELECT account_name, hosted_zone_name, record_name,
                   record_type, record_value, record_alias_name
            FROM aws_domains
            WHERE record_name = %s OR record_name = %s
            ORDER BY last_seen DESC
            LIMIT 10
        """, (name, name.rstrip('.') + '.'))
        rows = cur.fetchall()
        cur.close(); conn.close()
        return rows

    # ── Step 3: ELB lookup ──────────────────────────────────────────────
    def resolve_elb(dns_name: str) -> dict | None:
        """Find an LB row by its DNS name."""
        conn = _conn()
        cur  = conn.cursor(dictionary=True)
        cur.execute("""
            SELECT lb_arn, lb_name, lb_type, dns_name, scheme,
                   state, vpc_id, account_name, region
            FROM aws_load_balancers
            WHERE dns_name = %s OR dns_name = %s
            LIMIT 1
        """, (dns_name, dns_name.rstrip('.')))
        row = cur.fetchone()
        cur.close(); conn.close()
        return row

    # ── Step 4: Listeners ───────────────────────────────────────────────
    def resolve_listeners(lb_arn: str) -> list:
        conn = _conn()
        cur  = conn.cursor(dictionary=True)
        cur.execute("""
            SELECT listener_arn, lb_type, protocol, port,
                   default_action_type, default_action_target
            FROM aws_lb_listeners
            WHERE lb_arn = %s
            ORDER BY port
        """, (lb_arn,))
        rows = cur.fetchall()
        cur.close(); conn.close()
        return rows

    # ── Step 5: ALB rule match ──────────────────────────────────────────
    def match_alb_rule(lb_arn: str, hostname: str) -> dict | None:
        """
        Find the highest-priority non-default ALB rule whose host-header
        condition matches the queried hostname. Falls back to default rule.
        """
        conn = _conn()
        cur  = conn.cursor(dictionary=True)
        # Non-default host-header rules, ordered by numeric priority
        cur.execute("""
            SELECT rule_arn, listener_arn, priority, is_default,
                   condition_type, condition_values,
                   action_type, action_target,
                   redirect_host, redirect_path, redirect_port,
                   redirect_protocol, redirect_status,
                   fixed_status
            FROM aws_lb_listener_rules
            WHERE lb_arn = %s
              AND is_default = 0
              AND condition_type = 'host-header'
            ORDER BY CAST(priority AS UNSIGNED)
        """, (lb_arn,))
        rules = cur.fetchall()

        matched = None
        for rule in rules:
            try:
                values = json.loads(rule["condition_values"] or "[]")
            except Exception:
                values = []
            if hostname in values:
                matched = rule
                break

        cur.close(); conn.close()
        return matched

    # ── Step 6: Target group + targets ─────────────────────────────────
    def resolve_tg(tg_arn: str) -> dict:
        conn = _conn()
        cur  = conn.cursor(dictionary=True)
        cur.execute("""
            SELECT tg_arn, tg_name, target_type, protocol, port,
                   health_check_path, account_name, region
            FROM aws_lb_target_groups
            WHERE tg_arn = %s
        """, (tg_arn,))
        tg = cur.fetchone()

        targets = []
        if tg:
            cur.execute("""
                SELECT target_id, port, az, health_state, health_reason
                FROM aws_lb_tg_targets
                WHERE tg_arn = %s
                ORDER BY health_state, target_id
            """, (tg_arn,))
            targets = cur.fetchall()

        cur.close(); conn.close()
        return {"tg": tg, "targets": targets}

    # ── Step 6b: CLB instances ──────────────────────────────────────────
    def resolve_clb_instances(lb_name: str, account_name: str) -> list:
        conn = _conn()
        cur  = conn.cursor(dictionary=True)
        cur.execute("""
            SELECT instance_id, state, reason_code, description
            FROM aws_clb_instances
            WHERE lb_name = %s AND account_name = %s
            ORDER BY state, instance_id
        """, (lb_name, account_name))
        rows = cur.fetchall()
        cur.close(); conn.close()
        return rows

    # ── Lookup EC2 instance name from aws_inventory_resources ───────────
    def resolve_instance_name(instance_id: str) -> str:
        try:
            conn = _conn()
            cur  = conn.cursor(dictionary=True)
            cur.execute("""
                SELECT name FROM aws_inventory_resources
                WHERE aws_id = %s LIMIT 1
            """, (instance_id,))
            row = cur.fetchone()
            cur.close(); conn.close()
            return row["name"] if row else instance_id
        except Exception:
            return instance_id

    # ════════════════════════════════════════════════════════════════════
    # WALK THE CHAIN
    # ════════════════════════════════════════════════════════════════════

    def walk(name: str, depth: int = 0):
        if depth > 4:
            hops.append({"type": "note", "label": "Max depth reached",
                         "detail": {"reason": "Stopped after 4 redirect hops."}})
            return

        # ── DNS ──────────────────────────────────────────────────────────
        dns_rows = resolve_dns(name)
        if not dns_rows:
            if depth == 0:
                hops.append({"type": "note", "label": "Not found in DNS",
                             "detail": {"hostname": name,
                                        "reason": "No DNS record found in aws_domains."}})
            return

        for dns in dns_rows:
            hops.append({
                "type":    "dns",
                "label":   dns["record_name"],
                "detail":  {
                    "record_name":   dns["record_name"],
                    "record_type":   dns["record_type"],
                    "record_value":  dns["record_value"] or dns.get("record_alias_name", ""),
                    "hosted_zone":   dns["hosted_zone_name"],
                },
                "account": dns["account_name"],
            })

        # Use the first/most-recent row for chain resolution
        dns       = dns_rows[0]
        rec_value = (dns["record_value"] or dns.get("record_alias_name") or "").strip()

        # ── Direct ELB CNAME ─────────────────────────────────────────────
        if ".elb.amazonaws.com" in rec_value or ".elb." in rec_value:
            walk_elb(rec_value, name, depth + 1)
            return

        # ── Another CNAME — recurse ──────────────────────────────────────
        if dns["record_type"] in ("CNAME", "A", "ALIAS"):
            walk(rec_value, depth + 1)

    def walk_elb(elb_dns: str, queried_hostname: str, depth: int):
        elb_dns = elb_dns.strip().rstrip('.')

        if elb_dns in seen_elbs:
            hops.append({"type": "note", "label": "Loop detected",
                         "detail": {"elb_dns": elb_dns}})
            return
        seen_elbs.add(elb_dns)

        lb = resolve_elb(elb_dns)
        if not lb:
            hops.append({
                "type":  "note",
                "label": "ELB not yet collected",
                "detail": {
                    "dns_name": elb_dns,
                    "reason":   "This load balancer isn't in the inventory yet. "
                                "Run collect_lb.py to populate it.",
                },
            })
            return

        hops.append({
            "type":    "elb",
            "label":   lb["lb_name"],
            "detail":  {
                "lb_name":  lb["lb_name"],
                "lb_type":  lb["lb_type"],
                "dns_name": lb["dns_name"],
                "scheme":   lb["scheme"],
                "state":    lb["state"],
                "vpc_id":   lb["vpc_id"],
            },
            "account": lb["account_name"],
            "region":  lb["region"],
        })

        lb_type = lb["lb_type"]

        # ── Classic LB ───────────────────────────────────────────────────
        if lb_type == "classic":
            listeners = resolve_listeners(lb["lb_arn"])
            for lst in listeners:
                hops.append({
                    "type":  "clb_listener",
                    "label": f"{lst['protocol']}:{lst['port']}",
                    "detail": {
                        "protocol":       lst["protocol"],
                        "port":           lst["port"],
                        "action":         lst.get("default_action_target", ""),
                    },
                })
            instances = resolve_clb_instances(lb["lb_name"], lb["account_name"])
            for inst in instances:
                name_label = resolve_instance_name(inst["instance_id"])
                hops.append({
                    "type":    "target",
                    "label":   name_label,
                    "detail":  {
                        "instance_id":  inst["instance_id"],
                        "instance_name": name_label,
                        "health_state": inst.get("state", ""),
                        "reason_code":  inst.get("reason_code", ""),
                        "description":  inst.get("description", ""),
                        "az":           inst.get("az", ""),
                    },
                    "account": lb["account_name"],
                    "region":  lb["region"],
                })
            return

        # ── NLB ──────────────────────────────────────────────────────────
        if lb_type == "network":
            listeners = resolve_listeners(lb["lb_arn"])
            for lst in listeners:
                hops.append({
                    "type":  "nlb_listener",
                    "label": f"{lst['protocol']}:{lst['port']}",
                    "detail": {
                        "protocol": lst["protocol"],
                        "port":     lst["port"],
                        "action":   lst.get("default_action_type", ""),
                        "target":   lst.get("default_action_target", ""),
                    },
                })
                tg_arn = lst.get("default_action_target", "")
                if tg_arn and tg_arn.startswith("arn:"):
                    _append_tg(tg_arn, lb["account_name"], lb["region"])
            return

        # ── ALB ──────────────────────────────────────────────────────────
        listeners = resolve_listeners(lb["lb_arn"])
        # Show the HTTPS:443 listener summary (or all if no 443)
        https_listener = next(
            (l for l in listeners if l.get("port") == 443), None
        )
        http_listener  = next(
            (l for l in listeners if l.get("port") == 80), None
        )

        if http_listener and http_listener.get("default_action_type") == "redirect":
            hops.append({
                "type":  "alb_listener",
                "label": "HTTP:80",
                "detail": {
                    "protocol": "HTTP",
                    "port":     80,
                    "action":   "redirect → HTTPS",
                },
            })

        if https_listener:
            hops.append({
                "type":  "alb_listener",
                "label": "HTTPS:443",
                "detail": {
                    "protocol":      "HTTPS",
                    "port":          443,
                    "default_action": https_listener.get("default_action_type", ""),
                    "default_target": https_listener.get("default_action_target", ""),
                },
            })

            # Rule matching against the queried hostname
            rule = match_alb_rule(lb["lb_arn"], queried_hostname)
            if rule:
                cond_vals = []
                try:
                    cond_vals = json.loads(rule["condition_values"] or "[]")
                except Exception:
                    pass

                hops.append({
                    "type":  "alb_rule",
                    "label": f"Rule priority {rule['priority']}",
                    "detail": {
                        "priority":        rule["priority"],
                        "is_default":      bool(rule["is_default"]),
                        "condition_type":  rule.get("condition_type") or "(default)",
                        "condition_values": cond_vals,
                        "action_type":     rule.get("action_type", ""),
                    },
                })

                atype = rule.get("action_type", "")

                if atype == "redirect":
                    redirect_host  = rule.get("redirect_host") or "#{host}"
                    redirect_path  = rule.get("redirect_path") or "/#{path}"
                    redirect_port  = rule.get("redirect_port") or "443"
                    redirect_proto = rule.get("redirect_protocol") or "HTTPS"
                    redirect_url   = f"{redirect_proto}://{redirect_host}:{redirect_port}{redirect_path}"
                    hops.append({
                        "type":  "alb_redirect",
                        "label": f"301 → {redirect_host}",
                        "detail": {
                            "redirect_url":      redirect_url,
                            "redirect_host":     redirect_host,
                            "redirect_protocol": redirect_proto,
                            "redirect_port":     redirect_port,
                            "redirect_path":     redirect_path,
                            "status_code":       rule.get("redirect_status", "HTTP_301"),
                        },
                    })
                    # Follow the redirect if the target is a known hostname
                    if redirect_host not in ("#{host}", None, ""):
                        walk(redirect_host, depth + 1)

                elif atype == "forward":
                    tg_arn = rule.get("action_target", "")
                    if tg_arn and tg_arn.startswith("arn:"):
                        _append_tg(tg_arn, lb["account_name"], lb["region"])

                elif atype == "fixed-response":
                    hops.append({
                        "type":  "note",
                        "label": f"Fixed response {rule.get('fixed_status', '')}",
                        "detail": {"status": rule.get("fixed_status", "")},
                    })

            else:
                # No rules collected yet — show default action
                da_type   = https_listener.get("default_action_type", "")
                da_target = https_listener.get("default_action_target", "")
                if da_type == "forward" and da_target and da_target.startswith("arn:"):
                    _append_tg(da_target, lb["account_name"], lb["region"])

    def _append_tg(tg_arn: str, account_name: str, region: str):
        result = resolve_tg(tg_arn)
        tg      = result["tg"]
        targets = result["targets"]

        if not tg:
            hops.append({"type": "note", "label": "Target group not found",
                         "detail": {"tg_arn": tg_arn}})
            return

        hops.append({
            "type":    "target_group",
            "label":   tg["tg_name"],
            "detail":  {
                "tg_name":          tg["tg_name"],
                "target_type":      tg["target_type"],
                "protocol":         tg["protocol"],
                "port":             tg["port"],
                "health_check_path": tg.get("health_check_path", ""),
                "target_count":     len(targets),
            },
            "account": tg["account_name"],
            "region":  tg["region"],
        })

        for t in targets:
            instance_id   = t["target_id"]
            instance_name = resolve_instance_name(instance_id) if not instance_id.startswith("arn:") else instance_id
            hops.append({
                "type":    "target",
                "label":   instance_name,
                "detail":  {
                    "instance_id":   instance_id,
                    "instance_name": instance_name,
                    "port":          t.get("port"),
                    "az":            t.get("az", ""),
                    "health_state":  t.get("health_state", ""),
                    "health_reason": t.get("health_reason", ""),
                },
                "account": account_name,
                "region":  region,
            })

    # Kick off the walk
    if lb_name:
        conn = _conn()
        cur  = conn.cursor(dictionary=True)
        cur.execute(
            "SELECT dns_name FROM aws_load_balancers "
            "WHERE lb_name = %s AND account_name = %s AND region = %s LIMIT 1",
            (lb_name, account, region),
        )
        row = cur.fetchone()
        cur.close(); conn.close()
        if row and row["dns_name"]:
            walk_elb(row["dns_name"], row["dns_name"], 1)
        else:
            hops.append({"type": "note", "label": "ELB not yet collected",
                         "detail": {"reason": "Load balancer not in aws_load_balancers. "
                                               "Run collect_lb.py to populate it."}})
    else:
        walk(hostname)

    return {"hostname": hostname, "hops": hops}


@app.route("/api/trace")
@api_login_required
def api_trace():
    hostname = request.args.get("hostname", "").strip().lower().rstrip('.')
    if not hostname or len(hostname) < 3:
        return jsonify({"error": "hostname required"}), 400
    lb_name = request.args.get("lb_name", "").strip()
    account = request.args.get("account", "").strip()
    region  = request.args.get("region", "").strip()
    try:
        result = trace_resolve(hostname, lb_name, account, region)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

if __name__ == "__main__":
    app.run(debug=False, host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", "5000")))
