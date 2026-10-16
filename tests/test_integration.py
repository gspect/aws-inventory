"""
End-to-end test against a real MySQL database, using the demo data.

Skipped unless AWS_INVENTORY_INTEGRATION=1. It WIPES the database named in the
config file (via demo/seed.py), so only point it at a throwaway database:

    AWS_INVENTORY_INTEGRATION=1 AWS_INVENTORY_CONFIG=/path/to/test-config.ini pytest tests/test_integration.py
"""
import importlib
import os
import subprocess
import sys

import pytest

from conftest import ROOT

pytestmark = pytest.mark.skipif(
    os.environ.get("AWS_INVENTORY_INTEGRATION") != "1",
    reason="set AWS_INVENTORY_INTEGRATION=1 (and AWS_INVENTORY_CONFIG) to run against a real MySQL",
)

PAGES = ["", "sg", "iam", "network", "sso", "rds", "messaging", "s3", "efs", "ecs", "eks", "cloudfront", "lambda"]


@pytest.fixture(scope="module")
def client():
    env = dict(os.environ)
    for script in ("create_tables.py", "seed.py"):
        subprocess.run([sys.executable, os.path.join(ROOT, "demo", script)], check=True, env=env, cwd=ROOT)
    os.environ["DISABLE_AUTH"] = "1"
    os.environ["FLASK_SECRET_KEY"] = "test"
    for m in ("app", "okta_auth", "config_loader", "schema"):
        sys.modules.pop(m, None)
    module = importlib.import_module("app")
    module.app.config["TESTING"] = True
    return module.app.test_client()


def get(client, path):
    return client.get("/aws-inventory/" + path)


@pytest.mark.parametrize("page", PAGES)
def test_page_renders(client, page):
    resp = get(client, page)
    assert resp.status_code == 200
    assert b"AWS Inventory" in resp.data


def test_search_finds_dns_and_load_balancer(client):
    html = get(client, "?q=app.example.com").data.decode()
    assert "app.example.com." in html
    assert "prod-public-alb" in html


def test_security_groups_page_lists_demo_groups(client):
    html = get(client, "sg?q=production").data.decode()
    assert "production-alb" in html


def test_s3_page_lists_buckets(client):
    html = get(client, "s3").data.decode()
    assert "acme-prod-assets" in html and "acme-terraform-state" in html


def test_eks_page_lists_clusters(client):
    html = get(client, "eks").data.decode()
    assert "prod-cluster" in html and "staging-cluster" in html


def test_stats_bar_counts(client):
    html = get(client, "").data.decode()
    assert "ACCOUNTS" in html.upper()


def test_trace_follows_dns_to_instances(client):
    data = get(client, "api/trace?hostname=app.example.com").get_json()
    types = [h["type"] for h in data["hops"]]
    assert types[0] == "dns"
    assert "elb" in types and "alb_rule" in types and "target_group" in types
    targets = [h for h in data["hops"] if h["type"] == "target"]
    assert len(targets) == 4
    assert {h["detail"]["health_state"] for h in targets} == {"healthy", "unhealthy"}


def test_trace_unknown_hostname_is_graceful(client):
    data = get(client, "api/trace?hostname=nothing.example.com").get_json()
    assert data["hops"][-1]["type"] == "note"


def test_sg_compare_dedupes_and_returns_rules(client):
    import mysql.connector
    from config_loader import get_db_config
    conn = mysql.connector.connect(**get_db_config())
    cur = conn.cursor()
    cur.execute("SELECT DISTINCT sg_id, account_name FROM aws_security_groups WHERE account_name='acme-production' LIMIT 2")
    pairs = cur.fetchall()
    conn.close()
    param = ",".join(f"{sg}:{acct}" for sg, acct in pairs)
    resp = get(client, f"sg/compare?sgs={param}")
    assert resp.status_code == 200
    assert resp.get_json()["rules"]
