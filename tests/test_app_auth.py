"""App behaviour that doesn't need a database: authentication and input validation."""
import importlib
import sys

import pytest

from conftest import SAMPLE_CONFIG

MODULES = ("app", "okta_auth", "config_loader", "schema")


def load_app(monkeypatch, tmp_path, **env):
    cfg = tmp_path / "config.ini"
    cfg.write_text(SAMPLE_CONFIG.replace("3306", "1"))  # port 1: DB unreachable
    monkeypatch.setenv("AWS_INVENTORY_CONFIG", str(cfg))
    for key in ("DISABLE_AUTH", "OKTA_DOMAIN", "OKTA_CLIENT_ID", "OKTA_CLIENT_SECRET", "FLASK_SECRET_KEY"):
        monkeypatch.delenv(key, raising=False)
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    for m in MODULES:
        sys.modules.pop(m, None)
    module = importlib.import_module("app")
    module.app.config["TESTING"] = True
    return module


@pytest.fixture
def auth_off(monkeypatch, tmp_path):
    return load_app(monkeypatch, tmp_path, DISABLE_AUTH="1", FLASK_SECRET_KEY="test").app.test_client()


@pytest.fixture
def auth_on(monkeypatch, tmp_path):
    return load_app(monkeypatch, tmp_path, FLASK_SECRET_KEY="test").app.test_client()


def test_api_requires_login_by_default(auth_on):
    resp = auth_on.get("/aws-inventory/api/accounts")
    assert resp.status_code == 401
    assert resp.get_json()["error"] == "Authentication required"


def test_pages_redirect_to_login_by_default(auth_on):
    resp = auth_on.get("/aws-inventory/sg")
    assert resp.status_code == 302
    assert resp.headers["Location"].endswith("/aws-inventory/auth/login")


def test_login_explains_missing_okta_config(auth_on):
    resp = auth_on.get("/aws-inventory/auth/login")
    assert resp.status_code == 500
    assert b"Okta is not configured" in resp.data


def test_disable_auth_allows_access(auth_off):
    resp = auth_off.get("/aws-inventory/api/accounts")
    assert resp.status_code == 200
    assert resp.get_json() == {"accounts": ["central", "prod"]}


def test_sync_rejects_unknown_script(auth_off):
    resp = auth_off.post("/aws-inventory/api/sync/not_a_script")
    assert resp.status_code == 400
    assert resp.get_json()["error"] == "Unknown script"


def test_sync_rejects_unknown_account(auth_off):
    # collect_iam supports account scoping; an account that isn't in config.ini must be refused
    resp = auth_off.post("/aws-inventory/api/sync/collect_iam", json={"account_name": "does-not-exist"})
    assert resp.status_code == 400
    assert "Unknown account" in resp.get_json()["error"]


def test_trace_requires_hostname(auth_off):
    resp = auth_off.get("/aws-inventory/api/trace?hostname=a")
    assert resp.status_code == 400


def test_random_secret_key_generated_when_unset(monkeypatch, tmp_path):
    module = load_app(monkeypatch, tmp_path, DISABLE_AUTH="1")
    assert module.app.secret_key and module.app.secret_key != "change-this-in-production"
    assert len(module.app.secret_key) >= 32
