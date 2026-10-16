import pytest

import config_loader
from conftest import SAMPLE_CONFIG


@pytest.fixture
def cfg_path(tmp_path):
    p = tmp_path / "config.ini"
    p.write_text(SAMPLE_CONFIG)
    return str(p)


def test_db_config(cfg_path):
    db = config_loader.get_db_config(cfg_path)
    assert db == {
        "host": "127.0.0.1",
        "port": 3306,
        "user": "tester",
        "password": "not-a-real-password",
        "database": "aws_inventory",
    }


def test_accounts_parsed(cfg_path):
    accounts = {a["name"]: a for a in config_loader.get_accounts(cfg_path)}
    assert set(accounts) == {"central", "prod"}
    assert accounts["central"]["regions"] == ["us-east-1", "us-west-2"]
    assert accounts["central"]["access_key"].startswith("AKIA")
    assert accounts["prod"]["role_arn"].endswith("InventoryReadOnly")


def test_collect_flag_defaults_and_overrides(cfg_path):
    accounts = {a["name"]: a for a in config_loader.get_accounts(cfg_path)}
    # defaults: s3/ecs/cloudfront on, eks off
    assert accounts["central"]["s3_collect"] is True
    assert accounts["central"]["ecs_collect"] is True
    assert accounts["central"]["cloudfront_collect"] is True
    assert accounts["central"]["eks_collect"] is False
    # overrides
    assert accounts["prod"]["eks_collect"] is True
    assert accounts["prod"]["s3_collect"] is False


def test_account_without_credentials_is_rejected(tmp_path):
    p = tmp_path / "bad.ini"
    p.write_text("[database]\nuser=a\npassword=b\ndatabase=c\n[account:x]\nregions=us-east-1\n")
    with pytest.raises(ValueError, match="needs one of"):
        config_loader.get_accounts(str(p))


def test_no_accounts_is_rejected(tmp_path):
    p = tmp_path / "empty.ini"
    p.write_text("[database]\nuser=a\npassword=b\ndatabase=c\n")
    with pytest.raises(ValueError, match="No \\[account:NAME\\]"):
        config_loader.get_accounts(str(p))


def test_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        config_loader.load_config(str(tmp_path / "nope.ini"))


def test_identity_center_optional(cfg_path):
    assert config_loader.get_identity_center_config(cfg_path) is None


def test_identity_center_parsed(tmp_path):
    p = tmp_path / "ic.ini"
    p.write_text(SAMPLE_CONFIG + "\n[identity_center]\ninstance_arn = arn:aws:sso:::instance/ssoins-1\n"
                 "identity_store_id = d-123\nprofile = demo\n")
    ic = config_loader.get_identity_center_config(str(p))
    assert ic["identity_store_id"] == "d-123"
    assert ic["profile"] == "demo"
