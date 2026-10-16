"""
Shared config loader for all AWS inventory scripts and the Flask app.
Reads database credentials and AWS account definitions from config.ini.
"""

import configparser
import os
import boto3

# Always resolve config.ini relative to this file's location
# so scripts can be run from any directory
CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.ini")


def load_config(path: str = CONFIG_PATH) -> configparser.ConfigParser:
    cfg = configparser.ConfigParser()
    read = cfg.read(path)
    if not read:
        raise FileNotFoundError(f"Config file not found: {path}")
    return cfg


def get_db_config(path: str = CONFIG_PATH) -> dict:
    """Return MySQL connection dict."""
    cfg = load_config(path)
    return {
        "host":     cfg.get("database", "host",     fallback="localhost"),
        "port":     cfg.getint("database", "port",  fallback=3306),
        "user":     cfg.get("database", "user"),
        "password": cfg.get("database", "password"),
        "database": cfg.get("database", "database"),
    }


def get_accounts(path: str = CONFIG_PATH) -> list[dict]:
    """
    Return a list of account dicts parsed from config.ini.
    Each dict contains 'name', 'regions', and one of:
      - 'access_key' + 'secret_key'
      - 'profile'
      - 'role_arn'
    """
    cfg      = load_config(path)
    accounts = []

    for section in cfg.sections():
        if not section.startswith("account:"):
            continue

        name    = section.split("account:", 1)[1].strip()
        regions = [
            r.strip()
            for r in cfg.get(section, "regions", fallback="us-west-2").split(",")
        ]
        account = {"name": name, "regions": regions}

        if cfg.has_option(section, "access_key") and cfg.has_option(section, "secret_key"):
            account["access_key"] = cfg.get(section, "access_key").strip()
            account["secret_key"] = cfg.get(section, "secret_key").strip()
        elif cfg.has_option(section, "role_arn"):
            account["role_arn"] = cfg.get(section, "role_arn").strip()
        elif cfg.has_option(section, "profile"):
            account["profile"]  = cfg.get(section, "profile").strip()
        else:
            raise ValueError(
                f"Account '{name}' in config.ini needs one of: "
                f"'access_key'+'secret_key', 'profile', or 'role_arn'"
            )
        account["s3_collect"] = cfg.getboolean(section, "s3_collect", fallback=True)
        account["ecs_collect"] = cfg.getboolean(section, "ecs_collect", fallback=True)
        account["eks_collect"] = cfg.getboolean(section, "eks_collect", fallback=False)
        account["cloudfront_collect"] = cfg.getboolean(section, "cloudfront_collect",  fallback=True)
        accounts.append(account)

    if not accounts:
        raise ValueError("No [account:NAME] sections found in config.ini")

    return accounts


def get_identity_center_config(path: str = CONFIG_PATH) -> dict | None:
    """
    Return Identity Center config dict or None if not configured.
    """
    cfg = load_config(path)
    if not cfg.has_section("identity_center"):
        return None

    account = {
        "instance_arn":      cfg.get("identity_center", "instance_arn").strip(),
        "identity_store_id": cfg.get("identity_center", "identity_store_id").strip(),
    }

    if cfg.has_option("identity_center", "profile"):
        account["profile"] = cfg.get("identity_center", "profile").strip()
    elif cfg.has_option("identity_center", "access_key"):
        account["access_key"] = cfg.get("identity_center", "access_key").strip()
        account["secret_key"] = cfg.get("identity_center", "secret_key").strip()
    elif cfg.has_option("identity_center", "role_arn"):
        account["role_arn"] = cfg.get("identity_center", "role_arn").strip()
    else:
        raise ValueError("identity_center section needs profile, access_key, or role_arn")

    return account


def _get_source_session(cfg: configparser.ConfigParser) -> boto3.Session:
    """
    Return a boto3 session using the first access_key/secret_key account found
    in config.ini. This is used as the source identity when calling STS
    AssumeRole for all role_arn-based accounts.

    Typically this is a central/management account that hosts the read-only IAM user.
    """
    for section in cfg.sections():
        if not section.startswith("account:"):
            continue
        if cfg.has_option(section, "access_key") and cfg.has_option(section, "secret_key"):
            return boto3.Session(
                aws_access_key_id=cfg.get(section, "access_key").strip(),
                aws_secret_access_key=cfg.get(section, "secret_key").strip(),
            )
    raise ValueError(
        "No access_key/secret_key account found in config.ini. "
        "At least one account (e.g. your central/management account) must use access_key/secret_key "
        "to serve as the STS source identity for role assumption."
    )


def get_session(account: dict) -> boto3.Session:
    """
    Return a boto3 session for the given account dict.
    Supports access key, named profile, or role assumption.

    For role_arn accounts, STS AssumeRole is called explicitly using the
    base credentials (the access_key/secret_key account in config.ini),
    rather than relying on whatever ambient credentials exist on the server.
    """
    if "access_key" in account and "secret_key" in account:
        return boto3.Session(
            aws_access_key_id=account["access_key"],
            aws_secret_access_key=account["secret_key"],
        )

    if "profile" in account:
        return boto3.Session(profile_name=account["profile"])

    if "role_arn" in account:
        cfg            = load_config()
        source_session = _get_source_session(cfg)
        sts            = source_session.client("sts")
        resp           = sts.assume_role(
            RoleArn=account["role_arn"],
            RoleSessionName="InventoryScript",
            DurationSeconds=3600,
        )
        c = resp["Credentials"]
        return boto3.Session(
            aws_access_key_id=c["AccessKeyId"],
            aws_secret_access_key=c["SecretAccessKey"],
            aws_session_token=c["SessionToken"],
        )

    raise ValueError(
        f"Account '{account.get('name', '?')}' has no valid auth method in config.ini. "
        "Needs one of: access_key+secret_key, profile, or role_arn."
    )
