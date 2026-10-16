"""
Table definitions for collectors that don't define their own DDL, plus the
sync_jobs table used by the web UI's "sync now" feature.

Usage:  from schema import ensure_tables;  ensure_tables(cur, "sg")
All statements are CREATE TABLE IF NOT EXISTS, so they are safe to run every time.
The database itself is created by scripts/collect_inventory.py (run it first).
"""

_T = "ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"


def _tags(table: str) -> str:
    return f"""
CREATE TABLE IF NOT EXISTS `{table}` (
    `id`           INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `aws_id`       VARCHAR(255) NOT NULL,
    `account_name` VARCHAR(255) NOT NULL,
    `tag_key`      VARCHAR(255) NOT NULL,
    `tag_value`    TEXT,
    `last_seen`    DATETIME     NOT NULL,
    UNIQUE KEY `uq_tag` (`aws_id`, `account_name`, `tag_key`)
) {_T};"""


SCHEMA = {
    "sync": [f"""
CREATE TABLE IF NOT EXISTS `sync_jobs` (
    `id`               INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `script`           VARCHAR(100) NOT NULL,
    `account_name`     VARCHAR(255) NULL,
    `triggered_by`     VARCHAR(255) NULL,
    `triggered_at`     DATETIME     NOT NULL,
    `finished_at`      DATETIME     NULL,
    `status`           VARCHAR(20)  NOT NULL,
    `cooldown_minutes` INT          NOT NULL DEFAULT 30,
    INDEX `idx_script_time` (`script`, `triggered_at`)
) {_T};"""],

    "sg": [f"""
CREATE TABLE IF NOT EXISTS `aws_security_groups` (
    `id`               INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `sg_id`            VARCHAR(64)  NOT NULL,
    `sg_name`          VARCHAR(255),
    `description`      TEXT,
    `vpc_id`           VARCHAR(64),
    `account_name`     VARCHAR(255) NOT NULL,
    `region`           VARCHAR(32)  NOT NULL,
    `direction`        VARCHAR(16)  NOT NULL,
    `protocol`         VARCHAR(16),
    `from_port`        INT NULL,
    `to_port`          INT NULL,
    `target`           VARCHAR(255) NOT NULL DEFAULT '',
    `target_type`      VARCHAR(16),
    `description_rule` TEXT,
    `last_seen`        DATETIME     NOT NULL,
    UNIQUE KEY `uq_rule` (`sg_id`, `account_name`, `region`, `direction`,
                          `protocol`, `from_port`, `to_port`, `target`),
    INDEX `idx_sg_id`   (`sg_id`),
    INDEX `idx_account` (`account_name`),
    INDEX `idx_target`  (`target`)
) {_T};""", _tags("aws_sg_tags")],

    "network": [
        _tags("aws_subnet_tags"),
        f"""
CREATE TABLE IF NOT EXISTS `aws_subnets` (
    `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `subnet_id` VARCHAR(64) NOT NULL, `name` VARCHAR(255), `vpc_id` VARCHAR(64),
    `cidr_block` VARCHAR(64), `availability_zone` VARCHAR(32), `available_ips` INT,
    `state` VARCHAR(32), `map_public_ip` TINYINT(1), `default_for_az` TINYINT(1),
    `account_name` VARCHAR(255) NOT NULL, `region` VARCHAR(32) NOT NULL,
    `last_seen` DATETIME NOT NULL,
    UNIQUE KEY `uq_subnet` (`subnet_id`, `account_name`, `region`),
    INDEX `idx_vpc` (`vpc_id`)
) {_T};""", f"""
CREATE TABLE IF NOT EXISTS `aws_route_tables` (
    `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `route_table_id` VARCHAR(64) NOT NULL, `name` VARCHAR(255), `vpc_id` VARCHAR(64),
    `associated_subnets` TEXT, `main` TINYINT(1),
    `destination` VARCHAR(255) NOT NULL DEFAULT '', `target` VARCHAR(255),
    `target_type` VARCHAR(32), `state` VARCHAR(32),
    `account_name` VARCHAR(255) NOT NULL, `region` VARCHAR(32) NOT NULL,
    `last_seen` DATETIME NOT NULL,
    UNIQUE KEY `uq_route` (`route_table_id`, `destination`, `account_name`, `region`),
    INDEX `idx_vpc` (`vpc_id`)
) {_T};""", f"""
CREATE TABLE IF NOT EXISTS `aws_network_acls` (
    `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `nacl_id` VARCHAR(64) NOT NULL, `name` VARCHAR(255), `vpc_id` VARCHAR(64),
    `associated_subnets` TEXT, `is_default` TINYINT(1),
    `rule_number` INT NOT NULL, `direction` VARCHAR(16) NOT NULL,
    `protocol` VARCHAR(16), `from_port` INT NULL, `to_port` INT NULL,
    `cidr_block` VARCHAR(64), `action` VARCHAR(16),
    `account_name` VARCHAR(255) NOT NULL, `region` VARCHAR(32) NOT NULL,
    `last_seen` DATETIME NOT NULL,
    UNIQUE KEY `uq_nacl_rule` (`nacl_id`, `rule_number`, `direction`, `account_name`, `region`),
    INDEX `idx_vpc` (`vpc_id`)
) {_T};""", f"""
CREATE TABLE IF NOT EXISTS `aws_nat_gateways` (
    `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `nat_gw_id` VARCHAR(64) NOT NULL, `name` VARCHAR(255), `vpc_id` VARCHAR(64),
    `subnet_id` VARCHAR(64), `state` VARCHAR(32), `type` VARCHAR(32),
    `public_ip` VARCHAR(64), `private_ip` VARCHAR(64),
    `account_name` VARCHAR(255) NOT NULL, `region` VARCHAR(32) NOT NULL,
    `last_seen` DATETIME NOT NULL,
    UNIQUE KEY `uq_nat` (`nat_gw_id`, `account_name`, `region`)
) {_T};""", f"""
CREATE TABLE IF NOT EXISTS `aws_internet_gateways` (
    `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `igw_id` VARCHAR(64) NOT NULL, `name` VARCHAR(255), `vpc_id` VARCHAR(64),
    `state` VARCHAR(32),
    `account_name` VARCHAR(255) NOT NULL, `region` VARCHAR(32) NOT NULL,
    `last_seen` DATETIME NOT NULL,
    UNIQUE KEY `uq_igw` (`igw_id`, `account_name`, `region`)
) {_T};""", f"""
CREATE TABLE IF NOT EXISTS `aws_vpc_peering` (
    `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `peering_id` VARCHAR(64) NOT NULL, `name` VARCHAR(255), `status` VARCHAR(64),
    `requester_vpc_id` VARCHAR(64), `requester_cidr` VARCHAR(255),
    `requester_account` VARCHAR(64), `requester_region` VARCHAR(32),
    `accepter_vpc_id` VARCHAR(64), `accepter_cidr` VARCHAR(255),
    `accepter_account` VARCHAR(64), `accepter_region` VARCHAR(32),
    `account_name` VARCHAR(255) NOT NULL, `region` VARCHAR(32) NOT NULL,
    `last_seen` DATETIME NOT NULL,
    UNIQUE KEY `uq_peering` (`peering_id`, `account_name`, `region`)
) {_T};""", f"""
CREATE TABLE IF NOT EXISTS `aws_transit_gateways` (
    `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `tgw_id` VARCHAR(64) NOT NULL, `name` VARCHAR(255), `description` TEXT,
    `state` VARCHAR(32),
    `account_name` VARCHAR(255) NOT NULL, `region` VARCHAR(32) NOT NULL,
    `last_seen` DATETIME NOT NULL,
    UNIQUE KEY `uq_tgw` (`tgw_id`, `account_name`, `region`)
) {_T};""", f"""
CREATE TABLE IF NOT EXISTS `aws_tgw_attachments` (
    `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `attachment_id` VARCHAR(64) NOT NULL, `tgw_id` VARCHAR(64) NOT NULL,
    `resource_type` VARCHAR(64), `resource_id` VARCHAR(255),
    `resource_account` VARCHAR(64), `state` VARCHAR(32),
    `account_name` VARCHAR(255) NOT NULL, `region` VARCHAR(32) NOT NULL,
    `last_seen` DATETIME NOT NULL,
    UNIQUE KEY `uq_attachment` (`attachment_id`, `tgw_id`, `account_name`, `region`)
) {_T};"""],

    "iam": [f"""
CREATE TABLE IF NOT EXISTS `aws_iam_principals` (
    `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `principal_id` VARCHAR(128) NOT NULL, `principal_name` VARCHAR(255),
    `principal_type` VARCHAR(16) NOT NULL, `arn` VARCHAR(512),
    `account_name` VARCHAR(255) NOT NULL,
    `created_at` DATETIME NULL, `last_used` DATETIME NULL,
    `path` VARCHAR(512), `extra` LONGTEXT, `last_seen` DATETIME NOT NULL,
    UNIQUE KEY `uq_principal` (`principal_id`, `account_name`),
    INDEX `idx_type` (`principal_type`),
    INDEX `idx_name` (`principal_name`)
) {_T};""", f"""
CREATE TABLE IF NOT EXISTS `aws_iam_policies` (
    `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `principal_id` VARCHAR(128) NOT NULL, `principal_name` VARCHAR(255),
    `principal_type` VARCHAR(16), `account_name` VARCHAR(255) NOT NULL,
    `policy_name` VARCHAR(255) NOT NULL, `policy_arn` VARCHAR(512),
    `policy_type` VARCHAR(16) NOT NULL, `scope` VARCHAR(16),
    `last_seen` DATETIME NOT NULL,
    UNIQUE KEY `uq_policy` (`principal_id`, `account_name`, `policy_name`, `policy_type`)
) {_T};""", f"""
CREATE TABLE IF NOT EXISTS `aws_iam_policy_statements` (
    `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `policy_name` VARCHAR(255), `policy_arn` VARCHAR(512), `policy_type` VARCHAR(16),
    `principal_id` VARCHAR(128), `account_name` VARCHAR(255) NOT NULL,
    `effect` VARCHAR(16), `actions` MEDIUMTEXT, `resources` MEDIUMTEXT,
    `conditions` MEDIUMTEXT, `sid` VARCHAR(255), `last_seen` DATETIME NOT NULL,
    INDEX `idx_principal` (`principal_id`, `account_name`, `policy_name`)
) {_T};""", f"""
CREATE TABLE IF NOT EXISTS `aws_iam_trust_relationships` (
    `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `role_id` VARCHAR(128) NOT NULL, `role_name` VARCHAR(255),
    `account_name` VARCHAR(255) NOT NULL, `trusted_type` VARCHAR(64),
    `trusted_arn` TEXT, `actions` TEXT, `conditions` MEDIUMTEXT,
    `last_seen` DATETIME NOT NULL,
    INDEX `idx_role` (`role_id`, `account_name`)
) {_T};"""],

    "sso": [f"""
CREATE TABLE IF NOT EXISTS `sso_users` (
    `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `user_id` VARCHAR(128) NOT NULL, `username` VARCHAR(255),
    `display_name` VARCHAR(255), `email` VARCHAR(255),
    `account_name` VARCHAR(255) NOT NULL, `identity_store_id` VARCHAR(64),
    `last_seen` DATETIME NOT NULL,
    UNIQUE KEY `uq_user` (`user_id`, `account_name`)
) {_T};""", f"""
CREATE TABLE IF NOT EXISTS `sso_groups` (
    `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `group_id` VARCHAR(128) NOT NULL, `group_name` VARCHAR(255), `description` TEXT,
    `account_name` VARCHAR(255) NOT NULL, `identity_store_id` VARCHAR(64),
    `last_seen` DATETIME NOT NULL,
    UNIQUE KEY `uq_group` (`group_id`, `account_name`)
) {_T};""", f"""
CREATE TABLE IF NOT EXISTS `sso_group_memberships` (
    `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `user_id` VARCHAR(128) NOT NULL, `username` VARCHAR(255),
    `group_id` VARCHAR(128) NOT NULL, `group_name` VARCHAR(255),
    `account_name` VARCHAR(255) NOT NULL, `last_seen` DATETIME NOT NULL,
    UNIQUE KEY `uq_membership` (`user_id`, `group_id`, `account_name`)
) {_T};""", f"""
CREATE TABLE IF NOT EXISTS `sso_permission_sets` (
    `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `permission_set_arn` VARCHAR(255) NOT NULL, `name` VARCHAR(255), `description` TEXT,
    `session_duration` VARCHAR(32), `account_name` VARCHAR(255) NOT NULL,
    `instance_arn` VARCHAR(255), `last_seen` DATETIME NOT NULL,
    UNIQUE KEY `uq_ps` (`permission_set_arn`, `account_name`)
) {_T};""", f"""
CREATE TABLE IF NOT EXISTS `sso_permission_set_policies` (
    `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `permission_set_arn` VARCHAR(160) NOT NULL, `permission_set_name` VARCHAR(255),
    `policy_name` VARCHAR(128) NOT NULL, `policy_arn` VARCHAR(512),
    `policy_type` VARCHAR(32) NOT NULL, `policy_document` MEDIUMTEXT,
    `account_name` VARCHAR(255) NOT NULL, `last_seen` DATETIME NOT NULL,
    UNIQUE KEY `uq_ps_policy` (`permission_set_arn`, `policy_name`, `policy_type`, `account_name`)
) {_T};""", f"""
CREATE TABLE IF NOT EXISTS `sso_account_assignments` (
    `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `instance_arn` VARCHAR(255), `permission_set_arn` VARCHAR(255) NOT NULL,
    `permission_set_name` VARCHAR(255), `target_account_id` VARCHAR(32) NOT NULL,
    `target_account_name` VARCHAR(255), `principal_type` VARCHAR(16) NOT NULL,
    `principal_id` VARCHAR(128) NOT NULL, `principal_name` VARCHAR(255),
    `account_name` VARCHAR(255) NOT NULL, `last_seen` DATETIME NOT NULL,
    UNIQUE KEY `uq_assignment` (`permission_set_arn`, `target_account_id`,
                                `principal_type`, `principal_id`, `account_name`)
) {_T};"""],
}


def ensure_tables(cur, group: str) -> None:
    """Create the tables for one collector group ('sg', 'network', 'iam', 'sso', 'sync')."""
    for ddl in SCHEMA[group]:
        cur.execute(ddl)
