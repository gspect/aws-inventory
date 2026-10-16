"""Static checks on schema.py (no database needed)."""
import re

import schema

# MySQL/InnoDB limit for a single index, with utf8mb4 (4 bytes per character)
MAX_KEY_BYTES = 3072
BYTES = {"INT": 4, "DATETIME": 5, "TINYINT": 1, "SMALLINT": 2}


class FakeCursor:
    def __init__(self):
        self.statements = []

    def execute(self, sql):
        self.statements.append(sql)


def all_ddl():
    return [ddl for group in schema.SCHEMA.values() for ddl in group]


def column_widths(ddl):
    widths = {}
    for name, typ, size in re.findall(r"`(\w+)`\s+(VARCHAR|INT|DATETIME|TINYINT|SMALLINT)(?:\((\d+)\))?", ddl):
        widths[name] = int(size) * 4 if typ == "VARCHAR" else BYTES[typ]
    return widths


def test_expected_groups():
    assert set(schema.SCHEMA) == {"sync", "sg", "network", "iam", "sso"}


def test_every_statement_is_idempotent_create():
    for ddl in all_ddl():
        assert ddl.strip().startswith("CREATE TABLE IF NOT EXISTS"), ddl[:60]
        assert ddl.strip().endswith(";")


def test_ensure_tables_runs_every_statement_in_group():
    for group, ddls in schema.SCHEMA.items():
        cur = FakeCursor()
        schema.ensure_tables(cur, group)
        assert cur.statements == ddls


def test_unknown_group_raises():
    import pytest
    with pytest.raises(KeyError):
        schema.ensure_tables(FakeCursor(), "nope")


def test_index_keys_fit_within_mysql_limit():
    """Regression test: a too-long unique key makes CREATE TABLE fail on MySQL."""
    for ddl in all_ddl():
        widths = column_widths(ddl)
        table = re.search(r"`(\w+)` \(", ddl).group(1)
        for key in re.findall(r"(?:UNIQUE KEY|INDEX|KEY)\s+`\w+`\s*\(([^)]*(?:\([^)]*\)[^)]*)*)\)", ddl):
            cols = re.findall(r"`(\w+)`", key)
            total = sum(widths[c] for c in cols)
            assert total <= MAX_KEY_BYTES, f"{table}: key ({', '.join(cols)}) is {total} bytes"


def test_tables_have_no_duplicate_names():
    names = [re.search(r"`(\w+)` \(", d).group(1) for d in all_ddl()]
    assert len(names) == len(set(names))
