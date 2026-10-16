"""Create every table the app uses (for the demo / a fresh install without AWS access)."""
import glob
import os
import re
import sys

import mysql.connector

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)
from config_loader import get_db_config
from schema import SCHEMA

cfg = get_db_config()
conn = mysql.connector.connect(**cfg)
cur = conn.cursor()

n = 0
for path in sorted(glob.glob(os.path.join(ROOT, "scripts", "collect_*.py"))):
    src = open(path, encoding="utf-8").read()
    for m in re.finditer(r"CREATE TABLE IF NOT EXISTS .*?;\s*(?=\"\"\")", src, re.S):
        for stmt in re.split(r";\s*(?=CREATE TABLE|\Z)", m.group(0)):
            if not stmt.strip():
                continue
            if "{" in stmt:
                print("skip (templated):", os.path.basename(path))
                continue
            try:
                cur.execute(stmt)
                n += 1
            except mysql.connector.Error as e:
                print("FAILED in", os.path.basename(path), "-", stmt.strip().splitlines()[0])
                print("   ", e)
                raise SystemExit(1)

for group in SCHEMA:
    for ddl in SCHEMA[group]:
        try:
            cur.execute(ddl)
            n += 1
        except mysql.connector.Error as e:
            print("FAILED in schema.py group", group, "-", ddl.strip().splitlines()[0])
            print("   ", e)
            raise SystemExit(1)

conn.commit()
print(f"{n} CREATE TABLE statements OK")
cur.execute("SHOW TABLES")
print(len(cur.fetchall()), "tables in database")
