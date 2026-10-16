import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

SAMPLE_CONFIG = """
[database]
host = 127.0.0.1
port = 3306
database = aws_inventory
user = tester
password = not-a-real-password

[account:central]
access_key = AKIAEXAMPLEEXAMPLE
secret_key = not-a-real-secret
regions = us-east-1, us-west-2

[account:prod]
role_arn = arn:aws:iam::123456789012:role/InventoryReadOnly
regions = eu-west-1
eks_collect = true
s3_collect = false
"""
