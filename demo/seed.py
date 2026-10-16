"""
Fill the database with FAKE demo data so the web UI can be explored (and
screenshotted) without an AWS account.

    python demo/create_tables.py
    python demo/seed.py
    DISABLE_AUTH=1 python app.py

Everything here is invented: accounts, IDs, IPs and hostnames use made-up
values and the reserved example.com / example.net domains.
"""
import json
import os
import random
import sys
from datetime import datetime, timedelta

import mysql.connector

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from config_loader import get_db_config

random.seed(42)
conn = mysql.connector.connect(**get_db_config())
cur = conn.cursor()
NOW = datetime.utcnow().replace(microsecond=0)
TS = NOW.strftime("%Y-%m-%d %H:%M:%S")


def hexid(n=17):
    return "".join(random.choice("0123456789abcdef") for _ in range(n))


def ins(table, **cols):
    names = ", ".join(f"`{c}`" for c in cols)
    marks = ", ".join(["%s"] * len(cols))
    cur.execute(f"INSERT INTO `{table}` ({names}) VALUES ({marks})", list(cols.values()))


# ── wipe previous demo data ────────────────────────────────────────────
cur.execute("SHOW TABLES")
for (t,) in cur.fetchall():
    if t != "sync_jobs":
        cur.execute(f"DELETE FROM `{t}`")

ACCOUNTS = {
    "acme-production": {"region": "us-east-1", "cidr": "10.10", "vpc": "vpc-0a1b2c3d4e5f60001"},
    "acme-staging": {"region": "us-east-1", "cidr": "10.20", "vpc": "vpc-0a1b2c3d4e5f60002"},
    "acme-shared-services": {"region": "us-west-2", "cidr": "10.30", "vpc": "vpc-0a1b2c3d4e5f60003"},
}

# ── security groups ────────────────────────────────────────────────────
SGS = {}  # account -> {key: sg_id}
for acct, a in ACCOUNTS.items():
    SGS[acct] = {k: "sg-" + hexid() for k in ("alb", "web", "db", "bastion")}
    rules = {
        "alb": [("inbound", "tcp", 443, 443, "0.0.0.0/0", "cidr", "HTTPS from the internet"),
                ("inbound", "tcp", 80, 80, "0.0.0.0/0", "cidr", "HTTP (redirects to HTTPS)"),
                ("outbound", "-1", None, None, "0.0.0.0/0", "cidr", "")],
        "web": [("inbound", "tcp", 8080, 8080, SGS[acct]["alb"], "sg", "From the load balancer"),
                ("inbound", "tcp", 22, 22, SGS[acct]["bastion"], "sg", "SSH from bastion"),
                ("outbound", "-1", None, None, "0.0.0.0/0", "cidr", "")],
        "db": [("inbound", "tcp", 5432, 5432, SGS[acct]["web"], "sg", "Postgres from app tier"),
               ("inbound", "tcp", 5432, 5432, a["cidr"] + ".0.0/16", "cidr", "VPC CIDR"),
               ("outbound", "-1", None, None, "0.0.0.0/0", "cidr", "")],
        "bastion": [("inbound", "tcp", 22, 22, "203.0.113.0/24", "cidr", "Office VPN (documentation range)"),
                    ("outbound", "-1", None, None, "0.0.0.0/0", "cidr", "")],
    }
    for key, rs in rules.items():
        for d, proto, fp, tp, target, ttype, desc in rs:
            ins("aws_security_groups", sg_id=SGS[acct][key], sg_name=f"{acct.split('-', 1)[1]}-{key}",
                description=f"{key} tier", vpc_id=a["vpc"], account_name=acct, region=a["region"],
                direction=d, protocol=proto, from_port=fp, to_port=tp, target=target,
                target_type=ttype, description_rule=desc, last_seen=TS)
    for key in SGS[acct]:
        ins("aws_sg_tags", aws_id=SGS[acct][key], account_name=acct, tag_key="Tier",
            tag_value=key, last_seen=TS)

# ── EC2, VPCs ──────────────────────────────────────────────────────────
INSTANCES = {}  # account -> [(id, name, ip)]
for acct, a in ACCOUNTS.items():
    ins("aws_inventory_resources", name=f"{acct}-vpc", aws_id=a["vpc"], ipadd=f"{a['cidr']}.0.0/16",
        account_name=acct, type="vpc", region=a["region"], extra="State=available | Default=False", last_seen=TS)
    INSTANCES[acct] = []
    for i in range(1, 7 if acct != "acme-shared-services" else 3):
        iid = "i-" + hexid()
        ip = f"{a['cidr']}.{random.choice([1, 2])}.{10 + i}"
        name = f"web-{i:02d}" if acct != "acme-shared-services" else ("bastion-01" if i == 1 else "ci-runner-01")
        sg = SGS[acct]["web"] if "web" in name else SGS[acct]["bastion"]
        state = "running" if i != 5 else "stopped"
        ins("aws_inventory_resources", name=name, aws_id=iid, ipadd=ip, account_name=acct, type="ec2",
            region=a["region"], extra=f"State={state} | InstanceType={random.choice(['t3.medium', 'm5.large', 'c5.xlarge'])} | SGs={sg}",
            last_seen=TS)
        ins("aws_resource_tags", aws_id=iid, account_name=acct, tag_key="Environment",
            tag_value=acct.split("-", 1)[1], last_seen=TS)
        ins("aws_resource_tags", aws_id=iid, account_name=acct, tag_key="Owner", tag_value="platform-team", last_seen=TS)
        INSTANCES[acct].append((iid, name, ip))

# ── load balancers, listeners, rules, target groups ────────────────────
LBS = [("acme-production", "prod-public-alb", "application", "internet-facing"),
       ("acme-production", "prod-internal-nlb", "network", "internal"),
       ("acme-staging", "staging-public-alb", "application", "internet-facing")]
LB_DNS = {}
for acct, name, ltype, scheme in LBS:
    a = ACCOUNTS[acct]
    short = "alb" if ltype == "application" else "nlb"
    prefix = "app" if short == "alb" else "net"
    lbid = hexid(16)
    arn = f"arn:aws:elasticloadbalancing:{a['region']}:111111111111:loadbalancer/{prefix}/{name}/{lbid}"
    dns = f"{name}-{random.randint(100000000, 999999999)}.{a['region']}.elb.amazonaws.com"
    LB_DNS[name] = dns
    ins("aws_load_balancers", lb_arn=arn, lb_name=name, lb_type=short, dns_name=dns, scheme=scheme,
        state="active", vpc_id=a["vpc"], account_name=acct, region=a["region"], last_seen=TS)
    ins("aws_inventory_resources", name=name, aws_id=f"{prefix}/{name}/{lbid}",
        ipadd=f"{a['cidr']}.1.5, {a['cidr']}.2.5", account_name=acct, type=short, region=a["region"],
        extra=f"DNS={dns} | Scheme={scheme} | State=active | SGs={SGS[acct]['alb'] if short == 'alb' else ''}", last_seen=TS)

    tg_arn = f"arn:aws:elasticloadbalancing:{a['region']}:111111111111:targetgroup/{name}-tg/{hexid(16)}"
    ins("aws_lb_target_groups", tg_arn=tg_arn, tg_name=f"{name}-tg", target_type="instance",
        protocol="HTTP" if short == "alb" else "TCP", port=8080, vpc_id=a["vpc"],
        health_check_protocol="HTTP", health_check_path="/healthz", health_check_port="traffic-port",
        healthy_threshold=3, unhealthy_threshold=2, lb_arns=json.dumps([arn]),
        account_name=acct, region=a["region"], last_seen=TS)
    for iid, iname, ip in INSTANCES[acct][:4]:
        ins("aws_lb_tg_targets", tg_arn=tg_arn, target_id=iid, port=8080, az=a["region"] + "a",
            health_state="healthy" if iname != "web-04" else "unhealthy",
            health_reason="" if iname != "web-04" else "Target.FailedHealthChecks",
            account_name=acct, region=a["region"], last_seen=TS)

    if short == "alb":
        l443 = f"{arn.replace('loadbalancer/', 'listener/')}/{hexid(16)}"
        l80 = f"{arn.replace('loadbalancer/', 'listener/')}/{hexid(16)}"
        ins("aws_lb_listeners", listener_arn=l443, lb_arn=arn, lb_type="alb", protocol="HTTPS", port=443,
            ssl_policy="ELBSecurityPolicy-TLS13-1-2-2021-06", default_action_type="forward",
            default_action_target=tg_arn, account_name=acct, region=a["region"], last_seen=TS)
        ins("aws_lb_listeners", listener_arn=l80, lb_arn=arn, lb_type="alb", protocol="HTTP", port=80,
            default_action_type="redirect", default_action_target="", account_name=acct,
            region=a["region"], last_seen=TS)
        host = "app.example.com" if acct == "acme-production" else "app.staging.example.com"
        ins("aws_lb_listener_rules", rule_arn=l443 + "/r1", listener_arn=l443, lb_arn=arn, priority="10",
            is_default=0, condition_type="host-header", condition_values=json.dumps([host]),
            action_type="forward", action_target=tg_arn, account_name=acct, region=a["region"], last_seen=TS)
        ins("aws_lb_listener_rules", rule_arn=l80 + "/r1", listener_arn=l80, lb_arn=arn, priority="default",
            is_default=1, action_type="redirect", redirect_host="#{host}", redirect_path="/#{path}",
            redirect_port="443", redirect_protocol="HTTPS", redirect_status="HTTP_301",
            account_name=acct, region=a["region"], last_seen=TS)
    ins("aws_lb_tags", aws_id=arn, aws_id_type="lb", account_name=acct, tag_key="Environment",
        tag_value=acct.split("-", 1)[1], last_seen=TS)

# ── DNS ────────────────────────────────────────────────────────────────
def dns(zone, rname, rtype, value, acct, alias=None, ttl=300):
    ins("aws_domains", hosted_zone_name=zone, hosted_zone_id="Z" + hexid(12).upper(), record_name=rname,
        record_type=rtype, record_alias_name=alias, record_value=value, record_ttl=ttl,
        account_name=acct, last_seen=TS)

dns("example.com.", "app.example.com.", "A", LB_DNS["prod-public-alb"], "acme-production", alias=LB_DNS["prod-public-alb"], ttl=None)
dns("example.com.", "www.example.com.", "CNAME", "app.example.com", "acme-production")
dns("example.com.", "internal.example.com.", "CNAME", LB_DNS["prod-internal-nlb"], "acme-production")
dns("example.com.", "example.com.", "MX", "10 mail.example.com", "acme-production", ttl=3600)
dns("staging.example.com.", "app.staging.example.com.", "CNAME", LB_DNS["staging-public-alb"], "acme-staging")
dns("example.com.", "bastion.example.com.", "A", INSTANCES["acme-shared-services"][0][2], "acme-shared-services")

# ── network ────────────────────────────────────────────────────────────
for acct, a in ACCOUNTS.items():
    for n, az in enumerate(("a", "b")):
        for kind in ("public", "private"):
            octet = n * 2 + (0 if kind == "public" else 1)
            ins("aws_subnets", subnet_id="subnet-" + hexid(), name=f"{acct}-{kind}-{az}", vpc_id=a["vpc"],
                cidr_block=f"{a['cidr']}.{octet}.0/24", availability_zone=a["region"] + az,
                available_ips=random.randint(180, 240), state="available",
                map_public_ip=1 if kind == "public" else 0, default_for_az=0,
                account_name=acct, region=a["region"], last_seen=TS)
    igw = "igw-" + hexid()
    ins("aws_internet_gateways", igw_id=igw, name=f"{acct}-igw", vpc_id=a["vpc"], state="available",
        account_name=acct, region=a["region"], last_seen=TS)
    ins("aws_nat_gateways", nat_gw_id="nat-" + hexid(), name=f"{acct}-nat", vpc_id=a["vpc"],
        subnet_id="subnet-" + hexid(), state="available", type="public", public_ip="198.51.100.10",
        private_ip=f"{a['cidr']}.0.20", account_name=acct, region=a["region"], last_seen=TS)
    rt = "rtb-" + hexid()
    for dest, target, ttype in (("0.0.0.0/0", igw, "internet-gateway"), (f"{a['cidr']}.0.0/16", "local", "local")):
        ins("aws_route_tables", route_table_id=rt, name=f"{acct}-public", vpc_id=a["vpc"],
            associated_subnets="", main=0, destination=dest, target=target, target_type=ttype,
            state="active", account_name=acct, region=a["region"], last_seen=TS)
ins("aws_vpc_peering", peering_id="pcx-" + hexid(), name="prod-to-shared", status="active",
    requester_vpc_id=ACCOUNTS["acme-production"]["vpc"], requester_cidr="10.10.0.0/16",
    requester_account="111111111111", requester_region="us-east-1",
    accepter_vpc_id=ACCOUNTS["acme-shared-services"]["vpc"], accepter_cidr="10.30.0.0/16",
    accepter_account="333333333333", accepter_region="us-west-2",
    account_name="acme-production", region="us-east-1", last_seen=TS)

# ── S3 ─────────────────────────────────────────────────────────────────
BUCKETS = [("acme-prod-assets", "acme-production", 820), ("acme-prod-backups", "acme-production", 2400),
           ("acme-prod-logs", "acme-production", 1300), ("acme-staging-assets", "acme-staging", 95),
           ("acme-shared-artifacts", "acme-shared-services", 410), ("acme-terraform-state", "acme-shared-services", 1)]
for name, acct, gb in BUCKETS:
    ins("aws_s3_buckets", bucket_name=name, region=ACCOUNTS[acct]["region"],
        creation_date=(NOW - timedelta(days=random.randint(200, 1400))).strftime("%Y-%m-%d %H:%M:%S"),
        versioning="Enabled" if "state" in name or "backups" in name else "Suspended", mfa_delete="Disabled",
        encryption_enabled=1, encryption_type="AES256", block_public_acls=1, ignore_public_acls=1,
        block_public_policy=1, restrict_public_buckets=1, fully_public_blocked=1,
        lifecycle_rules=1 if "logs" in name else 0, lifecycle_rule_count=2 if "logs" in name else 0, object_lock_enabled=0,
        replication_enabled=1 if "backups" in name else 0, website_enabled=0, logging_enabled=0,
        account_name=acct, last_seen=TS)
    split = {"StandardStorage": 0.6, "StandardIAStorage": 0.25, "GlacierStorage": 0.15}
    for st, share in split.items():
        ins("aws_s3_storage", bucket_name=name, storage_type=st, size_bytes=int(gb * share * 1073741824),
            object_count=int(gb * share * 9000), account_name=acct, metric_date=TS, last_seen=TS)
    ins("aws_s3_storage", bucket_name=name, storage_type="AllStorageTypes", size_bytes=int(gb * 1073741824),
        object_count=int(gb * 9000), account_name=acct, metric_date=TS, last_seen=TS)
    ins("aws_s3_tags", bucket_name=name, account_name=acct, tag_key="Team", tag_value="platform", last_seen=TS)

# ── EKS ────────────────────────────────────────────────────────────────
EKS = [("prod-cluster", "acme-production", "1.30", [("general", "ON_DEMAND", "m5.large", 3, 2, 6),
                                                   ("batch-spot", "SPOT", "c5.xlarge", 2, 0, 8)]),
       ("staging-cluster", "acme-staging", "1.31", [("general", "ON_DEMAND", "t3.large", 2, 1, 3)])]
for cname, acct, ver, groups in EKS:
    a = ACCOUNTS[acct]
    ins("aws_eks_clusters", cluster_name=cname, cluster_arn=f"arn:aws:eks:{a['region']}:111111111111:cluster/{cname}",
        status="ACTIVE", kubernetes_version=ver, platform_version="eks.7",
        endpoint=f"https://{hexid(32).upper()}.gr7.{a['region']}.eks.amazonaws.com",
        endpoint_public_access=1, endpoint_private_access=1, public_access_cidrs='["0.0.0.0/0"]',
        role_arn="arn:aws:iam::111111111111:role/eks-cluster-role", vpc_id=a["vpc"],
        subnet_ids='["subnet-aaa","subnet-bbb"]', security_group_ids="[]", cluster_sg_id="sg-" + hexid(),
        secrets_encrypted=1, kms_key_arn="", logging_enabled='["api","audit"]', service_ipv4_cidr="172.20.0.0/16",
        ip_family="ipv4", dns_name="", account_name=acct, region=a["region"],
        created_at=(NOW - timedelta(days=300)).strftime("%Y-%m-%d %H:%M:%S"), last_seen=TS)
    for gname, cap, itype, desired, mn, mx in groups:
        ins("aws_eks_nodegroups", nodegroup_name=gname,
            nodegroup_arn=f"arn:aws:eks:{a['region']}:111111111111:nodegroup/{cname}/{gname}/{hexid(8)}",
            cluster_name=cname, status="ACTIVE", capacity_type=cap, instance_types=json.dumps([itype]),
            ami_type="AL2023_x86_64_STANDARD", ami_release_version="1.30.4-20240901", disk_size_gb=50,
            desired_size=desired, min_size=mn, max_size=mx, node_role_arn="arn:aws:iam::111111111111:role/eks-node",
            subnet_ids='["subnet-aaa"]', labels="{}", taints="[]", update_config="{}",
            account_name=acct, region=a["region"],
            created_at=(NOW - timedelta(days=250)).strftime("%Y-%m-%d %H:%M:%S"), last_seen=TS)
        # hourly node snapshots for the past 7 days, with a daily scaling wave
        for h in range(7 * 24, -1, -1):
            t = NOW - timedelta(hours=h)
            wave = 1 if 8 <= t.hour <= 18 else 0
            count = min(mx, max(mn, desired + (wave * (3 if cap == "SPOT" else 1)) - (0 if t.weekday() < 5 else 1)))
            for k in range(count):
                ins("aws_eks_node_history", account_name=acct, region=a["region"], cluster_name=cname,
                    instance_id=f"i-{hexid(8)}", instance_type=itype, node_group=gname, capacity_type=cap,
                    az=a["region"] + "a", node_state="running", asg_name=f"eks-{gname}-asg",
                    recorded_at=t.strftime("%Y-%m-%d %H:%M:%S"))

conn.commit()
for t in ("aws_inventory_resources", "aws_domains", "aws_load_balancers", "aws_security_groups",
          "aws_subnets", "aws_s3_buckets", "aws_eks_clusters", "aws_eks_node_history"):
    cur.execute(f"SELECT COUNT(*) FROM `{t}`")
    print(f"{t:28}{cur.fetchone()[0]:>6} rows")
print("Demo data loaded.")
