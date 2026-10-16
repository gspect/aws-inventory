# Changelog

All notable changes to the AWS Inventory Tool are documented here.

---

## [2.5.0] — Unreleased

### Changed — Public release preparation
- Now a strictly AWS inventory tool: removed all non-AWS integrations; the traffic trace runs DNS → load balancer → target
- Removed hardcoded install paths; the app and collectors locate each other relative to their own files
- `FLASK_SECRET_KEY` no longer has an insecure default (a random key is generated with a warning)
- The app binds to `127.0.0.1` by default (`HOST` / `PORT` env vars to override)
- Optional `DISABLE_AUTH=1` runs the app without Okta login (local use only)
- Optional `PROJECT_URL` env var enables Source and feedback-issue links

### Added
- `schema.py` creates the IAM, Security Group, Network and Identity Center tables and the `sync_jobs` table automatically
- `requirements.txt`, `LICENSE` (MIT) and installation instructions

### Fixed
- `aws_eks_node_history` was missing its `asg_name` column on fresh installs; it is now created, and added to existing tables automatically
- `schema.py`: shortened a key on `sso_permission_set_policies` that exceeded MySQL's index size limit

### Added — Demo
- `demo/create_tables.py` and `demo/seed.py` load fake data so the UI can be explored without an AWS account

### Security
- HTML-escaped AWS-sourced values (tags, security group names, rule descriptions) before rendering in the browser

---

## [2.4.0] — 2026-07-28

### Added — Traffic Trace & Load Balancer Inventory

- **Traffic Trace drawer** — clicking the `⇢ Trace` button next to any `*.elb.amazonaws.com` value in the DNS table (or next to any ALB/NLB/CLB row in the Resources table) opens a slide-in drawer that resolves the full end-to-end traffic path: DNS record → ALB/NLB/CLB → listener → listener rules → target group → EC2 instance; redirect chains are followed automatically across accounts; each hop shows account and region badges; EC2 health state is colour-coded (green/red/gray)
- **`collect_lb.py`** — new collector for all three AWS load balancer types across all accounts and regions; ALB/NLB via the `elbv2` API, Classic LBs via the legacy `elb` API; collects load balancers, listeners, ALB listener rules (conditions + actions including host-header matches and redirects), target groups, target health, and Classic LB instance membership; tags collected for LBs and target groups; supports `--account` scoping, stale-delete cleanup per region, and DDL auto-creation on first run
- New database tables: `aws_load_balancers`, `aws_lb_listeners`, `aws_lb_listener_rules`, `aws_lb_target_groups`, `aws_lb_tg_targets`, `aws_clb_instances`, `aws_lb_tags`
- Load balancer count (ALB + NLB + CLB) added to header stat bar on the Resources & DNS page

### Cron setup

```
0 4 * * * /path/to/venv/bin/python /path/to/aws-inventory/scripts/collect_lb.py >> /path/to/aws-inventory/scripts/cron-logs/collect_lb_cron-$(date +\%Y-\%m-\%d).log 2>&1
```

---

## [2.3.0] — 2026-07-20

### Improved — Resources & DNS Page UX

- **Active/stale last seen highlighting** — when a search returns multiple historical snapshots of the same record, the most recent entry is highlighted with a green left border and a `current` badge; older entries are dimmed with an amber left border and a `stale` badge; a small legend appears above the table explaining the distinction; no visual treatment is applied when all rows share the same timestamp
- **Sticky TTL and Last Seen columns** — both columns are pinned to the right edge of the DNS Records table via `position: sticky` so they remain visible while scrolling horizontally through wide records (e.g. long TXT values or CNAME chains)
- **Zone ID toggle** — Zone ID column is hidden by default to reclaim horizontal space; a `Zone ID ＋` button in the Last Seen header shows or hides it on demand; preference is persisted in `localStorage`
- **Mirror scrollbar** — a synchronized horizontal scrollbar strip appears above the DNS Records table header so you can scroll the table left/right without first scrolling to the bottom of the table
- **Removed What's New panel** — the collapsible changelog widget on the home page has been removed; the full changelog remains at `CHANGELOG.md` in the repository

---

## [2.2.0] — 2026-05-16

### Added — Lambda Functions Page

- New **⚡ Lambda** page (`/lambda`) for browsing Lambda functions across all accounts and regions
- **Functions tab** — searchable and filterable by runtime and account; cards show state badge, color-coded runtime badge (Python/Node/Java/Go/Ruby/.NET/Custom/Container), architecture badge (arm64 / x86_64), memory, timeout, code size, VPC indicator, layer count, env var count, and reserved concurrency (flags `0` as throttled in red)
- **By Runtime tab** — aggregated table with function count, % distribution bar, average memory, and total code size per runtime
- **By Account tab** — function count per account with region count, VPC-attached count, and reserved concurrency count; clicking an account name filters the Functions tab
- **Detail view** — full configuration (handler, runtime, arch, memory, timeout, package type, code size, ephemeral `/tmp` storage, reserved concurrency, execution role, KMS key, code signing, image URI), networking section (VPC/subnets/SGs as chips), logging config (log group, log format, application/system log levels), SnapStart config, environment variable keys as pills (keys only — values never stored), layers table, aliases table, and event source mappings (sourced from the existing `aws_lambda_esms` table)
- **`collect_lambda.py`** — full Lambda collector running across all accounts and all regions; collects function configuration, VPC config, env var keys, reserved concurrency (via `get_function_concurrency`), layers, aliases, and tags; stale functions removed from DB on each run; supports `--account` and `--region` flags for scoped runs
- New database tables: `aws_lambda_functions`, `aws_lambda_layers`, `aws_lambda_aliases`, `aws_lambda_tags`
- Lambda function count and distinct runtime count added to `get_stats()` and the header stat bar
- Lambda nav link added to `base.html`

### Cron setup

```
0 3 * * * /path/to/venv/bin/python /path/to/aws-inventory/scripts/collect_lambda.py >> /path/to/aws-inventory/scripts/cron-logs/collect_lambda_cron-$(date +\%Y-\%m-\%d).log 2>&1
```

---

## [2.1.0] — 2026-05-08

### Added — Multi-SG Compare View

- **Compare Rules button** on the Resources & DNS page — any EC2 or load balancer with 2 or more security groups now shows an `⊕ Compare Rules` button next to the SG pills in the Details column; single-SG resources are unchanged
- **Slide-in drawer** — clicking Compare Rules opens a panel from the right without navigating away from search results; the drawer shows a merged, deduplicated ruleset across all attached SGs
- **Rule deduplication** — rules are deduped on `(direction, protocol, from_port, to_port, target, target_type)`; functionally identical rules that appear in multiple SGs are collapsed to one row
- **Source SG chips** — each rule row shows color-coded chips indicating which SG(s) the rule came from, making it easy to trace back to the originating group
- **Duplicate rule detection** — when 2+ SGs are in view and duplicate rules exist, a `⚠ N duplicate rules` badge appears in the stats bar; clicking it highlights the duplicate rows in amber and scrolls to the first one; click again to clear
- **Stats bar** — shows SG count, total raw rule count, and unique rule count at a glance
- **Direction tabs** — filter the rule table to All / Inbound / Outbound without reloading
- **+ Add SG typeahead** — search-as-you-type input in the drawer header lets you add any SG from any of the 51 accounts to the current view; results show SG ID, name, account, and region
- **Remove chips** — each active SG has an `✕` button to remove it from the view; removing the last SG closes the drawer
- **Cross-account support** — SGs from different accounts can be compared in the same view; account name is shown on chips when accounts differ
- **Shareable link** — `🔗 Copy link` button copies a `/aws-inventory/sg?multi=sg-x:account1,sg-y:account2` URL to the clipboard
- **`sg.html` multi-param view** — the `?multi=` URL renders a full standalone merged-rules page on the Security Groups page, so shared links work without requiring the drawer; same deduplication, source chips, and duplicate highlighting as the drawer

### Added — New API endpoints

- `GET /aws-inventory/sg/compare?sgs=sg-x:account1,sg-y:account2` — returns merged + deduped rules, SG metadata, and stats; account qualifier is optional (will look up if omitted); cross-account comparisons supported
- `GET /aws-inventory/sg/search?q=sg-abc&limit=10` — lightweight SG typeahead; searches all accounts by SG ID or name; used by the `+ Add SG` input in the drawer

---

## [2.0.0] — 2026-05-08

### Added — EKS Node Scaling History

- **Node Scaling History chart** on every EKS cluster detail page — stacked bar chart showing total node count over the last 7, 30, or 90 days with hourly granularity (4-hour buckets for the 90-day view)
- **Group-by toggle** — pivot the chart between three views without reloading the page:
  - **Instance Type** — see exactly which instance families are running (e.g. `c5.4xlarge`, `c7a.8xlarge`, `c7a.12xlarge`) and how the mix changes over time — useful for cost analysis
  - **Node Group** — break down by managed node group name or `self-managed` for Karpenter/static ASG nodes
  - **Capacity** — split On-Demand vs Spot to see autoscaler behaviour over time
- **Summary stat bar** — shows current total node count, period peak, period average, and number of data snapshots in the selected window
- **Captures all nodes**, including self-managed nodes invisible to the EKS API — collection uses EC2 `describe_instances` filtered by `kubernetes.io/cluster/<name>=owned` so Karpenter-provisioned and static ASG nodes are counted alongside managed node group nodes
- **Capacity type detection** with three-level fallback: `eks:capacity-type` tag → `karpenter.sh/capacity-type` tag → EC2 `InstanceLifecycle` field
- New `collect_eks_node_history.py` — lightweight hourly collector; reads known clusters from `aws_eks_clusters` (no re-discovery overhead), then calls EC2 `describe_instances` per cluster; runs against all accounts with `eks_collect = true`; supports `--account` and `--dry-run` flags; dry-run output groups nodes by node group, capacity type, and instance type counts for easy verification
- Automatic 90-day retention — old rows pruned on every run
- New database table: `aws_eks_node_history` — one row per node per hourly snapshot (`instance_id`, `instance_type`, `node_group`, `capacity_type`, `az`, `node_state`, `recorded_at`)
- New Flask route: `GET /eks/node-history` — JSON API accepting `cluster`, `account`, `region`, `days`, and `group_by` parameters; returns series data and summary stats; protected by `@api_login_required`

### Cron setup

```
0 * * * * /path/to/venv/bin/python /path/to/aws-inventory/scripts/collect_eks_node_history.py >> /path/to/aws-inventory/scripts/cron-logs/collect_eks_node_history_cron-$(date +\%Y-\%m-\%d).log 2>&1
```

### DB migration note

If `aws_eks_node_history` was previously created by an earlier draft of the collector (schema without `instance_id`), drop and recreate it:

```sql
DROP TABLE IF EXISTS aws_eks_node_history;
```

The table is recreated automatically on the next collector run.

---

## [1.9.0] — 2026-04-28

### Added — S3, EFS, ECS, EKS, and CloudFront Pages

#### S3
- New `/s3` page for browsing S3 buckets across all accounts
- List view shows bucket name, account, region, total size, object count, versioning, lifecycle rules, public access status badge, and encryption badge
- Detail view includes a **storage class breakdown donut chart** (Standard, Standard-IA, One Zone-IA, Glacier, Deep Archive, all Intelligent-Tiering tiers, etc.) rendered with plain Canvas — no external dependencies
- Security posture section: all four Public Access Block settings displayed in a 2×2 grid with green/orange indicators
- Configuration section: versioning, MFA delete, object lock, replication, static website hosting, server access logging, lifecycle rule count
- New `collect_s3.py` — uses CloudWatch `get_metric_data` batch API to fetch all storage class metrics for up to 35 buckets per API call; never paginates bucket objects so collection time is O(buckets) regardless of object count

#### EFS
- New `/efs` page for browsing EFS file systems
- Storage tier breakdown: Standard, Standard-IA, Archive sizes with bar chart proportions
- Mount target inventory per AZ, throughput mode, performance mode, encryption, lifecycle policy, and backup status
- New `collect_efs.py` — runs weekly

#### ECS
- New `/ecs` page for browsing ECS clusters and services across opted-in accounts
- Service detail includes task definition breakdown with per-container image, ports, log driver, and env/secrets count
- Load balancer linkage shows attached target group ARN and container port
- New `collect_ecs.py` — runs daily; only for accounts with `ecs_collect = true` in config.ini

#### EKS
- New `/eks` page for browsing EKS clusters across opted-in accounts
- Detail view shows API access config, CIDR restrictions, control plane logging flags, and all managed node groups with scaling config, instance types, labels, and taints
- New `collect_eks.py` — runs daily; only for accounts with `eks_collect = true` in config.ini

#### CloudFront
- New `/cloudfront` page for browsing CloudFront distributions
- Origin cards auto-classify origin type (S3, ALB, API Gateway, Custom)
- Shows cache behavior config, TLS minimum protocol, WAF indicator, geo restriction, and ACM certificate linkage
- New `collect_cloudfront.py` — runs daily; only for accounts with `cloudfront_collect = true` in config.ini

---

## [1.8.0] — 2026-04-16

### Added — Messaging (SQS/SNS/Lambda) Page

- New `/messaging` page for browsing SQS queues, SNS topics, and Lambda Event Source Mappings across all accounts
- **SQS tab** — queue name, type (Standard/FIFO), message counts, retention, visibility timeout, DLQ linkage, encryption
- **SNS tab** — topic name, type, subscription count, encryption, DLQ
- **DLQ summary tab** — all queues configured as dead-letter queues with their source queue and current message depth
- **Detail views** — full queue/topic config with Lambda ESM linkage (shows which functions consume a given queue/topic)
- New `collect_messaging.py` — collects SQS, SNS, and Lambda ESMs

---

## [1.7.0] — 2026-04-09

### Added — `--account` scoping to all collection scripts

- `collect_inventory.py`, `collect_sg.py`, and `collect_network.py` now support `--account <name>` for single-account runs, matching the existing behavior in `collect_iam.py` and `collect_rds.py`
- All six scripts now consistently support account scoping

---

## [1.6.0] — 2026-04-02

### Added — Databases (RDS/Aurora) Page
- New `/rds` page for searching RDS and Aurora resources across all 51 accounts
- **Aurora Clusters** — cluster ID, writer/reader endpoints, engine + version, engine mode, port, multi-AZ, deletion protection, VPC, subnet group, security groups (with links to SG page), parameter group, member instance list (writer/reader roles), backup retention, maintenance windows, encryption, IAM auth, tags
- **DB Instances** — instance ID, class, engine + version, connection endpoint + port, multi-AZ, publicly accessible flag (highlighted with a red PUBLIC badge), storage type/size/IOPS/encryption, deletion protection, Performance Insights, CA cert, parameter group, subnet group, VPC, security groups, cluster membership, replica source, tags
- Color-coded engine badges for aurora-mysql, aurora-postgresql, mysql, postgres, mariadb, oracle, and sqlserver
- Security warnings on detail views: deletion protection off and unencrypted storage display ⚠ yellow indicators
- Cluster member list links directly to each instance detail view; instance detail links back to parent cluster
- New `collect_rds.py` collection script — runs weekly (Sundays at 2 AM) since RDS topology changes infrequently
- New database tables: `aws_rds_clusters`, `aws_rds_instances`, `aws_rds_tags`
- Databases link added to nav bar on all pages
- RDS cluster and instance counts added to `get_stats()`

---

## [1.5.0] — 2026-04-01

### Added — Okta SSO Authentication
- All pages are now protected by Okta OIDC authentication via `okta_auth.py`
- Users are redirected to Okta login on first visit and returned to their original page after authentication
- Logged-in user's name is displayed in the header of every page with a logout button
- Auth handled via a shared Flask blueprint (`okta_bp`) registered across all routes
- Session managed server-side using `FLASK_SECRET_KEY` environment variable
- Okta credentials (`OKTA_DOMAIN`, `OKTA_CLIENT_ID`, `OKTA_CLIENT_SECRET`) injected via systemd environment override

### Improved — Header Layout
- Header now spans full width with logo on the left and links/user info on the right

---

## [1.4.0] — 2026-03-25

### Added — Identity Center (SSO) Page
- New `/sso` page for searching AWS Identity Center users and groups
- Search by username, email, display name, or group name across all accounts
- User detail view shows group memberships, account assignments across all AWS accounts, and permission sets with full policy statements (effect, actions, resources)
- Group detail view shows all members (with links to individual user views) and all account assignments for the group
- Permission sets expand to show attached managed policies, inline policies, and customer-managed policies with full statement detail
- Direct assignment vs group-inherited assignment is clearly indicated per permission set

---

## [1.3.0] — 2026-03-23

### Added — Network Page
- New `/network` page with tabbed layout covering all network-layer resources
- **Subnets** — subnet ID, name, VPC, CIDR, AZ, available IPs, public/private flag, tags
- **Route Tables** — expandable cards showing all routes per table with destination, target, and target type
- **Network ACLs** — expandable cards showing inbound and outbound rules with rule number, protocol, ports, CIDR, and allow/deny
- **NAT Gateways** — ID, name, VPC, subnet, state, type, public/private IP
- **Internet Gateways** — ID, name, attached VPC, state
- **VPC Peering** — expandable cards showing requester/accepter VPC, account, CIDR, and status
- **Transit Gateways** — expandable cards showing state and all attachments
- New `collect_network.py` collection script
- New database tables: `aws_subnets`, `aws_subnet_tags`, `aws_route_tables`, `aws_network_acls`, `aws_nat_gateways`, `aws_internet_gateways`, `aws_vpc_peering`, `aws_transit_gateways`, `aws_tgw_attachments`

---

## [1.2.0] — 2026-03-23

### Added — Tags Support
- All resources now display associated AWS tags via a clickable 🏷 pill that opens an inline popover
- Tags stored in dedicated tables: `aws_resource_tags`, `aws_sg_tags`, `aws_subnet_tags`
- Tag collection added to `collect_inventory.py`, `collect_sg.py`

### Added — Stale Data Cleanup
- All collection scripts use a stale-delete strategy — resources not seen in the current sync run are automatically removed
- Orphaned tag rows are also cleaned up after each region sync

### Fixed — Load Balancer Security Groups
- ALB/NLB/CLB security group IDs were not being stored or displayed
- SG IDs now appear as clickable links in the Details column for load balancers

---

## [1.1.0] — 2026-03-23

### Added — Project Links
- Project repository link added to the header and footer of all pages
- Feedback & Feature Request button (floating FAB) added to all pages — opens a pre-filled issue

---

## [1.0.0] — Initial Release

### Features
- **Resources & DNS page** — search EC2, ALB/NLB/CLB, VPCs, and Route53 records by IP, name, CIDR, or AWS ID
- **Security Groups page** — search SGs by name, ID, or CIDR; drill down to view all inbound/outbound rules; SG-to-SG references are clickable
- **IAM page** — search users and roles; view attached policies with full permission statements, trust relationships, and EC2 instance associations
- Multi-account support via `config.ini` with cross-account role assumption
- Stat bar in header showing total accounts, EC2, load balancers, VPCs, DNS records, and last sync time
- Collection scripts for EC2/LB/VPC/DNS, Security Groups, and IAM
- Gunicorn + Nginx deployment on Ubuntu 22.04
- MySQL backend with upsert-based sync

---

## Upcoming

- [ ] Tag-based search — search resources by tag key or value across all resource types
- [ ] Export to CSV — download search results as a CSV file
- [ ] IAM improvements — surface unused roles/users and access key age warnings
- [ ] RDS — add parameter group detail view
- [ ] EKS node history — Force Sync support for `collect_eks_node_history.py`
