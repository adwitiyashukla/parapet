# parapet

![ci](https://github.com/adwitiyashukla/parapet/actions/workflows/ci.yml/badge.svg)

parapet is a security posture scanner for AWS. It reads a live account through read only API calls, or a Terraform plan before anything is applied, and checks both against the same 47 rules. Every rule carries its CIS AWS Foundations Benchmark v3.0 and AWS Foundational Security Best Practices ids, a severity and a fix. Findings come out as a terminal table, JSON, SARIF for GitHub code scanning, or a self contained HTML report.

I built it while preparing for cloud engineering roles. I wanted one tool that covers the two places misconfigurations show up: the account that already exists, and the pull request that is about to change it.

## What it does

```
$ parapet scan plan examples/insecure/plan.json
parapet 0.1.0  source: terraform  origin: examples/insecure/plan.json  regions: us-east-1
resources 20  rules 47  checks 43  passed 7  failed 36  suppressed 0  score 16.3
critical 6  high 8  medium 13  low 9

SEVERITY  RULE        TYPE                 RESOURCE           REGION     MESSAGE
critical  EC2-002     security_group       web                us-east-1  ingress allows every port from ::/0
critical  IAM-012     iam_role             app-role           global     trust policy allows sts:AssumeRole from any principal in statement 1
critical  LAMBDA-001  lambda_function      api                us-east-1  resource policy allows any principal in public
critical  RDS-001     db_instance          app-db             us-east-1  instance has a public endpoint
critical  S3-002      s3_bucket            parapet-demo-data  us-east-1  bucket policy allows any principal in PublicRead
critical  S3-007      s3_bucket            parapet-demo-data  us-east-1  bucket uses the canned ACL public-read
high      EC2-001     security_group       web                us-east-1  ingress open on port 22 from 0.0.0.0/0, port 3389 from 0.0.0.0/0
...
```

The two example stacks under `examples/` are real Terraform plans (AWS provider 6.71, Terraform 1.12). The insecure one plans 29 resources and gets 36 findings. The hardened one plans 50 resources, passes all 65 checks that apply and exits 0. Both scans finish in under 0.1 seconds.

## Install

Python 3.11 or newer.

```
pip install git+https://github.com/adwitiyashukla/parapet
```

Or from a clone:

```
git clone https://github.com/adwitiyashukla/parapet
cd parapet
pip install -e .[dev]
pytest
```

## Scan a Terraform plan

```
terraform plan -out=tfplan
terraform show -json tfplan > plan.json
parapet scan plan plan.json --sarif results.sarif --html report.html
```

The plan adapter reads `resource_changes` and the `configuration` block. Terraform splits one bucket across several resources (`aws_s3_bucket_public_access_block`, `aws_s3_bucket_versioning`, `aws_s3_bucket_policy` and so on), and the ids that tie them together are unknown until apply. parapet resolves the references from the configuration expressions instead, so the child resources get folded back onto the bucket, security group, VPC, IAM user, role or Lambda function they belong to. Values that are still unknown after that are skipped rather than guessed, and an attribute that will get a computed value counts as configured.

## Scan a live account

```
parapet scan aws --regions us-east-1,eu-west-1 --profile audit --json results.json
```

The collectors only call describe, list and get APIs. `scanner-policy.json` lists the exact 49 actions if you want a least privilege role; the AWS managed `SecurityAudit` policy also works. Regions and services run in a thread pool (`workers` in the config). When one call fails, for example `AccessDenied` on RDS in one region, the error is recorded in the report and every other check still runs. `--regions all` scans every enabled region.

## Rules

| Family | Rules | What they cover | Frameworks |
| --- | --- | --- | --- |
| S3 | 9 | public access block, public policies and ACLs, deny HTTP, versioning, KMS, access logging, MFA delete, account level block | CIS 2.1.x, FSBP S3.x |
| IAM | 12 | root keys and MFA, password policy, console MFA, key rotation, unused credentials, direct user policies, admin and service wildcard policies, open trust policies | CIS 1.x, FSBP IAM.x |
| EC2 and VPC | 11 | admin, database and unexpected ports open to the internet, all traffic rules, default security group, flow logs, EBS encryption, IMDSv2, public IPs | CIS 5.x and 3.7, FSBP EC2.x |
| CloudTrail | 5 | multi-region trail, log validation, KMS, CloudWatch Logs, logging status | CIS 3.x, FSBP CloudTrail.x |
| KMS | 1 | rotation on customer managed keys | CIS 3.6, FSBP KMS.4 |
| RDS | 5 | public access, encryption, backups, deletion protection, minor upgrades | CIS 2.2.x, FSBP RDS.x |
| Lambda | 3 | public invoke permissions, function URLs without auth, deprecated runtimes | FSBP Lambda.x |
| AWS Config | 1 | recorder present and recording | CIS 3.3, FSBP Config.1 |

`parapet rules` prints the full list with ids, severities and mappings. Rules that need data only a live account has (credential report, trail status, Config recorders) are marked `aws` and skip plan scans; one rule only applies to plans.

Each rule is a small class with a `check` method that returns pass, fail with a message, or skip. Adding one means adding a class to the right module and putting it in that module's `RULES` list.

## Outputs and exit codes

| Flag | Output |
| --- | --- |
| default | table on stdout, wrapped to the terminal width |
| `--json FILE` | full result with summary, findings, suppressions, errors and warnings |
| `--sarif FILE` | SARIF 2.1.0 with `security-severity` so GitHub code scanning sorts findings by severity |
| `--html FILE` | one file report with severity filters, text search and sortable columns |

Exit code 1 means a finding at or above `fail_on` (default `high`), 2 means a usage, config or connection error, 0 is clean. `--fail-on none` turns the gate off.

`parapet diff old.json new.json` compares two JSON results and lists new and resolved findings. It exits 1 when a new finding crosses the threshold, so a scheduled scan can alert on regressions instead of the whole backlog.

## CI

The repo's own workflow does this on every push: run the tests on Python 3.11 to 3.13, scan the insecure example, upload the SARIF to the Security tab, keep the HTML report as an artifact, then scan the hardened example with `--fail-on low` as the gate.

```yaml
- run: pip install git+https://github.com/adwitiyashukla/parapet
- run: terraform show -json tfplan > plan.json
- run: parapet scan plan plan.json --sarif results.sarif --fail-on high
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: results.sarif
```

## Config

parapet reads `config.toml` from the working directory when it exists, or the file given with `--config`. Every key is validated, unknown keys are an error.

| Section | Keys |
| --- | --- |
| `[scan]` | `regions`, `workers`, `fail_on`, `profile` |
| `[rules]` | `disabled`, `access_key_max_age_days`, `unused_credential_days`, `password_min_length`, `password_reuse_prevention`, `backup_retention_min_days`, `admin_ports`, `database_ports`, `public_ports_allowed`, `deprecated_lambda_runtimes` |
| `[report]` | `width` (0 means the terminal width) |

Accepted risks go in the same file. A suppression needs a reason, matches resources by glob against the id, ARN, name or Terraform address, and can expire:

```toml
[[suppressions]]
rule = "S3-006"
resource = "arn:aws:s3:::my-logs-*"
reason = "log buckets are not logged again"
expires = 2027-06-30
```

Suppressed findings stay in the JSON and HTML output with their reason. An expired suppression stops matching and shows up as a warning. `--no-suppress` ignores them for one run.

## Docker

```
docker build -t parapet .
docker run --rm -v "$PWD":/work parapet scan plan examples/insecure/plan.json
docker run --rm -v "$HOME/.aws":/root/.aws:ro -v "$PWD":/work parapet scan aws --profile audit
```

## Tests

111 tests, about 20 seconds. The live collectors are tested against [moto](https://github.com/getmoto/moto), which mocks the AWS APIs in process, with an account built to trip most of the rules. The plan adapter and the rules are tested against the two example plans plus hand built resources for every pass, fail and skip path.

## Layout

```
parapet/
  cli.py            argparse entry point, exit codes
  config.py         config.toml loading and validation
  engine.py         runs the rules, applies suppressions, builds the result
  diff.py           compares two json results
  model.py          Resource, Inventory, Finding, ScanResult
  sources/aws.py    boto3 collectors
  sources/terraform.py  plan json adapter and reference folding
  rules/            one module per service, policy.py for IAM document checks
  report/           table, json, sarif and html renderers
examples/           insecure and hardened Terraform stacks with their plan json
tests/
```
