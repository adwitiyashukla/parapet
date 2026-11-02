# parapet

![ci](https://github.com/adwitiyashukla/parapet/actions/workflows/ci.yml/badge.svg)

parapet is a security posture scanner for AWS that I wrote in Python. It can scan a live AWS account with read only API calls, or a Terraform plan before anything gets applied. Both go through the same 47 rules. Rules are mapped to CIS AWS Foundations Benchmark v3.0 and AWS Security Hub control ids wherever a matching control exists, and every finding comes with a severity and a fix. Results print as a table, or get saved as JSON, SARIF for GitHub code scanning, or a single file HTML report.

I built it while preparing for cloud engineering roles. Most misconfigurations either already sit in a running account or are about to land through a pull request, so I wanted one tool that checks both.

## What it does

```
$ parapet scan plan examples/insecure/plan.json
parapet 0.1.0  source: terraform  origin: examples/insecure/plan.json  regions: us-east-1
resources 20  rules 47  checks 43  passed 7  failed 36  suppressed 0  score 16.3
critical 6  high 8  medium 13  low 9

SEVERITY  RULE        TYPE              RESOURCE                         REGION     MESSAGE
critical  EC2-002     security_group    web                              us-east-1  ingress allows every port from ::/0
critical  IAM-012     iam_role          app-role                         global     trust policy allows sts:AssumeRole
                                                                                    from any principal in statement 1
critical  LAMBDA-001  lambda_function   api                              us-east-1  resource policy allows any principal
                                                                                    in public
critical  RDS-001     db_instance       app-db                           us-east-1  instance has a public endpoint
critical  S3-002      s3_bucket         parapet-demo-data                us-east-1  bucket policy allows any principal
                                                                                    in PublicRead
critical  S3-007      s3_bucket         parapet-demo-data                us-east-1  bucket uses the canned ACL
                                                                                    public-read
...
```

The two stacks in `examples/` are real Terraform plans, made with Terraform 1.12 and AWS provider 6.71. The insecure stack plans 29 resources and gets 36 findings. The hardened stack plans 50 resources and passes all 65 checks that apply to it. On my laptop a full CLI run on either plan takes 0.5 to 0.9 seconds, and almost all of that is Python starting up. Loading the plan and running the rules takes 1.5 to 1.7 milliseconds.

## Install

Python 3.11 or newer.

```
pip install git+https://github.com/adwitiyashukla/parapet
```

From a clone, with the test dependencies:

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

Terraform splits one S3 bucket into several resources, like `aws_s3_bucket_public_access_block`, `aws_s3_bucket_versioning` and `aws_s3_bucket_policy`. The ids that link them are unknown until apply. parapet follows the references in the plan's `configuration` block instead and folds each child resource back onto its bucket. The same happens for security group rules, flow logs, IAM policies and attachments, and Lambda permissions. If a value is still unknown after that, the check is skipped instead of guessed. An attribute that only gets its value at apply time, like a KMS key ARN, counts as set.

## Scan a live account

```
parapet scan aws --regions us-east-1,eu-west-1 --profile audit --json results.json
```

The collectors never change anything in the account. They call describe, list and get APIs, plus GenerateCredentialReport for the IAM credential report. `scanner-policy.json` has the exact 49 actions for a least privilege role, and the AWS managed `SecurityAudit` policy works too. Regions and services are collected in parallel (`workers` in the config). If one call fails, for example `AccessDenied` on RDS in one region, the error goes into the report and every other check still runs. CloudTrail trails are read from their home region, so a multi-region trail still counts when its home region is not in the scan. `--regions all` scans every enabled region.

## Rules

| Family | Rules | What they check | CIS v3.0 | Security Hub |
| --- | --- | --- | --- | --- |
| S3 | 9 | public access block, public policy or ACL, HTTPS only policy, versioning, KMS encryption, access logs, MFA delete | 2.1.1, 2.1.2, 2.1.4 | S3.1, S3.2, S3.3, S3.5, S3.8, S3.9, S3.14, S3.17, S3.20 |
| IAM | 12 | root keys and MFA, password policy, console MFA, key age, unused credentials, one active key, direct user policies, admin and wildcard policies, open trust policies | 1.4, 1.5, 1.8, 1.9, 1.10, 1.12, 1.13, 1.14, 1.15, 1.16 | IAM.1, IAM.2, IAM.3, IAM.4, IAM.5, IAM.7, IAM.8, IAM.9, IAM.15, IAM.16, IAM.21, IAM.22 |
| EC2 and VPC | 11 | admin, database and other ports open to the internet, default security group, flow logs, EBS encryption, IMDSv2, public IPs | 2.2.1, 3.7, 5.2, 5.3, 5.4, 5.6 | EC2.2, EC2.3, EC2.6, EC2.7, EC2.8, EC2.9, EC2.18, EC2.19, EC2.53, EC2.54 |
| CloudTrail | 5 | multi-region trail, log validation, KMS, CloudWatch Logs, logging turned on | 3.1, 3.2, 3.5 | CloudTrail.1, CloudTrail.2, CloudTrail.4, CloudTrail.5 |
| KMS | 1 | key rotation | 3.6 | KMS.4 |
| RDS | 5 | public access, encryption, backups, deletion protection, minor version upgrades | 2.3.1, 2.3.2, 2.3.3 | RDS.2, RDS.3, RDS.8, RDS.11, RDS.13 |
| Lambda | 3 | public invoke permission, function URL without auth, deprecated runtime | none | Lambda.1, Lambda.2 |
| AWS Config | 1 | recorder present and recording | 3.3 | Config.1 |

`parapet rules` prints every rule with its id, severity, sources and mappings. Some rules need data that only exists in a live account, like the credential report, trail status or Config recorders. Those are marked `aws` and are skipped for plans. One rule only makes sense for plans.

Each rule is a small class with a `check` method that returns pass, fail with a message, or skip. A new rule is a new class in the right module, added to that module's `RULES` list.

## Outputs and exit codes

| Flag | Output |
| --- | --- |
| default | table on stdout, wrapped to the terminal width |
| `--json FILE` | full result with summary, findings, suppressions, errors and warnings |
| `--sarif FILE` | SARIF 2.1.0 with `security-severity`, so GitHub code scanning sorts findings by severity |
| `--html FILE` | one file report with severity filters, text search and sortable columns |

Exit code 1 means at least one finding at or above `fail_on`, which defaults to `high`. Exit code 2 means a usage, config or connection error, and 0 means clean. `--fail-on none` turns the gate off.

`parapet diff old.json new.json` compares two JSON results and lists new and resolved findings. It exits 1 only when a new finding crosses the threshold, so a scheduled scan can alert on regressions instead of the whole backlog.

## CI

On every push, `.github/workflows/ci.yml` runs the tests on Python 3.11, 3.12 and 3.13. Then it scans the insecure example, uploads the SARIF to the repo's Security tab and keeps the HTML report as an artifact. The last step scans the hardened example with `--fail-on low`, so the build fails if a rule change starts flagging a clean plan. A third job builds the Docker image and runs the same scan inside it.

To gate your own Terraform pull requests, the steps look like this.

```yaml
- run: pip install git+https://github.com/adwitiyashukla/parapet
- run: terraform show -json tfplan > plan.json
- run: parapet scan plan plan.json --sarif results.sarif --fail-on high
- uses: github/codeql-action/upload-sarif@v4
  if: always()
  with:
    sarif_file: results.sarif
```

## Config

parapet reads `config.toml` from the working directory if it exists, or the file passed with `--config`. Every key is validated and unknown keys are an error.

| Section | Keys |
| --- | --- |
| `[scan]` | `regions`, `workers`, `fail_on`, `profile` |
| `[rules]` | `disabled`, `access_key_max_age_days`, `unused_credential_days`, `password_min_length`, `password_reuse_prevention`, `backup_retention_min_days`, `admin_ports`, `database_ports`, `public_ports_allowed`, `deprecated_lambda_runtimes` |
| `[report]` | `width` (0 means the terminal width) |

Accepted risks go in the same file. A suppression needs a reason. It matches resources by glob against the id, ARN, name or Terraform address, and it can have an expiry date.

```toml
[[suppressions]]
rule = "S3-006"
resource = "arn:aws:s3:::my-logs-*"
reason = "log buckets are not logged again"
expires = 2027-06-30
```

Suppressed findings stay in the JSON and HTML output with their reason. An expired suppression stops matching and shows up as a warning. `--no-suppress` ignores all suppressions for one run.

## Docker

```
docker build -t parapet .
docker run --rm -v "$PWD":/work parapet scan plan examples/insecure/plan.json
docker run --rm -v "$HOME/.aws":/root/.aws:ro -v "$PWD":/work parapet scan aws --profile audit
```

## Tests

116 tests, about 40 seconds on my laptop. The live collectors run against [moto](https://github.com/getmoto/moto), which mocks the AWS APIs in process. The test account is built to trip most of the rules, and the trail tests cover a multi-region trail whose home region is outside the scan. The plan adapter and the rules are tested on the two example plans and on hand built resources for every pass, fail and skip path.

## Layout

```
parapet/
  cli.py                argparse entry point, exit codes
  config.py             config.toml loading and validation
  engine.py             runs the rules, applies suppressions, builds the result
  diff.py               compares two json results
  model.py              Resource, Inventory, Finding, ScanResult
  sources/aws.py        boto3 collectors
  sources/terraform.py  plan json adapter and reference folding
  rules/                one module per service, policy.py for IAM document checks
  report/               table, json, sarif and html renderers
examples/               insecure and hardened Terraform stacks with their plan json
tests/
```
