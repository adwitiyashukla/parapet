import argparse
import json
import os
import sys
from pathlib import Path

from parapet import __version__
from parapet.config import ConfigError, load_config, parse_fail_on
from parapet.diff import diff_results, load_result, render_diff
from parapet.engine import run_rules
from parapet.model import ScanResult
from parapet.report import render_html, render_json, render_sarif, render_table
from parapet.rules import build_rules
from parapet.sources import SourceError
from parapet.sources.terraform import load_plan


def add_scan_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--config", metavar="FILE", help="config file, default ./config.toml when it exists")
    parser.add_argument("--json", metavar="FILE", help="write the full result as json")
    parser.add_argument("--sarif", metavar="FILE", help="write findings as SARIF 2.1.0 for code scanning")
    parser.add_argument("--html", metavar="FILE", help="write a self contained html report")
    parser.add_argument(
        "--fail-on",
        metavar="SEVERITY",
        help="exit 1 at or above this severity: critical, high, medium, low, info, none",
    )
    parser.add_argument("--no-suppress", action="store_true", help="ignore the suppressions in the config")
    parser.add_argument("--quiet", action="store_true", help="do not print the findings table")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="parapet", description="security posture scanner for AWS accounts and Terraform plans"
    )
    parser.add_argument("--version", action="version", version=f"parapet {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("scan", help="scan a live account or a terraform plan")
    targets = scan.add_subparsers(dest="target", required=True)
    aws = targets.add_parser("aws", help="scan a live AWS account with read only API calls")
    aws.add_argument("--regions", metavar="LIST", help="comma separated regions, or all")
    aws.add_argument("--profile", metavar="NAME", help="aws cli profile to use")
    aws.add_argument("--workers", type=int, metavar="N", help="parallel collectors")
    add_scan_options(aws)
    plan = targets.add_parser("plan", help="scan a terraform plan exported with terraform show -json")
    plan.add_argument("path", help="path to the plan json")
    add_scan_options(plan)
    diff = commands.add_parser("diff", help="compare two json results and list new and resolved findings")
    diff.add_argument("baseline", help="json result of the earlier scan")
    diff.add_argument("current", help="json result of the later scan")
    diff.add_argument("--config", metavar="FILE")
    diff.add_argument("--fail-on", metavar="SEVERITY", help="exit 1 when a new finding is at or above this severity")
    diff.add_argument("--json", metavar="FILE", help="write the diff as json")
    rules = commands.add_parser("rules", help="list the rules and their framework mappings")
    rules.add_argument("--config", metavar="FILE")
    rules.add_argument("--json", action="store_true", help="print the list as json")
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "scan":
            return run_scan(args)
        if args.command == "diff":
            return run_diff(args)
        return run_rules_listing(args)
    except (ConfigError, SourceError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except BrokenPipeError:
        sys.stdout = open(os.devnull, "w")
        return 0


def exit_code(result: ScanResult, fail_on) -> int:
    worst = result.worst()
    if fail_on is None or worst is None:
        return 0
    return 1 if worst >= fail_on else 0


def write_output(path: str, content: str) -> None:
    target = Path(path)
    if target.parent and not target.parent.exists():
        target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    print(f"wrote {target}", file=sys.stderr)


def run_scan(args) -> int:
    config = load_config(args.config)
    if args.fail_on is not None:
        config.fail_on = parse_fail_on(args.fail_on, "--fail-on")
    if args.no_suppress:
        config.suppressions = []
    if args.target == "plan":
        inventory = load_plan(args.path)
    else:
        from parapet.sources.aws import AwsSource, make_session

        if args.regions:
            config.regions = [r.strip() for r in args.regions.split(",") if r.strip()]
        if args.profile:
            config.profile = args.profile
        if args.workers:
            config.workers = max(1, args.workers)
        label = f"profile {config.profile}" if config.profile else "default credentials"
        print(f"scanning account via {label} in {', '.join(config.regions)}", file=sys.stderr)
        inventory = AwsSource(make_session(config.profile), config.regions, config.workers, label).collect()
    result = run_rules(inventory, config)
    if args.json:
        write_output(args.json, render_json(result))
    if args.sarif:
        write_output(args.sarif, render_sarif(result))
    if args.html:
        write_output(args.html, render_html(result))
    if not args.quiet:
        print(render_table(result, config.width), end="")
    return exit_code(result, config.fail_on)


def run_diff(args) -> int:
    config = load_config(args.config)
    fail_on = parse_fail_on(args.fail_on, "--fail-on") if args.fail_on is not None else config.fail_on
    diff = diff_results(load_result(args.baseline), load_result(args.current))
    if args.json:
        write_output(args.json, json.dumps(diff.to_dict(), indent=2) + "\n")
    print(render_diff(diff), end="")
    worst = diff.worst_new()
    if fail_on is None or worst is None:
        return 0
    return 1 if worst >= fail_on else 0


def run_rules_listing(args) -> int:
    config = load_config(args.config)
    rules = build_rules(config.settings, config.disabled_rules)
    if args.json:
        print(json.dumps([rule.describe() for rule in rules], indent=2))
        return 0
    print(f"{'ID':11} {'SEVERITY':9} {'SOURCES':14} {'CIS':12} {'FSBP':22} TITLE")
    for rule in rules:
        print(
            f"{rule.id:11} {rule.severity.label:9} {'+'.join(rule.sources):14} "
            f"{', '.join(rule.cis):12} {', '.join(rule.fsbp):22} {rule.title}"
        )
    print(
        f"\n{len(rules)} rules"
        + (f", {len(config.disabled_rules)} disabled in config" if config.disabled_rules else "")
    )
    return 0
