"""VulnShield CLI entry point."""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import List, Optional

from vulnshield.findings.model import Finding, Protocol, Severity, Confidence, FindingStatus, ScanResult
from vulnshield.findings.storage import FindingStore
from vulnshield.local.scanner import LocalScanner
from vulnshield.remediation.patches import PatchEngine
from vulnshield.remediation.recommender import RemediationRecommender
from vulnshield.reporting.generator import ReportGenerator
from vulnshield.remote.authorization import TargetAuthorizer, AuthorizationError
from vulnshield.remote.scanner import RemoteAssessmentEngine
from vulnshield.remote.scheduler import ScheduleManager
from vulnshield.remote.targets import (
    TargetConfig,
    HttpProtocolConfig,
    SshProtocolConfig,
    parse_targets_file,
    TargetInventoryManager,
)


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vulnshield",
        description="VulnShield CLI - Production-Grade Remote & Local Vulnerability Assessment Engine",
    )
    subparsers = parser.add_subparsers(dest="subcommand", help="Available subcommands")

    # 1. scan
    scan_parser = subparsers.add_parser("scan", help="Run vulnerability assessment")
    scan_parser.add_argument("path", nargs="?", default=None, help="Local directory path to scan")
    scan_parser.add_argument("--url", help="Target HTTP/HTTPS URL")
    scan_parser.add_argument("--ssh", help="Target SSH host (e.g. admin@server.example.com or server.example.com)")
    scan_parser.add_argument("--identity", help="Path to SSH private key identity file")
    scan_parser.add_argument("--port", type=int, default=None, help="SSH port override (default: 22)")
    scan_parser.add_argument("--mode", choices=["passive", "active"], default="passive", help="Assessment mode (default: passive)")
    scan_parser.add_argument("--targets", help="Path to targets.yaml file for batch assessment")
    scan_parser.add_argument("--concurrency", type=int, default=5, help="Concurrency limit (default: 5)")
    scan_parser.add_argument("--allow-private-ips", action="store_true", help="Permit scans against private/loopback IPs (testing only)")
    scan_parser.add_argument("--json", action="store_true", help="Output results in JSON format")

    # 2. targets
    targets_parser = subparsers.add_parser("targets", help="Manage assessment targets")
    targets_sub = targets_parser.add_subparsers(dest="targets_action", help="Target actions")

    add_t_parser = targets_sub.add_parser("add", help="Add a new target")
    add_t_parser.add_argument("--id", help="Target ID (auto-generated if omitted)")
    add_t_parser.add_argument("--url", help="HTTP/HTTPS URL")
    add_t_parser.add_argument("--ssh", help="SSH connection string (user@host)")
    add_t_parser.add_argument("--identity", help="SSH private key path")
    add_t_parser.add_argument("--authorized", action="store_true", default=True, help="Mark target authorized")

    list_t_parser = targets_sub.add_parser("list", help="List configured targets")
    val_t_parser = targets_sub.add_parser("validate", help="Validate targets against authorization & policy")

    # 3. schedule
    sched_parser = subparsers.add_parser("schedule", help="Manage scheduled assessments")
    sched_sub = sched_parser.add_subparsers(dest="schedule_action", help="Schedule actions")

    sched_add = sched_sub.add_parser("add", help="Schedule a recurring assessment")
    sched_add.add_argument("--targets", required=True, help="Path to targets.yaml")
    sched_add.add_argument("--interval", required=True, help="Scan interval (e.g. 24h, 12h, 30m)")

    sched_list = sched_sub.add_parser("list", help="List scheduled jobs")

    # 4. findings
    findings_parser = subparsers.add_parser("findings", help="Query and inspect findings")
    findings_sub = findings_parser.add_subparsers(dest="findings_action", help="Findings actions")

    find_list = findings_sub.add_parser("list", help="List recorded findings")
    find_list.add_argument("--target", help="Filter by target ID")
    find_list.add_argument("--severity", help="Filter by severity (CRITICAL, HIGH, etc.)")
    find_list.add_argument("--status", help="Filter by status (CONFIRMED_VULNERABLE, etc.)")

    find_show = findings_sub.add_parser("show", help="Show full details for a finding")
    find_show.add_argument("finding_id", help="Finding ID")

    find_cmp = findings_sub.add_parser("compare", help="Compare two scans (differential analysis)")
    find_cmp.add_argument("scan_id_1", help="First scan ID")
    find_cmp.add_argument("scan_id_2", help="Second scan ID")

    # 5. remediate
    rem_parser = subparsers.add_parser("remediate", help="Remediation recommendations")
    rem_sub = rem_parser.add_subparsers(dest="remediate_action", help="Remediation action")
    rem_rec = rem_sub.add_parser("recommend", help="Generate remediation plan for target")
    rem_rec.add_argument("--target", required=True, help="Target ID")

    # 6. patch
    patch_parser = subparsers.add_parser("patch", help="Vendor patch tracking and verification")
    patch_sub = patch_parser.add_subparsers(dest="patch_action", help="Patch actions")

    patch_src = patch_sub.add_parser("sources", help="List official patch sources for target")
    patch_src.add_argument("--target", required=True, help="Target ID")

    patch_ver = patch_sub.add_parser("verify", help="Verify patch remediation against target")
    patch_ver.add_argument("--target", required=True, help="Target ID")

    return parser


def handle_scan(args: argparse.Namespace) -> int:
    store = FindingStore()

    # Case 1: Local scan
    if args.path and not args.url and not args.ssh and not args.targets:
        local_scanner = LocalScanner()
        findings = local_scanner.scan_path(args.path)
        if args.json:
            print(json.dumps([f.to_dict() for f in findings], indent=2))
        else:
            print(ReportGenerator.format_findings_table(findings))
        return 0

    # Case 2: Remote Batch scan via --targets
    if args.targets:
        targets = parse_targets_file(args.targets)
        authorizer = TargetAuthorizer(allow_private_ips=args.allow_private_ips)
        engine = RemoteAssessmentEngine(authorizer=authorizer, finding_store=store)
        result = engine.scan_targets_batch(targets, concurrency=args.concurrency)

        if args.json:
            print(json.dumps(result.to_dict(), indent=2))
        else:
            print(f"Scan Completed: {result.scan_id}")
            print(ReportGenerator.format_findings_table(result.findings))
        return 0

    # Case 3: Ad-hoc remote scan with --url and/or --ssh
    if args.url or args.ssh:
        target_id = "adhoc-target"
        protocols: dict = {}

        if args.url:
            protocols["http" if args.url.startswith("http://") else "https"] = {
                "url": args.url,
                "mode": args.mode,
            }
            target_id = args.url

        if args.ssh:
            # Parse user@host or host
            ssh_user = "scanner"
            ssh_host = args.ssh
            if "@" in args.ssh:
                ssh_user, ssh_host = args.ssh.split("@", 1)

            protocols["ssh"] = {
                "host": ssh_host,
                "username": ssh_user,
                "identity": args.identity,
                "port": args.port or 22,
            }
            if not args.url:
                target_id = args.ssh

        target = TargetConfig(
            id=target_id,
            authorized=True,  # Explicit CLI invocation grants authorized status
            protocols=protocols,
        )

        authorizer = TargetAuthorizer(allow_private_ips=args.allow_private_ips)
        engine = RemoteAssessmentEngine(authorizer=authorizer, finding_store=store)
        result = engine.scan_targets_batch([target], concurrency=1)

        if args.json:
            print(json.dumps(result.to_dict(), indent=2))
        else:
            print(f"Scan Completed: {result.scan_id}")
            print(ReportGenerator.format_findings_table(result.findings))
        return 0

    print("Error: Specify --url, --ssh, --targets, or a local path to scan.", file=sys.stderr)
    return 1


def handle_targets(args: argparse.Namespace) -> int:
    manager = TargetInventoryManager()

    if args.targets_action == "add":
        target_id = args.id or (args.url or args.ssh or "target-1")
        protocols: dict = {}
        if args.url:
            protocols["http" if args.url.startswith("http://") else "https"] = {"url": args.url}
        if args.ssh:
            ssh_user = "scanner"
            ssh_host = args.ssh
            if "@" in args.ssh:
                ssh_user, ssh_host = args.ssh.split("@", 1)
            protocols["ssh"] = {
                "host": ssh_host,
                "username": ssh_user,
                "identity": args.identity,
            }

        target = TargetConfig(
            id=target_id,
            authorized=args.authorized,
            protocols=protocols,
        )
        manager.add_target(target)
        print(f"Target '{target_id}' added successfully.")
        return 0

    elif args.targets_action == "list":
        targets = manager.load()
        if not targets:
            print("No targets configured.")
            return 0
        print(f"{'TARGET ID':<25} {'AUTHORIZED':<12} {'PROTOCOLS'}")
        print("-" * 60)
        for t in targets:
            protos = ", ".join(t.protocols.keys())
            print(f"{t.id:<25} {str(t.authorized):<12} {protos}")
        return 0

    elif args.targets_action == "validate":
        validation_results = manager.validate_targets()
        print(f"{'TARGET ID':<25} {'STATUS':<10} {'ISSUES'}")
        print("-" * 70)
        for r in validation_results:
            status_str = "VALID" if r["valid"] else "INVALID"
            issues_str = "; ".join(r["issues"]) if r["issues"] else "None"
            print(f"{r['target_id']:<25} {status_str:<10} {issues_str}")
        return 0

    return 0


def handle_schedule(args: argparse.Namespace) -> int:
    manager = ScheduleManager()

    if args.schedule_action == "add":
        job = manager.add_schedule(args.targets, args.interval)
        print(f"Scheduled assessment '{job.id}' created with interval {job.interval_raw}.")
        return 0

    elif args.schedule_action == "list":
        jobs = manager.list_schedules()
        if not jobs:
            print("No scheduled assessments.")
            return 0
        print(f"{'JOB ID':<30} {'INTERVAL':<10} {'TARGETS FILE'}")
        print("-" * 75)
        for j in jobs:
            print(f"{j.id:<30} {j.interval_raw:<10} {j.targets_file}")
        return 0

    return 0


def handle_findings(args: argparse.Namespace) -> int:
    store = FindingStore()

    if args.findings_action == "list":
        findings = store.list_findings(
            target_id=args.target,
            severity=args.severity,
            status=args.status,
        )
        print(ReportGenerator.format_findings_table(findings))
        return 0

    elif args.findings_action == "show":
        finding = store.get_finding(args.finding_id)
        if not finding:
            print(f"Finding '{args.finding_id}' not found.", file=sys.stderr)
            return 1
        print(ReportGenerator.format_finding_detail(finding))
        return 0

    elif args.findings_action == "compare":
        try:
            diff = store.compare_scans(args.scan_id_1, args.scan_id_2)
            print(ReportGenerator.format_compare_report(diff))
            return 0
        except Exception as e:
            print(f"Comparison error: {e}", file=sys.stderr)
            return 1

    return 0


def handle_remediate(args: argparse.Namespace) -> int:
    store = FindingStore()
    findings = store.list_findings(target_id=args.target)
    if not findings:
        print(f"No findings recorded for target '{args.target}'.")
        return 0

    recommender = RemediationRecommender()
    print(f"REMEDIATION RECOMMENDATIONS FOR: {args.target}")
    print("=" * 80)

    for f in findings:
        plan = recommender.recommend_for_finding(f)
        print(f"\nFinding: {f.title} ({f.cve or f.id})")
        print(f"Action:  {plan.recommended_action}")
        if plan.dry_run_command:
            print(f"Dry-run: {plan.dry_run_command}")
        if plan.production_command:
            print(f"Apply:   {plan.production_command}")
        if plan.documentation_url:
            print(f"Docs:    {plan.documentation_url}")
        for note in plan.safety_notes:
            print(f"Safety:  - {note}")
        print("-" * 80)

    return 0


def handle_patch(args: argparse.Namespace) -> int:
    store = FindingStore()
    engine = PatchEngine(finding_store=store)

    if args.patch_action == "sources":
        sources = engine.get_patch_sources(args.target)
        if not sources:
            print(f"No patch sources identified for target '{args.target}'.")
            return 0
        print(f"{'COMPONENT':<15} {'SECURITY CHANNEL':<30} {'OFFICIAL REPOSITORY'}")
        print("-" * 80)
        for s in sources:
            print(f"{s['component']:<15} {s['security_channel']:<30} {s['official_repo']}")
        return 0

    elif args.patch_action == "verify":
        # Check current status against historic findings
        findings = store.list_findings(target_id=args.target)
        result = engine.verify_patch(args.target, findings)
        print(f"Remediation Verification for {args.target}: {result['verification_status']}")
        print(f"Verified Remediated: {result['verified_remediated_count']} / {result['total_historic']}")
        if result["unremediated"]:
            print("\nUnremediated Vulnerabilities:")
            for u in result["unremediated"]:
                print(f"  - [{u['severity']}] {u['cve'] or u['finding_id']} ({u['component']})")
        return 0

    return 0


def main() -> None:
    parser = create_parser()
    args = parser.parse_args()

    if not args.subcommand:
        parser.print_help()
        sys.exit(0)

    try:
        if args.subcommand == "scan":
            sys.exit(handle_scan(args))
        elif args.subcommand == "targets":
            sys.exit(handle_targets(args))
        elif args.subcommand == "schedule":
            sys.exit(handle_schedule(args))
        elif args.subcommand == "findings":
            sys.exit(handle_findings(args))
        elif args.subcommand == "remediate":
            sys.exit(handle_remediate(args))
        elif args.subcommand == "patch":
            sys.exit(handle_patch(args))
    except AuthorizationError as e:
        print(f"\n[SECURITY AUTHORIZATION ERROR] {e}\n", file=sys.stderr)
        sys.exit(2)
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"\n[ERROR] {e}\n", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
