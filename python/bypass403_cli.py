#!/usr/bin/env python3
"""
bypass403 — Python control layer.

Runs the Go binary, reads JSONL output, generates reports, sends webhooks.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
from decimal import Decimal, InvalidOperation
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

MAX_BATCH_TARGETS = 100
MAX_TARGET_LIST_BYTES = 1_048_576
MIN_REQUEST_BUDGET_PER_TARGET = 7
GO_DURATION_UNITS = {
    "ns": 1,
    "us": 1_000,
    "µs": 1_000,
    "ms": 1_000_000,
    "s": 1_000_000_000,
    "m": 60_000_000_000,
    "h": 3_600_000_000_000,
}


def parse_args():
    p = argparse.ArgumentParser(
        prog="bypass403",
        description="Authorized access-control assessment with optional batch and report workflows.",
    )
    p.add_argument("--go-binary", required=True, help=argparse.SUPPRESS)
    p.add_argument("--version", action="version", version="bypass403 1.0.0")
    targets = p.add_mutually_exclusive_group(required=True)
    targets.add_argument("-u", "--url", "--target")
    targets.add_argument("-l", "--list", dest="target_list", help="File containing targets (one URL per line)")
    p.add_argument("-k", "--techniques", default="all")
    p.add_argument("-j", "--jobs", type=int, default=20)
    p.add_argument("-H", "--header", action="append", default=[])
    p.add_argument("-b", "--cookie", default="")
    p.add_argument("-A", "--user-agent", default="")
    p.add_argument("-x", "--proxy", default="")
    p.add_argument("-o", "--output", default="")
    p.add_argument("--config", default="")
    p.add_argument("--timeout", default="10s")
    p.add_argument("--rate", "--rate-limit", dest="rate_limit", type=int, default=100)
    p.add_argument("--retries", type=int, default=2)
    p.add_argument("--max-requests", type=int, default=0)
    p.add_argument("--max-duration", default="")
    p.add_argument("--allow-host", action="append", default=[])
    p.add_argument("-ms", "--match-status", default="")
    p.add_argument("-n", "--dry-run", action="store_true")
    p.add_argument("--md", help="Markdown report path")
    p.add_argument("--html", help="HTML report path")
    p.add_argument("--webhook", default="")
    p.add_argument("--jsonl", help="Where Go writes JSONL (default: temp)")
    p.add_argument("-q", "--quiet", action="store_true")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--no-retest", action="store_true")
    return p.parse_args()


def normalize_batch_target(raw: str) -> str:
    raw = raw.strip()
    if not raw:
        raise ValueError("target URL is empty")
    if "://" not in raw:
        raw = "https://" + raw
    parsed = urlsplit(raw)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise ValueError(f"target must be an HTTP(S) URL with a hostname: {raw}")
    if parsed.username or parsed.password:
        raise ValueError("target URLs must not embed credentials")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f"target has an invalid port: {raw}") from exc
    hostname = parsed.hostname.lower().rstrip(".")
    if ":" in hostname:
        hostname = f"[{hostname}]"
    default_port = 80 if parsed.scheme.lower() == "http" else 443
    netloc = hostname if port in (None, default_port) else f"{hostname}:{port}"
    return urlunsplit((parsed.scheme.lower(), netloc, parsed.path or "/", parsed.query, ""))


def load_batch_targets(path: str) -> list[str]:
    try:
        target_path = Path(path)
        if target_path.stat().st_size > MAX_TARGET_LIST_BYTES:
            raise ValueError(f"target list cannot exceed {MAX_TARGET_LIST_BYTES} bytes")
        with target_path.open(encoding="utf-8-sig") as source:
            lines = source.read().splitlines()
    except (OSError, UnicodeError) as exc:
        raise ValueError(f"could not read target list: {exc}") from exc

    targets = []
    seen = set()
    for line_number, line in enumerate(lines, 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            target = normalize_batch_target(line)
        except ValueError as exc:
            raise ValueError(f"line {line_number}: {exc}") from exc
        if target not in seen:
            seen.add(target)
            targets.append(target)
        if len(targets) > MAX_BATCH_TARGETS:
            raise ValueError(f"target list cannot exceed {MAX_BATCH_TARGETS} unique targets")
    if not targets:
        raise ValueError("target list contains no URLs")
    return targets


def validate_batch_allowlist(targets: list[str], allowed_hosts: list[str]) -> None:
    allowed = {host.strip().lower().rstrip(".") for host in allowed_hosts if host.strip()}
    if not allowed:
        raise ValueError("batch mode requires one or more --allow-host values")
    unmatched = sorted({urlsplit(target).hostname.lower().rstrip(".") for target in targets} - allowed)
    if unmatched:
        raise ValueError("targets outside --allow-host: " + ", ".join(unmatched))


def parse_go_duration_ns(value: str) -> int:
    pattern = re.compile(r"(\d+(?:\.\d+)?)(ns|us|µs|ms|s|m|h)")
    position = 0
    total = Decimal(0)
    for match in pattern.finditer(value):
        if match.start() != position:
            raise ValueError(f"invalid Go duration: {value}")
        try:
            total += Decimal(match.group(1)) * GO_DURATION_UNITS[match.group(2)]
        except InvalidOperation as exc:
            raise ValueError(f"invalid Go duration: {value}") from exc
        position = match.end()
    if position != len(value) or position == 0 or total <= 0:
        raise ValueError(f"duration must be positive and use Go units: {value}")
    return int(total)


def allocate_request_budgets(total: int, target_count: int) -> list[int]:
    if target_count < 1 or total < target_count * MIN_REQUEST_BUDGET_PER_TARGET:
        raise ValueError(
            f"--max-requests must allow at least {MIN_REQUEST_BUDGET_PER_TARGET} requests per target"
        )
    base, remainder = divmod(total, target_count)
    return [base + (index < remainder) for index in range(target_count)]


def allocate_duration_budgets(total_ns: int, target_count: int) -> list[str]:
    if target_count < 1:
        raise ValueError("target count must be positive")
    per_target_ns = total_ns // target_count
    if per_target_ns < 1:
        raise ValueError("--max-duration is too small for the target count")
    return [f"{per_target_ns}ns"] * target_count


def validate_batch_output_paths(target_list: str, output_paths: list[str | None]) -> None:
    source = Path(target_list).resolve()
    for output_path in output_paths:
        if output_path and Path(output_path).resolve() == source:
            raise ValueError("batch outputs must not overwrite the target list")


def run_go(args, jsonl_path: Path, *, url: str | None = None,
           max_requests: int | None = None, max_duration: str | None = None) -> int:
    target_url = url or args.url
    cmd = [
        args.go_binary,
        "-u", target_url,
        "-k", args.techniques,
        "-j", str(args.jobs),
        "-b", args.cookie,
        "-o", str(jsonl_path),
        "--timeout", args.timeout,
        "--rate-limit", str(args.rate_limit),
        "--retries", str(args.retries),
    ]
    if args.user_agent:
        cmd += ["--user-agent", args.user_agent]
    request_limit = args.max_requests if max_requests is None else max_requests
    duration_limit = args.max_duration if max_duration is None else max_duration
    if request_limit > 0:
        cmd += ["--max-requests", str(request_limit)]
    if duration_limit:
        cmd += ["--max-duration", duration_limit]
    if args.match_status:
        cmd += ["--match-status", args.match_status]
    for host in args.allow_host:
        cmd += ["--allow-host", host]
    if args.config:
        cmd += ["--config", args.config]
    if args.proxy:
        cmd += ["-x", args.proxy]
    for h in args.header:
        cmd += ["-H", h]
    if args.quiet:
        cmd += ["-q"]
    if args.verbose:
        cmd += ["-v"]
    if args.no_retest:
        cmd += ["--no-retest"]
    if args.dry_run:
        cmd += ["--dry-run"]

    print("[*] Starting Go engine", file=sys.stderr)
    proc = subprocess.run(cmd)
    return proc.returncode


def run_batch(args, jsonl_path: Path) -> tuple[int, int]:
    try:
        targets = load_batch_targets(args.target_list)
        validate_batch_allowlist(targets, args.allow_host)
        if args.max_requests <= 0:
            raise ValueError("batch mode requires a positive global --max-requests value")
        if not args.max_duration:
            raise ValueError("batch mode requires a global --max-duration value")
        request_budgets = allocate_request_budgets(args.max_requests, len(targets))
        total_duration_ns = parse_go_duration_ns(args.max_duration)
        duration_budgets = allocate_duration_budgets(total_duration_ns, len(targets))
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc

    result_files = []
    exit_code = 0
    with tempfile.TemporaryDirectory(prefix="bypass403-batch-") as directory:
        for index, (target, request_budget, duration_budget) in enumerate(
            zip(targets, request_budgets, duration_budgets), 1
        ):
            target_output = Path(directory) / f"target-{index:03d}.jsonl"
            result_files.append(target_output)
            print(
                f"[*] Batch target {index}/{len(targets)}: {sanitize_url(target)} "
                f"(budget {request_budget}, duration {duration_budget})",
                file=sys.stderr,
            )
            try:
                target_exit = run_go(
                    args,
                    target_output,
                    url=target,
                    max_requests=request_budget,
                    max_duration=duration_budget,
                )
            except OSError as exc:
                print(f"[!] Could not start Go engine: {exc}", file=sys.stderr)
                target_exit = 2
            if target_exit not in (0, 10) and exit_code in (0, 10):
                exit_code = target_exit
            elif target_exit == 10 and exit_code == 0:
                exit_code = 10

        with jsonl_path.open("wb") as combined:
            for result_file in result_files:
                if result_file.exists():
                    with result_file.open("rb") as source:
                        for line in source:
                            combined.write(line)

    return exit_code, len(targets)


def load_findings(path: Path) -> list[dict]:
    if not path.exists() or path.stat().st_size == 0:
        return []
    out = []
    with path.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out


def sanitize_url(raw: str) -> str:
    try:
        parsed = urlsplit(raw)
        hostname = parsed.hostname
        if not parsed.scheme or not hostname:
            return raw
        if ":" in hostname:
            hostname = f"[{hostname}]"
        if parsed.port:
            hostname = f"{hostname}:{parsed.port}"
        sensitive = {
            "token", "access_token", "refresh_token", "api_key", "apikey",
            "secret", "password", "passwd", "authorization", "session", "cookie",
        }
        query = [
            (key, "[REDACTED]" if key.lower().replace("-", "_") in sensitive else value)
            for key, value in parse_qsl(parsed.query, keep_blank_values=True)
        ]
        return urlunsplit((parsed.scheme, hostname, parsed.path, urlencode(query), ""))
    except ValueError:
        return raw


def main():
    args = parse_args()

    if args.jsonl and args.output:
        raise SystemExit("--jsonl and --output cannot be used together")
    if args.target_list:
        try:
            validate_batch_output_paths(
                args.target_list,
                [args.output, args.jsonl, args.md, args.html],
            )
        except ValueError as exc:
            raise SystemExit(str(exc)) from exc
    temporary_jsonl = not args.jsonl and not args.output
    if args.jsonl:
        jsonl_path = Path(args.jsonl)
    elif args.output:
        jsonl_path = Path(args.output)
    else:
        temporary_file = tempfile.NamedTemporaryFile(prefix="bypass403-", suffix=".jsonl", delete=False)
        jsonl_path = Path(temporary_file.name)
        temporary_file.close()
    jsonl_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        if args.target_list:
            rc, target_count = run_batch(args, jsonl_path)
            fallback_report_target = f"Batch scan ({target_count} targets)"
        else:
            rc = run_go(args, jsonl_path)
            fallback_report_target = sanitize_url(args.url or "")
        findings = load_findings(jsonl_path)
        if args.target_list:
            report_target = fallback_report_target
        else:
            report_target = findings[0].get("target", fallback_report_target) if findings else fallback_report_target

        print(f"[*] Go engine produced {len(findings)} findings", file=sys.stderr)

        if args.md:
            from report.markdown import write_markdown
            write_markdown(Path(args.md), report_target, findings)
            print(f"[+] Markdown: {args.md}", file=sys.stderr)

        if args.html:
            from report.html import write_html
            write_html(Path(args.html), report_target, findings)
            print(f"[+] HTML: {args.html}", file=sys.stderr)

        if args.webhook and findings:
            from webhook.notify import send_webhook
            if send_webhook(args.webhook, report_target, findings):
                print("[+] Webhook sent", file=sys.stderr)

        sys.exit(rc)
    finally:
        if temporary_jsonl:
            jsonl_path.unlink(missing_ok=True)


if __name__ == "__main__":
    # Ensure report/ and webhook/ are importable
    sys.path.insert(0, str(Path(__file__).parent))
    main()