#!/usr/bin/env python3
"""
bypass403 — Python control layer.

Runs the Go binary, reads JSONL output, generates reports, sends webhooks.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path


def parse_args():
    p = argparse.ArgumentParser(prog="bypass403")
    p.add_argument("--go-binary", required=True, help="Path to bypass403-go")
    p.add_argument("-u", "--url", required=True)
    p.add_argument("-k", "--techniques", default="all")
    p.add_argument("-j", "--jobs", type=int, default=20)
    p.add_argument("-H", "--header", action="append", default=[])
    p.add_argument("-b", "--cookie", default="")
    p.add_argument("-x", "--proxy", default="")
    p.add_argument("-o", "--output", default="")
    p.add_argument("--md", help="Markdown report path")
    p.add_argument("--html", help="HTML report path")
    p.add_argument("--webhook", default="")
    p.add_argument("--jsonl", help="Where Go writes JSONL (default: temp)")
    p.add_argument("-q", "--quiet", action="store_true")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--no-retest", action="store_true")
    return p.parse_args()


def run_go(args, jsonl_path: Path) -> int:
    cmd = [
        args.go_binary,
        "-u", args.url,
        "-k", args.techniques,
        "-j", str(args.jobs),
        "-b", args.cookie,
        "-o", str(jsonl_path),
    ]
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

    print(f"[*] Running: {' '.join(cmd)}", file=sys.stderr)
    proc = subprocess.run(cmd)
    return proc.returncode


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


def main():
    args = parse_args()

    jsonl_path = Path(args.jsonl) if args.jsonl else Path("/tmp/bypass403-findings.jsonl")
    jsonl_path.parent.mkdir(parents=True, exist_ok=True)

    rc = run_go(args, jsonl_path)
    findings = load_findings(jsonl_path)

    print(f"[*] Go engine produced {len(findings)} findings", file=sys.stderr)

    if args.md:
        from report.markdown import write_markdown
        write_markdown(Path(args.md), args.url, findings)
        print(f"[+] Markdown: {args.md}", file=sys.stderr)

    if args.html:
        from report.html import write_html
        write_html(Path(args.html), args.url, findings)
        print(f"[+] HTML: {args.html}", file=sys.stderr)

    if args.webhook and findings:
        from webhook.notify import send_webhook
        send_webhook(args.webhook, args.url, findings)
        print(f"[+] Webhook sent", file=sys.stderr)

    if args.output:
        Path(args.output).write_text(
            json.dumps(findings, indent=2)
        )
        print(f"[+] JSON: {args.output}", file=sys.stderr)

    sys.exit(rc)


if __name__ == "__main__":
    # Ensure report/ and webhook/ are importable
    sys.path.insert(0, str(Path(__file__).parent))
    main()