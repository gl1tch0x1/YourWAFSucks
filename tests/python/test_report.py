import json
import sys
import shlex
from argparse import Namespace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "python"))

from bypass403_cli import (
    allocate_request_budgets,
    load_batch_targets,
    parse_go_duration_ns,
    parse_args,
    run_batch,
    sanitize_url,
    validate_batch_allowlist,
    validate_batch_output_paths,
)
from report.markdown import _repro_curl, write_markdown
from webhook.notify import send_webhook


def test_write_markdown(tmp_path):
    findings = [
        {
            "status": 200,
            "description": "Header: X-Forwarded-For: 127.0.0.1",
            "url": "https://target.tld/admin",
            "method": "GET",
            "technique": "headers",
            "score": 95,
            "reason": "status 200 != baseline 403",
            "replay_count": 2,
            "headers": {"X-Forwarded-For": "127.0.0.1"},
        }
    ]
    out = tmp_path / "report.md"
    write_markdown(out, "https://target.tld/admin", findings)

    assert out.exists()
    content = out.read_text()
    assert "403 Bypass Report" in content
    assert "X-Forwarded-For" in content
    assert "curl" in content


def test_report_cli_accepts_documented_scan_options(monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "bypass403",
            "--go-binary",
            "engine",
            "--target",
            "https://example.test/admin",
            "--techniques",
            "headers",
            "--jobs",
            "4",
            "--header",
            "X-Test: value",
            "--output",
            "findings.jsonl",
            "--timeout",
            "5s",
            "--rate-limit",
            "10",
            "--max-requests",
            "25",
            "--max-duration",
            "2m",
            "--allow-host",
            "example.test",
            "-ms",
            "200,403",
        ],
    )
    args = parse_args()

    assert args.url == "https://example.test/admin"
    assert args.jobs == 4
    assert args.header == ["X-Test: value"]
    assert args.output == "findings.jsonl"
    assert args.rate_limit == 10
    assert args.max_requests == 25
    assert args.max_duration == "2m"
    assert args.allow_host == ["example.test"]
    assert args.match_status == "200,403"


def test_batch_cli_requires_allowlist_and_global_limits(monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        ["bypass403", "--go-binary", "engine", "--list", "targets.txt"],
    )
    args = parse_args()

    assert args.url is None
    assert args.target_list == "targets.txt"
    assert args.max_requests == 0
    assert args.max_duration == ""


def test_batch_target_preflight_normalizes_deduplicates_and_checks_allowlist(tmp_path):
    target_file = tmp_path / "targets.txt"
    target_file.write_text(
        "# authorized hosts\nexample.test/admin\nhttps://EXAMPLE.test:443/admin\napi.example.test/v1\n",
        encoding="utf-8",
    )

    targets = load_batch_targets(str(target_file))
    assert targets == ["https://example.test/admin", "https://api.example.test/v1"]
    validate_batch_allowlist(targets, ["example.test", "api.example.test"])
    try:
        validate_batch_allowlist(targets, ["example.test"])
    except ValueError as exc:
        assert "api.example.test" in str(exc)
    else:
        raise AssertionError("expected unmatched host to be rejected")


def test_batch_output_cannot_overwrite_target_list(tmp_path):
    target_file = tmp_path / "targets.txt"
    target_file.write_text("example.test", encoding="utf-8")
    try:
        validate_batch_output_paths(str(target_file), [None, str(target_file)])
    except ValueError as exc:
        assert "must not overwrite" in str(exc)
    else:
        raise AssertionError("expected target list output collision to be rejected")


def test_go_duration_parser_supports_compound_durations():
    assert parse_go_duration_ns("1m30s") == 90_000_000_000
    assert parse_go_duration_ns("1.5h") == 5_400_000_000_000


def test_run_batch_splits_global_budgets_and_merges_jsonl(tmp_path, monkeypatch):
    target_file = tmp_path / "targets.txt"
    target_file.write_text("one.example.test\ntwo.example.test\n", encoding="utf-8")
    args = Namespace(
        target_list=str(target_file),
        allow_host=["one.example.test", "two.example.test"],
        max_requests=20,
        max_duration="120s",
    )
    allocated = []

    def fake_run_go(_args, output_path, *, url, max_requests, max_duration):
        allocated.append((url, max_requests, max_duration))
        output_path.write_text(json.dumps({"target": url}) + "\n", encoding="utf-8")
        return 0

    monkeypatch.setattr("bypass403_cli.run_go", fake_run_go)
    output_path = tmp_path / "combined.jsonl"
    result = run_batch(args, output_path)

    assert result == (0, 2)
    assert [entry[1] for entry in allocated] == allocate_request_budgets(20, 2)
    assert [entry[2] for entry in allocated] == ["60000000000ns", "60000000000ns"]
    assert [json.loads(line)["target"] for line in output_path.read_text().splitlines()] == [
        "https://one.example.test/",
        "https://two.example.test/",
    ]


def test_reproduction_command_quotes_values_without_disabling_tls():
    command = _repro_curl({
        "method": "GET",
        "url": "https://example.test/admin?a=1&b=two words",
        "headers": {"X-Test": "value with ' quotes"},
    })
    parts = shlex.split(command)

    assert "-k" not in parts
    assert parts[parts.index("-H") + 1] == "X-Test: value with ' quotes"
    assert parts[-1] == "https://example.test/admin?a=1&b=two words"


def test_report_target_redacts_userinfo_and_secret_query_values():
    assert sanitize_url(
        "https://user:pass@example.test/admin?access-token=secret&view=full#fragment"
    ) == "https://example.test/admin?access-token=%5BREDACTED%5D&view=full"


def test_webhook_rejects_non_http_urls():
    assert send_webhook("file:///tmp/report", "https://example.test", []) is False