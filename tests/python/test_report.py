import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "python"))

from bypass403_cli import parse_args
from report.markdown import write_markdown


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