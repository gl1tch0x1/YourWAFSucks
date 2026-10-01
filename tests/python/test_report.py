import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "python"))

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