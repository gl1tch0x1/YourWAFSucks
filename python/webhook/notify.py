import json
import sys
import urllib.request
from urllib.parse import urlsplit


def send_webhook(url: str, target: str, findings: list[dict]):
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        print("[!] Webhook URL must use HTTP or HTTPS", file=sys.stderr)
        return False

    high = [f for f in findings if f.get("score", 0) >= 60]

    text = (
        f"*bypass403 findings*\n"
        f"Target: `{target}`\n"
        f"Total: *{len(findings)}*  |  High-confidence: *{len(high)}*"
    )

    payload = json.dumps({"text": text}).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            resp.read(64 * 1024)
        return True
    except Exception as e:
        print(f"[!] Webhook failed ({type(e).__name__})", file=sys.stderr)
        return False