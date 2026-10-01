import json
import urllib.request


def send_webhook(url: str, target: str, findings: list[dict]):
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
            resp.read()
    except Exception as e:
        print(f"[!] Webhook failed: {e}", file=__import__("sys").stderr)