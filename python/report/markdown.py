from pathlib import Path
import os
import shlex


def write_markdown(path: Path, target: str, findings: list[dict]):
    lines = [
        f"# 403 Bypass Report — {target}",
        "",
        f"**Target:** `{target}`",
        f"**Findings:** {len(findings)}",
        "",
        "## Findings",
        "",
    ]

    for i, f in enumerate(findings, 1):
        lines += [
            f"### {i}. [{f.get('status')}] {f.get('description', 'unknown')}",
            "",
            f"- **URL:** `{f.get('url', '')}`",
            f"- **Method:** `{f.get('method', 'GET')}`",
            f"- **Technique:** `{f.get('technique', '')}`",
            f"- **Score:** {f.get('score', 0)}",
            f"- **Reason:** {f.get('reason', '')}",
            f"- **Replay:** {f.get('replay_count', 0)}/2",
            "",
        ]
        if f.get("headers"):
            lines.append(f"**Headers:** `{f['headers']}`")
            lines.append("")
        lines += [
            "**Reproduce:**",
            "```bash",
            _repro_curl(f),
            "```",
            "",
            "---",
            "",
        ]

    lines += [
        "## Remediation",
        "",
        "- Enforce consistent path normalization across all tiers",
        "- Do not trust `X-Forwarded-*` headers from untrusted sources",
        "- Reject unexpected HTTP methods at the edge",
        "- Canonicalize encoding before authorization checks",
        "",
    ]

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


def _repro_curl(f: dict) -> str:
    parts = [
        "curl", "--silent", "--show-error",
        "-X", f.get("method", "GET"),
        "-A", "Mozilla/5.0",
        "--path-as-is",
    ]
    for k, v in (f.get("headers") or {}).items():
        parts += ["-H", f"{k}: {v}"]
    parts += [
        "-o", os.devnull,
        "-w", "%{http_code}",
        str(f.get("url", "")),
    ]
    return shlex.join(parts)