import html as html_lib
from pathlib import Path


TEMPLATE = """<!DOCTYPE html>
<html><head><meta charset="utf-8">
<title>403 Bypass Report — {target}</title>
<style>
body {{ font-family: -apple-system, system-ui, sans-serif; max-width: 1200px; margin: 2rem auto; padding: 1rem; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
th {{ background: #f4f4f4; }}
code {{ background: #f4f4f4; padding: 2px 4px; border-radius: 3px; font-size: 0.9em; }}
.summary {{ background: #f9f9f9; border-left: 4px solid #4CAF50; padding: 1rem; margin: 1rem 0; }}
.status-2xx {{ color: #2e7d32; font-weight: bold; }}
.status-3xx {{ color: #00838f; font-weight: bold; }}
.status-4xx {{ color: #f57c00; font-weight: bold; }}
</style>
</head><body>
<h1>403 Bypass Report</h1>
<div class="summary">
<strong>Target:</strong> {target}<br>
<strong>Findings:</strong> {count}
</div>
<h2>Findings</h2>
<table>
<thead><tr><th>Status</th><th>Technique</th><th>Description</th><th>URL</th><th>Score</th><th>Reason</th></tr></thead>
<tbody>
{rows}
</tbody>
</table>
</body></html>"""


def write_html(path: Path, target: str, findings: list[dict]):
    rows = []
    for f in findings:
        status = f.get("status", 0)
        cls = "status-2xx" if 200 <= status < 300 else (
            "status-3xx" if 300 <= status < 400 else "status-4xx"
        )
        rows.append(f"""<tr>
<td class="{cls}">{status}</td>
<td>{html_lib.escape(str(f.get('technique', '')))}</td>
<td>{html_lib.escape(str(f.get('description', '')))}</td>
<td><code>{html_lib.escape(str(f.get('url', '')))}</code></td>
<td>{f.get('score', 0)}</td>
<td>{html_lib.escape(str(f.get('reason', '')))}</td>
</tr>""")

    out = TEMPLATE.format(
        target=html_lib.escape(target),
        count=len(findings),
        rows="\n".join(rows),
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(out, encoding="utf-8")