// Package report renders a self-contained HTML dashboard summarizing scan
// findings. The generated document inlines all CSS and JavaScript, references
// no external resources, and escapes every untrusted value.
package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/gl1tch0x1/YourWAFSucks/internal/techniques"
)

type findingView struct {
	Technique   string            `json:"technique"`
	Method      string            `json:"method"`
	URL         string            `json:"url"`
	Status      int               `json:"status"`
	Score       int               `json:"score"`
	Severity    string            `json:"severity"`
	Reason      string            `json:"reason"`
	ReplayCount int               `json:"replay_count"`
	Headers     map[string]string `json:"headers,omitempty"`
}

type breakdownItem struct {
	Label string
	Count int
}

type pageData struct {
	Target            string
	Version           string
	Generated         string
	Total             int
	HighestScore      int
	SeverityBreakdown []breakdownItem
	TechniqueBreak    []breakdownItem
	Findings          []findingView
	FindingsJSON      template.JS
}

var dashboard = template.Must(template.New("dashboard").Parse(dashboardHTML))

// Render returns the standalone HTML dashboard for the given findings.
func Render(findings []techniques.Result, target, version string) string {
	views := make([]findingView, 0, len(findings))
	severityCounts := make(map[string]int)
	techniqueCounts := make(map[string]int)
	highest := 0

	for _, f := range findings {
		status := 0
		if f.Response != nil {
			status = f.Response.Status
		}
		technique := f.Payload.Technique
		if technique == "" {
			technique = "unknown"
		}
		reason := f.Score.Reason
		if reason == "" {
			reason = f.Payload.Description
		}
		v := findingView{
			Technique:   technique,
			Method:      f.Payload.Method,
			URL:         redactURL(f.Payload.URL),
			Status:      status,
			Score:       f.Score.Score,
			Severity:    severityFor(f.Score.Score),
			Reason:      reason,
			ReplayCount: f.ReplayCount,
			Headers:     sanitizeHeaders(f.Payload.Headers),
		}
		views = append(views, v)
		severityCounts[v.Severity]++
		techniqueCounts[technique]++
		if v.Score > highest {
			highest = v.Score
		}
	}

	blob, err := json.Marshal(views)
	if err != nil {
		// findingView is fully serializable; this is effectively unreachable.
		blob = []byte("[]")
	}

	data := pageData{
		Target:            target,
		Version:           version,
		Generated:         time.Now().UTC().Format(time.RFC3339),
		Total:             len(views),
		HighestScore:      highest,
		SeverityBreakdown: breakdown(severityCounts),
		TechniqueBreak:    breakdown(techniqueCounts),
		Findings:          views,
		FindingsJSON:      template.JS(blob),
	}

	var buf bytes.Buffer
	if err := dashboard.Execute(&buf, data); err != nil {
		// Render cannot return an error, so fall back to a minimal, escaped
		// document rather than emitting a blank page.
		return fmt.Sprintf("<!DOCTYPE html><html><body><p>failed to render report: %s</p></body></html>",
			template.HTMLEscapeString(err.Error()))
	}
	return buf.String()
}

// WriteHTML renders the dashboard and writes it to path.
func WriteHTML(path string, findings []techniques.Result, target, version string) error {
	html := Render(findings, target, version)
	return os.WriteFile(path, []byte(html), 0o600)
}

func breakdown(counts map[string]int) []breakdownItem {
	items := make([]breakdownItem, 0, len(counts))
	for label, count := range counts {
		items = append(items, breakdownItem{Label: label, Count: count})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Count != items[j].Count {
			return items[i].Count > items[j].Count
		}
		return items[i].Label < items[j].Label
	})
	return items
}

func severityFor(score int) string {
	switch {
	case score >= 90:
		return "critical"
	case score >= 70:
		return "high"
	case score >= 40:
		return "medium"
	case score > 0:
		return "low"
	default:
		return "info"
	}
}

func sanitizeHeaders(headers map[string]string) map[string]string {
	if len(headers) == 0 {
		return nil
	}
	safe := make(map[string]string, len(headers))
	for name, value := range headers {
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key", "api-key", "x-auth-token", "x-access-token":
			safe[name] = "[REDACTED]"
		default:
			safe[name] = value
		}
	}
	return safe
}

func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	u.User = nil
	query := u.Query()
	for key := range query {
		normalized := strings.ToLower(strings.ReplaceAll(key, "-", "_"))
		switch normalized {
		case "token", "access_token", "refresh_token", "api_key", "apikey", "secret",
			"password", "passwd", "authorization", "session", "cookie":
			query[key] = []string{"[REDACTED]"}
		}
	}
	u.RawQuery = query.Encode()
	return u.String()
}

const dashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>YourWAFSucks Report</title>
<style>
  :root { color-scheme: dark; --bg:#0f1115; --panel:#171a21; --border:#2a2f3a; --text:#e6e8ee; --muted:#9aa3b2; }
  * { box-sizing: border-box; }
  body { margin:0; padding:2rem; background:var(--bg); color:var(--text); font:14px/1.5 "Segoe UI",system-ui,sans-serif; }
  h1 { margin:0 0 .25rem; font-size:1.6rem; }
  .sub { color:var(--muted); margin-bottom:1.5rem; }
  .cards { display:flex; flex-wrap:wrap; gap:1rem; margin-bottom:1.5rem; }
  .card { background:var(--panel); border:1px solid var(--border); border-radius:10px; padding:1rem 1.25rem; min-width:160px; }
  .card .label { color:var(--muted); font-size:.75rem; text-transform:uppercase; letter-spacing:.05em; }
  .card .value { font-size:1.5rem; font-weight:600; margin-top:.25rem; }
  .breakdown { display:flex; flex-wrap:wrap; gap:.4rem; margin-top:.5rem; }
  .pill { border:1px solid var(--border); border-radius:999px; padding:.1rem .55rem; font-size:.75rem; color:var(--muted); }
  .critical { color:#ff6b6b; } .high { color:#ffa94d; } .medium { color:#ffd43b; } .low { color:#74c0fc; } .info { color:var(--muted); }
  .toolbar { display:flex; gap:.5rem; margin-bottom:.75rem; }
  input[type=search] { flex:1; max-width:340px; background:var(--panel); border:1px solid var(--border); color:var(--text); border-radius:8px; padding:.5rem .75rem; }
  table { width:100%; border-collapse:collapse; background:var(--panel); border:1px solid var(--border); border-radius:10px; overflow:hidden; }
  th, td { text-align:left; padding:.55rem .7rem; border-bottom:1px solid var(--border); vertical-align:top; }
  th { cursor:pointer; user-select:none; color:var(--muted); font-size:.75rem; text-transform:uppercase; letter-spacing:.04em; }
  th:hover { color:var(--text); }
  tr:last-child td { border-bottom:none; }
  td.url { max-width:340px; word-break:break-all; }
  .score { font-weight:600; }
</style>
</head>
<body>
<h1>YourWAFSucks Report</h1>
<div class="sub">Target: <strong>{{.Target}}</strong> &middot; version {{.Version}} &middot; generated {{.Generated}} UTC</div>

<div class="cards">
  <div class="card"><div class="label">Total findings</div><div class="value">{{.Total}}</div></div>
  <div class="card"><div class="label">Highest score</div><div class="value">{{.HighestScore}}</div></div>
  <div class="card"><div class="label">Severity</div>
    <div class="breakdown">{{range .SeverityBreakdown}}<span class="pill {{.Label}}">{{.Label}}: {{.Count}}</span>{{end}}</div>
  </div>
  <div class="card"><div class="label">Techniques</div>
    <div class="breakdown">{{range .TechniqueBreak}}<span class="pill">{{.Label}}: {{.Count}}</span>{{end}}</div>
  </div>
</div>

<div class="toolbar"><input type="search" id="filter" placeholder="Filter findings..."></div>

<table id="findings">
  <thead>
    <tr>
      <th data-key="technique" data-type="text">Technique</th>
      <th data-key="method" data-type="text">Method</th>
      <th data-key="url" data-type="text">URL</th>
      <th data-key="status" data-type="num">Status</th>
      <th data-key="score" data-type="num">Score</th>
      <th data-key="severity" data-type="text">Severity</th>
      <th data-key="reason" data-type="text">Reason</th>
      <th data-key="replay" data-type="num">Replay</th>
    </tr>
  </thead>
  <tbody>
    {{range .Findings}}
    <tr>
      <td>{{.Technique}}</td>
      <td>{{.Method}}</td>
      <td class="url">{{.URL}}</td>
      <td>{{.Status}}</td>
      <td class="score">{{.Score}}</td>
      <td class="{{.Severity}}">{{.Severity}}</td>
      <td>{{.Reason}}</td>
      <td>{{.ReplayCount}}</td>
    </tr>
    {{end}}
  </tbody>
</table>

<script type="application/json" id="findings-data">{{.FindingsJSON}}</script>
<script>
(function () {
  "use strict";
  var table = document.getElementById("findings");
  var tbody = table.tBodies[0];
  var filter = document.getElementById("filter");
  var headers = Array.prototype.slice.call(table.tHead.rows[0].cells);
  var dir = {};

  filter.addEventListener("input", function () {
    var q = filter.value.toLowerCase();
    Array.prototype.forEach.call(tbody.rows, function (row) {
      row.style.display = row.textContent.toLowerCase().indexOf(q) === -1 ? "none" : "";
    });
  });

  headers.forEach(function (th, index) {
    th.addEventListener("click", function () {
      var type = th.getAttribute("data-type") || "text";
      dir[index] = !dir[index];
      var rows = Array.prototype.slice.call(tbody.rows);
      rows.sort(function (a, b) {
        var av = a.cells[index].textContent.trim();
        var bv = b.cells[index].textContent.trim();
        if (type === "num") {
          return (parseFloat(av) - parseFloat(bv)) * (dir[index] ? 1 : -1);
        }
        var cmp = av.localeCompare(bv);
        return cmp * (dir[index] ? 1 : -1);
      });
      rows.forEach(function (row) { tbody.appendChild(row); });
    });
  });
})();
</script>
</body>
</html>
`
