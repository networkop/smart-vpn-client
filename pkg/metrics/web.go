package metrics

import (
	"fmt"
	"html/template"
	"math"
	"net"
	"net/http"
	"strings"

	"github.com/sirupsen/logrus"
)

// WebServer starts the HTML dashboard bound to the first IPv4 address of
// ifaceName (default "eth0"). Binding to a single interface prevents the
// control endpoint from being reachable via the WireGuard tunnel.
func WebServer(port int, ifaceName string, onNext func()) {
	ip, err := ifaceIP(ifaceName)
	if err != nil {
		logrus.Errorf("Web: could not resolve %q: %s — dashboard will not start", ifaceName, err)
		return
	}

	logrus.Infof("Web: binding to %s (%s)", ip, ifaceName)

	mux := http.NewServeMux()
	mux.HandleFunc("/", handleDashboard)
	mux.HandleFunc("/next", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		onNext()
		http.Redirect(w, r, "/", http.StatusSeeOther)
	})

	addr := fmt.Sprintf("%s:%d", ip, port)
	logrus.Infof("Web dashboard: http://%s/", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		logrus.Errorf("Web: %s", err)
	}
}

func ifaceIP(name string) (string, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return "", err
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return "", err
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok {
			if v4 := ipnet.IP.To4(); v4 != nil {
				return v4.String(), nil
			}
		}
	}
	return "", fmt.Errorf("no IPv4 address on %q", name)
}

// ── Page data ─────────────────────────────────────────────────────────────────

const chartPx = 200.0

type barItem struct {
	Slot     int
	HeightPx float64
	Class    string  // "normal" | "over" | "empty"
	ValueMs  float64
}

type yLabelItem struct {
	Text     string
	BottomPx float64
}

type dashData struct {
	Region        string
	Baseline      float64
	Threshold     float64
	Latency       float64
	FractionPct   float64
	StatusClass   string
	StatusText    string
	Bars          []barItem
	ThresholdPx   float64
	ShowThreshold bool
	YLabels       []yLabelItem
	ChartTotalPx  float64
}

func buildDashData() dashData {
	mfs, _ := Registry.Gather()

	var (
		baseline, latency, fraction float64
		threshold                   float64
		region                      string
		window                      [10]float64
	)

	for _, mf := range mfs {
		switch mf.GetName() {
		case "vpn_healthcheck_baseline_ms":
			if len(mf.GetMetric()) > 0 {
				baseline = mf.GetMetric()[0].GetGauge().GetValue()
			}
		case "vpn_healthcheck_latency":
			if len(mf.GetMetric()) > 0 {
				latency = mf.GetMetric()[0].GetGauge().GetValue()
			}
		case "vpn_healthcheck_average":
			if len(mf.GetMetric()) > 0 {
				fraction = mf.GetMetric()[0].GetGauge().GetValue()
			}
		case "vpn_healthcheck_degraded":
			for _, m := range mf.GetMetric() {
				threshold = m.GetGauge().GetValue()
				for _, l := range m.GetLabel() {
					if l.GetName() == "best" {
						region = l.GetValue()
					}
				}
			}
		case "vpn_healthcheck_window_ms":
			for _, m := range mf.GetMetric() {
				slot := -1
				for _, l := range m.GetLabel() {
					if l.GetName() == "slot" {
						fmt.Sscanf(l.GetValue(), "%d", &slot)
					}
				}
				if slot >= 0 && slot < 10 {
					window[slot] = m.GetGauge().GetValue()
				}
			}
		}
	}

	maxVal := threshold * 1.3
	for _, v := range window {
		if v*1.1 > maxVal {
			maxVal = v * 1.1
		}
	}
	if maxVal <= 0 {
		maxVal = 100
	}

	bars := make([]barItem, 10)
	for i, v := range window {
		hpx := 0.0
		if maxVal > 0 {
			hpx = math.Round(v / maxVal * chartPx)
		}
		cls := "normal"
		if v == 0 {
			cls = "empty"
		} else if threshold > 0 && v > threshold {
			cls = "over"
		}
		bars[i] = barItem{Slot: i, HeightPx: hpx, Class: cls, ValueMs: v}
	}

	threshPx := 0.0
	showThresh := threshold > 0 && maxVal > 0
	if showThresh {
		threshPx = math.Round(threshold / maxVal * chartPx)
	}

	yLabels := make([]yLabelItem, 5)
	for i := 0; i < 5; i++ {
		frac := float64(i) / 4.0
		yLabels[i] = yLabelItem{
			Text:     fmt.Sprintf("%.0fms", maxVal*frac),
			BottomPx: math.Round(chartPx * frac),
		}
	}

	statusClass, statusText := "green", "HEALTHY"
	if fraction > 0.5 {
		statusClass, statusText = "red", "DEGRADED"
	} else if fraction > 0 {
		statusClass, statusText = "yellow", "WARNING"
	}

	return dashData{
		Region:        region,
		Baseline:      baseline,
		Threshold:     threshold,
		Latency:       latency,
		FractionPct:   fraction * 100,
		StatusClass:   statusClass,
		StatusText:    statusText,
		Bars:          bars,
		ThresholdPx:   threshPx,
		ShowThreshold: showThresh,
		YLabels:       yLabels,
		ChartTotalPx:  chartPx + 22,
	}
}

func handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	d := buildDashData()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := dashTmpl.Execute(w, d); err != nil {
		logrus.Warnf("Web: template error: %s", err)
	}
}

var dashTmpl = template.Must(template.New("dash").Funcs(template.FuncMap{
	"repeat": strings.Repeat,
}).Parse(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta http-equiv="refresh" content="5">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>VPN Health</title>
  <style>
    :root{--bg:#0d1117;--card:#161b22;--border:#30363d;--text:#c9d1d9;--muted:#8b949e;--green:#2ea043;--red:#da3633;--yellow:#e3b341;--blue:#1f6feb}
    *{box-sizing:border-box;margin:0;padding:0}
    body{background:var(--bg);color:var(--text);font-family:ui-monospace,'Cascadia Code','Source Code Pro',monospace;padding:24px;max-width:860px;margin:0 auto}
    h1{font-size:1rem;font-weight:600;margin-bottom:18px;letter-spacing:.04em}
    .card{background:var(--card);border:1px solid var(--border);border-radius:6px;padding:16px;margin-bottom:16px}
    .stats{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:20px}
    .stat{background:var(--bg);border:1px solid var(--border);border-radius:4px;padding:6px 14px;font-size:.8rem}
    .stat b{font-weight:600}
    .green{color:var(--green)}.yellow{color:var(--yellow)}.red{color:var(--red)}
    .chart-outer{position:relative;height:{{.ChartTotalPx}}px;padding-left:52px;padding-bottom:22px}
    .chart-inner{position:relative;height:100%;display:flex;align-items:flex-end;gap:5px;border-left:1px solid var(--border);border-bottom:1px solid var(--border)}
    .bar-col{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:flex-end;position:relative;height:100%}
    .bar{width:100%;border-radius:2px 2px 0 0}
    .bar.normal{background:var(--green)}.bar.over{background:var(--red)}.bar.empty{background:transparent;height:2px}
    .slot-label{position:absolute;bottom:-18px;font-size:.65rem;color:var(--muted);user-select:none}
    .thresh-line{position:absolute;left:0;right:0;border-top:2px dashed var(--yellow);pointer-events:none}
    .thresh-label{position:absolute;right:2px;top:-16px;font-size:.65rem;color:var(--yellow);white-space:nowrap}
    .y-axis{position:absolute;left:0;top:0;bottom:22px;width:50px}
    .y-label{position:absolute;right:6px;font-size:.65rem;color:var(--muted);transform:translateY(50%);white-space:nowrap}
    .btn{background:var(--blue);color:#fff;border:none;border-radius:4px;padding:9px 22px;font-family:inherit;font-size:.9rem;cursor:pointer}
    .btn:hover{background:#388bfd}.btn:active{opacity:.8}
    .footer{font-size:.72rem;color:var(--muted);margin-top:12px}
    .footer a{color:var(--muted)}
  </style>
</head>
<body>
  <h1>&#9656; VPN Health Monitor</h1>

  <div class="card">
    <div class="stats">
      <div class="stat">Region <b>{{.Region}}</b></div>
      <div class="stat">Baseline <b>{{printf "%.0f" .Baseline}}ms</b></div>
      <div class="stat">Threshold <b>{{printf "%.0f" .Threshold}}ms</b></div>
      <div class="stat">Latest <b>{{printf "%.0f" .Latency}}ms</b></div>
      <div class="stat">Over threshold <b class="{{.StatusClass}}">{{printf "%.0f" .FractionPct}}% &mdash; {{.StatusText}}</b></div>
    </div>

    <div class="chart-outer">
      <div class="y-axis">
        {{range .YLabels}}<div class="y-label" style="bottom:{{.BottomPx}}px">{{.Text}}</div>{{end}}
      </div>
      <div class="chart-inner">
        {{range .Bars}}
        <div class="bar-col">
          <div class="bar {{.Class}}" style="height:{{.HeightPx}}px" title="slot {{.Slot}}: {{printf "%.0f" .ValueMs}}ms"></div>
          <span class="slot-label">{{.Slot}}</span>
        </div>
        {{end}}
        {{if .ShowThreshold}}
        <div class="thresh-line" style="bottom:{{.ThresholdPx}}px">
          <span class="thresh-label">&#8592; threshold</span>
        </div>
        {{end}}
      </div>
    </div>
  </div>

  <div class="card">
    <form method="POST" action="/next">
      <button class="btn" type="submit">&#8635;&nbsp; Re-elect headend</button>
    </form>
  </div>

  <p class="footer">Auto-refreshes every 5s &nbsp;&middot;&nbsp; <a href="/metrics">raw metrics</a></p>
</body>
</html>
`))
