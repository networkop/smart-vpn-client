// vpn-tui prints an ASCII bar chart of the VPN health-check window metrics
// served by the main smart-vpn-client process at /metrics.
//
// Default behaviour: render once and exit (suitable for docker exec).
// Pass -watch to keep refreshing in place.
//
//	docker exec <container> /tmp/metrics
//	docker exec -it <container> /tmp/metrics -watch
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// ── ANSI helpers ──────────────────────────────────────────────────────────────

const (
	ansiReset   = "\033[0m"
	ansiRed     = "\033[31m"
	ansiGreen   = "\033[32m"
	ansiYellow  = "\033[33m"
	ansiCyan    = "\033[36m"
	ansiBold    = "\033[1m"
	clearScreen = "\033[2J\033[H"
)

func colored(s, color string, noColor bool) string {
	if noColor {
		return s
	}
	return color + s + ansiReset
}

// ── Metrics parsing ───────────────────────────────────────────────────────────

type vpnState struct {
	window    [10]float64
	baseline  float64
	threshold float64
	latency   float64
	fraction  float64 // fraction of slots over threshold (0–1)
	region    string
}

func fetchMetrics(url string) (*vpnState, error) {
	resp, err := http.Get(url) //nolint:gosec
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return parseMetrics(resp.Body)
}

func parseMetrics(r io.Reader) (*vpnState, error) {
	s := &vpnState{}
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		switch {
		case strings.HasPrefix(line, "vpn_healthcheck_window_ms{slot=\""):
			rest := strings.TrimPrefix(line, "vpn_healthcheck_window_ms{slot=\"")
			parts := strings.SplitN(rest, "\"}", 2)
			if len(parts) != 2 {
				continue
			}
			slot, err := strconv.Atoi(strings.TrimSpace(parts[0]))
			if err != nil || slot < 0 || slot >= 10 {
				continue
			}
			if val, err := strconv.ParseFloat(strings.TrimSpace(parts[1]), 64); err == nil {
				s.window[slot] = val
			}

		case strings.HasPrefix(line, "vpn_healthcheck_degraded{"):
			parts := strings.SplitN(line, "} ", 2)
			if len(parts) != 2 {
				continue
			}
			if val, err := strconv.ParseFloat(strings.TrimSpace(parts[1]), 64); err == nil {
				s.threshold = val
			}
			if idx := strings.Index(line, "best=\""); idx >= 0 {
				rest := line[idx+6:]
				if end := strings.Index(rest, "\""); end >= 0 {
					s.region = rest[:end]
				}
			}

		case strings.HasPrefix(line, "vpn_healthcheck_baseline_ms "):
			if val, err := strconv.ParseFloat(strings.TrimSpace(strings.TrimPrefix(line, "vpn_healthcheck_baseline_ms ")), 64); err == nil {
				s.baseline = val
			}

		case strings.HasPrefix(line, "vpn_healthcheck_latency "):
			if val, err := strconv.ParseFloat(strings.TrimSpace(strings.TrimPrefix(line, "vpn_healthcheck_latency ")), 64); err == nil {
				s.latency = val
			}

		case strings.HasPrefix(line, "vpn_healthcheck_average "):
			if val, err := strconv.ParseFloat(strings.TrimSpace(strings.TrimPrefix(line, "vpn_healthcheck_average ")), 64); err == nil {
				s.fraction = val
			}
		}
	}
	return s, scanner.Err()
}

// ── Chart rendering ───────────────────────────────────────────────────────────

const (
	chartHeight = 16
	chartWidth  = 62
)

func renderChart(s *vpnState, noColor bool) string {
	var sb strings.Builder

	// Y-axis scale: headroom above max observed value or threshold.
	maxVal := s.threshold * 1.3
	for _, v := range s.window {
		if v*1.1 > maxVal {
			maxVal = v * 1.1
		}
	}
	if maxVal <= 0 {
		maxVal = 100
	}

	// Pre-compute bar heights and threshold-exceeded flags.
	var heights [10]int
	var overThreshold [10]bool
	for i, v := range s.window {
		heights[i] = int(math.Round(float64(chartHeight) * v / maxVal))
		overThreshold[i] = s.threshold > 0 && v > s.threshold
	}

	// Row (0=top) at which the threshold dashed line is drawn.
	thresholdRow := -1
	if s.threshold > 0 {
		thresholdRow = chartHeight - int(math.Round(float64(chartHeight)*s.threshold/maxVal))
		if thresholdRow < 0 {
			thresholdRow = 0
		}
	}

	// ── header ───────────────────────────────────────────────────────────────
	title := colored(" VPN Health Monitor ", ansiBold+ansiCyan, noColor)
	sb.WriteString("╔══" + title + strings.Repeat("═", 39) + "╗\n")

	statusStr := "● HEALTHY"
	statusColor := ansiGreen
	if s.fraction > 0.5 {
		statusStr = "● DEGRADED"
		statusColor = ansiRed
	} else if s.fraction > 0 {
		statusStr = "● WARNING"
		statusColor = ansiYellow
	}

	row1 := fmt.Sprintf("  Region: %-10s  Baseline: %5.0fms  Threshold: %5.0fms",
		s.region, s.baseline, s.threshold)
	row2 := fmt.Sprintf("  Latest:  %5.0fms  Over threshold: %3.0f%%  %s",
		s.latency, s.fraction*100, colored(statusStr, statusColor, noColor))

	sb.WriteString("║" + padVisible(row1, chartWidth) + "║\n")
	sb.WriteString("║" + padVisible(row2, chartWidth) + "║\n")
	sb.WriteString("╠" + strings.Repeat("═", chartWidth) + "╣\n")

	// ── bar chart ────────────────────────────────────────────────────────────
	for row := 0; row < chartHeight; row++ {
		yVal := maxVal * float64(chartHeight-row) / float64(chartHeight)
		yLabel := ""
		if row == 0 || row%4 == 0 || row == chartHeight-1 {
			yLabel = fmt.Sprintf("%6.0fms", yVal)
		}
		line := fmt.Sprintf("%-8s │", yLabel)

		for col := 0; col < 10; col++ {
			filled := (chartHeight - row) <= heights[col]
			var cell string
			switch {
			case filled && overThreshold[col]:
				cell = colored("███ ", ansiRed, noColor)
			case filled:
				cell = colored("███ ", ansiGreen, noColor)
			case row == thresholdRow:
				cell = colored("--- ", ansiYellow, noColor)
			default:
				cell = "    "
			}
			line += cell
		}
		if row == thresholdRow {
			line += colored(" ← threshold", ansiYellow, noColor)
		}
		sb.WriteString("║ " + line + "\n")
	}

	// ── x-axis ───────────────────────────────────────────────────────────────
	sb.WriteString("║ " + "         └" + strings.Repeat("────", 10) + "\n")
	slots := "           "
	for i := 0; i < 10; i++ {
		slots += fmt.Sprintf(" %-3d", i)
	}
	sb.WriteString("║ " + slots + "  oldest→newest\n")
	sb.WriteString("╚" + strings.Repeat("═", chartWidth) + "╝\n")

	return sb.String()
}

// padVisible pads s so its visible (ANSI-stripped) length equals n.
func padVisible(s string, n int) string {
	diff := n - len(stripANSI(s))
	if diff > 0 {
		return s + strings.Repeat(" ", diff)
	}
	return s
}

func stripANSI(s string) string {
	var out strings.Builder
	inEsc := false
	for _, r := range s {
		switch {
		case r == '\033':
			inEsc = true
		case inEsc && r == 'm':
			inEsc = false
		case !inEsc:
			out.WriteRune(r)
		}
	}
	return out.String()
}

// ── Main ──────────────────────────────────────────────────────────────────────

func main() {
	urlFlag      := flag.String("url", "http://localhost:2112/metrics", "Metrics endpoint URL")
	intervalFlag := flag.Int("interval", 5, "Refresh interval in seconds (only used with -watch)")
	watchFlag    := flag.Bool("watch", false, "Keep refreshing in place (requires -it on docker exec)")
	noColorFlag  := flag.Bool("no-color", false, "Disable ANSI colour output")
	flag.Parse()

	draw := func(clear bool) {
		s, err := fetchMetrics(*urlFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error fetching %s: %v\n", *urlFlag, err)
			os.Exit(1)
		}
		if clear {
			fmt.Print(clearScreen)
		}
		fmt.Print(renderChart(s, *noColorFlag))
	}

	draw(false)

	if !*watchFlag {
		return
	}

	fmt.Printf("\n  refreshing every %ds — ctrl-c to quit\n", *intervalFlag)
	ticker := time.NewTicker(time.Duration(*intervalFlag) * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		draw(true)
		fmt.Printf("\n  refreshing every %ds — ctrl-c to quit\n", *intervalFlag)
	}
}
