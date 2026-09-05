package metrics

import (
	"fmt"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
)

const namespace = "vpn"

// Registry is exported so web.go can Gather from it.
var Registry = prometheus.NewRegistry()

var (
	HealthLatency = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: "healthcheck",
		Name:      "latency",
		Help:      "Health-check latency (ms)",
	})
	Baseline = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: "healthcheck",
		Name:      "baseline_ms",
		Help:      "Median baseline latency established after tunnel connect (ms)",
	})
	LastTenAverage = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: "healthcheck",
		Name:      "average",
		Help:      "Fraction of rolling window slots that exceed the degradation threshold (0–1)",
	})
	DegradationLevel = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: "healthcheck",
		Name:      "degraded",
		Help:      "Latency degradation threshold (ms)",
	},
		[]string{"best"},
	)
	WindowMeasurements = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: "healthcheck",
		Name:      "window_ms",
		Help:      "Individual latency measurements in the rolling window (ms). slot=0 is oldest, slot=9 is most recent.",
	},
		[]string{"slot"},
	)
	// BypassEnabled is 1 whenever -bypass-mark is set, regardless of whether
	// the rules are currently installed. Paired with BypassRulePresent it
	// separates "the split-tunnel bypass is switched off" from "it is switched
	// on but not working", which otherwise look identical from outside.
	BypassEnabled = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: "bypass",
		Name:      "enabled",
		Help:      "1 when a split-tunnel bypass fwmark is configured",
	})
	// BypassRulePresent is 1 only when both halves of the bypass are in place:
	// the ip rule matching the fwmark and the bypass table's default route.
	// Either one alone diverts nothing.
	BypassRulePresent = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: "bypass",
		Name:      "rule_present",
		Help:      "1 when the bypass ip rule and the bypass table default route are both installed",
	})
)

func init() {
	Registry.MustRegister(HealthLatency)
	Registry.MustRegister(Baseline)
	Registry.MustRegister(LastTenAverage)
	Registry.MustRegister(DegradationLevel)
	Registry.MustRegister(WindowMeasurements)
	Registry.MustRegister(BypassEnabled)
	Registry.MustRegister(BypassRulePresent)
}

// Server starts the Prometheus metrics endpoint and the /api/next control endpoint.
func Server(metricsPort int, onNext func()) {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(Registry, promhttp.HandlerOpts{}))
	mux.HandleFunc("/api/next", func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		onNext()
		w.WriteHeader(http.StatusAccepted)
		fmt.Fprintln(w, "headend re-election triggered")
	})

	addr := fmt.Sprintf(":%d", metricsPort)
	logrus.Fatal(http.ListenAndServe(addr, mux))
}
