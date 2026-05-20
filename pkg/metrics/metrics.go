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
)

func init() {
	Registry.MustRegister(HealthLatency)
	Registry.MustRegister(Baseline)
	Registry.MustRegister(LastTenAverage)
	Registry.MustRegister(DegradationLevel)
	Registry.MustRegister(WindowMeasurements)
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
