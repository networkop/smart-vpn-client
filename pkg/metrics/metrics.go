package metrics

import (
	"net/http"
	"fmt"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
)

const namespace = "vpn"

var (
	HealthLatency = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: "healthcheck",
		Name:      "latency",
		Help:      "Health-check latency",
	})
	LastTenAverage = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: "healthcheck",
		Name:      "average",
		Help:      "Weighted-average of last 10 healthchecks",
	})
	DegradationLevel = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: "healthcheck",
		Name:      "degraded",
		Help:      "Latency degradation threshold",
	},
		[]string{"best"},
	)
	// WindowMeasurements exposes each slot of the rolling measurement window
	// as a separate labelled series, so individual values are visible in dashboards.
	// slot="0" is the oldest, slot="9" is the most recent.
	WindowMeasurements = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: "healthcheck",
		Name:      "window_ms",
		Help:      "Individual latency measurements in the rolling window (ms). slot=0 is oldest, slot=9 is most recent.",
	},
		[]string{"slot"},
	)
)

func Server(metricsPort int) {
	r := prometheus.NewRegistry()
	r.MustRegister(HealthLatency)
	r.MustRegister(LastTenAverage)
	r.MustRegister(DegradationLevel)
	r.MustRegister(WindowMeasurements)
	handler := promhttp.HandlerFor(r, promhttp.HandlerOpts{})
	http.Handle("/metrics", handler)

	url := fmt.Sprintf(":%d", metricsPort)
	logrus.Fatal(http.ListenAndServe(url, nil))
}
