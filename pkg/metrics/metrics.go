package metrics

import (
	"net/http"

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
	DegradationLevel = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: "healthcheck",
		Name:      "degraded",
		Help:      "Latency degradation threshold",
	})
)

func Server() {
	r := prometheus.NewRegistry()
	r.MustRegister(HealthLatency)
	r.MustRegister(LastTenAverage)
	r.MustRegister(DegradationLevel)
	handler := promhttp.HandlerFor(r, promhttp.HandlerOpts{})
	http.Handle("/metrics", handler)

	logrus.Fatal(http.ListenAndServe(":2112", nil))
}
