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
)

func Server(metricsPort int) {
	r := prometheus.NewRegistry()
	r.MustRegister(HealthLatency)
	r.MustRegister(LastTenAverage)
	r.MustRegister(DegradationLevel)
	handler := promhttp.HandlerFor(r, promhttp.HandlerOpts{})
	http.Handle("/metrics", handler)

	url := fmt.Sprintf(":%d", metricsPort)
	logrus.Fatal(http.ListenAndServe(url, nil))
}
