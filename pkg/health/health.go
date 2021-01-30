package health

import (
	"math"
	"net/http"
	"time"

	"github.com/networkop/smart-vpn-client/pkg/metrics"
	"github.com/sirupsen/logrus"
)

var (
	checkURL = "http://example.com"
	maxWait  = 10 * time.Second
)

// Health service details
type Health struct {
	interval int
	baseline int64
	lastTen  []int64
}

// NewChecker creates health checking service
func NewChecker(interval int) *Health {

	return &Health{
		interval: interval,
		baseline: 0,
		lastTen:  make([]int64, 10),
	}
}

// Start a periodic healthCheck loop
func (c *Health) Start(out chan bool, in chan bool) {

	doCheck := func(client http.Client) (int64, error) {
		start := time.Now()
		_, err := client.Get(checkURL)
		total := time.Since(start).Milliseconds()
		if err != nil {
			return total, err
		}
		return total, nil
	}

	for {

		select {
		case <-in:
			c.baseline = 0
			time.Sleep(time.Duration(c.interval) * time.Second)
			client := http.Client{
				Timeout:   maxWait,
				Transport: http.DefaultTransport.(*http.Transport).Clone(),
			}
			logrus.Debugf("VPN tunnel has been set up, taking the baseline measurement")

			latency, err := doCheck(client)
			if err != nil {
				logrus.Infof("Failed baseline health check: %s", err)
				break
			}

			metrics.HealthLatency.Set(float64(latency))
			logrus.Infof("New baseline is %d ms; Threshold is %d", latency, latency*10)
			c.baseline = latency

		default:
			logrus.Debugf("Periodic health checking")
			client := http.Client{
				Timeout:   maxWait,
				Transport: http.DefaultTransport.(*http.Transport).Clone(),
			}
			latency, err := doCheck(client)

			metrics.HealthLatency.Set(float64(latency))
			c.updateLastTen(latency)

			if err != nil {
				logrus.Infof("Failed health check: %s", err)
				out <- false
			} else if c.healthDegraded() {
				logrus.Infof("Degraded health check for baseline %d ms: %+v", c.baseline, c.lastTen)
				out <- false
			} else {
				logrus.Debugf("Health check successful, nothing to do...")
				out <- true
			}

			time.Sleep(time.Duration(c.interval) * time.Second)

		}
	}
}

func (c *Health) updateLastTen(t int64) {
	c.lastTen = append(c.lastTen[1:], t)
}

// Health is degraded when a weighted average of the last 10 healthchecks
// exceeds the 10 x baseline taken when the connection was established
func (c *Health) healthDegraded() bool {
	if c.baseline == 0 { // baseline is not set yet
		return false
	}
	var numerator, denominator, result float64

	logrus.Infof("Last Ten latencies: %+v", c.lastTen)
	for i := len(c.lastTen) - 1; i >= 0; i-- {
		step := len(c.lastTen) - i - 1

		numerator += float64(c.lastTen[i]) * math.Exp(-float64(step))
		denominator += math.Exp(-float64(step))

	}

	result = numerator / denominator
	metrics.LastTenAverage.Set(result)
	logrus.Infof("Weighted Average:%.2f", result)

	threshold := float64(10 * c.baseline)
	metrics.DegradationLevel.Set(threshold)

	if result > threshold {
		return true
	}

	return false
}
