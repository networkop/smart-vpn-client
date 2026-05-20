package health

import (
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/networkop/smart-vpn-client/pkg/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
)

var (
	checkURL = "http://example.com"
	maxWait  = 10 * time.Second
)

const (
	// Number of baseline samples to take and median over.
	baselineSamples = 3
	// Number of recent measurements kept.
	windowSize = 10
	// Threshold multiplier: sustained latency above baseline*degradationFactor triggers reconnect.
	degradationFactor = 5.0
	// Minimum fraction of window that must exceed the threshold before declaring degradation.
	// 0.5 means more than half — a single spike (1/10) is ignored.
	degradationQuorum = 0.5
	// Minimum number of filled (non-zero) slots required before evaluating degradation.
	minSamples = 3
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
		lastTen:  make([]int64, windowSize),
	}
}

// Start a periodic healthCheck loop
func (c *Health) Start(out chan bool, in chan string) {

	doCheck := func(client http.Client) (int64, error) {
		start := time.Now()
		_, err := client.Get(checkURL)
		total := time.Since(start).Milliseconds()
		if err != nil {
			return total, err
		}
		return total, nil
	}

	newClient := func() http.Client {
		return http.Client{
			Timeout:   maxWait,
			Transport: http.DefaultTransport.(*http.Transport).Clone(),
		}
	}

	for {
		select {
		case winner := <-in:
			c.baseline = 0
			// Reset window so stale measurements from the previous connection
			// don't influence the new one.
			c.lastTen = make([]int64, windowSize)

			time.Sleep(time.Duration(c.interval) * time.Second)

			// Take several samples and use their median as the baseline,
			// so a single elevated measurement doesn't inflate the threshold.
			var samples []int64
			for i := 0; i < baselineSamples; i++ {
				if i > 0 {
					time.Sleep(time.Duration(c.interval) * time.Second)
				}
				latency, err := doCheck(newClient())
				if err != nil {
					logrus.Infof("Failed baseline sample %d: %s", i+1, err)
					continue
				}
				samples = append(samples, latency)
			}

			if len(samples) == 0 {
				logrus.Infof("All baseline samples failed, skipping baseline")
				break
			}

			c.baseline = median(samples)
			threshold := float64(c.baseline) * degradationFactor
			metrics.HealthLatency.Set(float64(c.baseline))
			metrics.Baseline.Set(float64(c.baseline))
			metrics.DegradationLevel.With(prometheus.Labels{"best": winner}).Set(threshold)
			logrus.Infof("New baseline is %d ms (median of %d samples); threshold is %.0f ms",
				c.baseline, len(samples), threshold)

		default:
			logrus.Debugf("Periodic health checking")
			latency, err := doCheck(newClient())

			metrics.HealthLatency.Set(float64(latency))
			c.updateLastTen(latency)

			if err != nil {
				logrus.Infof("Failed health check: %s", err)
				out <- false
			} else if c.healthDegraded() {
				logrus.Infof("Degraded health: baseline %d ms, last ten: %v", c.baseline, c.lastTen)
				out <- false
			} else {
				logrus.Debugf("Health check successful")
				out <- true
			}

			time.Sleep(time.Duration(c.interval) * time.Second)
		}
	}
}

func (c *Health) updateLastTen(t int64) {
	c.lastTen = append(c.lastTen[1:], t)
}

// healthDegraded returns true when more than degradationQuorum of the filled
// window slots exceed baseline*degradationFactor.
//
// A single spike — even 100x — only affects one slot, so 1/10 slots over
// threshold does not trigger a reconnect. Sustained degradation where the
// majority of measurements are elevated does.
func (c *Health) healthDegraded() bool {
	if c.baseline == 0 {
		return false
	}

	threshold := float64(c.baseline) * degradationFactor

	var exceeded, valid int
	for i, ms := range c.lastTen {
		metrics.WindowMeasurements.WithLabelValues(fmt.Sprintf("%d", i)).Set(float64(ms))
		if ms == 0 {
			continue // unfilled slot
		}
		valid++
		if float64(ms) > threshold {
			exceeded++
		}
	}

	if valid < minSamples {
		return false // not enough data yet
	}

	logrus.Debugf("Health: %d/%d measurements exceed threshold %.0f ms", exceeded, valid, threshold)
	metrics.LastTenAverage.Set(float64(exceeded) / float64(valid))

	return float64(exceeded)/float64(valid) > degradationQuorum
}

// median returns the median value of a slice without mutating it.
func median(samples []int64) int64 {
	if len(samples) == 0 {
		return 0
	}
	sorted := make([]int64, len(samples))
	copy(sorted, samples)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	mid := len(sorted) / 2
	if len(sorted)%2 == 0 {
		return (sorted[mid-1] + sorted[mid]) / 2
	}
	return sorted[mid]
}
