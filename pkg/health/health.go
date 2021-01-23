package health

import (
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
)

var (
	checkURL = "http://google.com"
	maxWait  = 10 * time.Second
)

// Health service details
type Health struct {
	interval int
	baseline time.Duration
	lastTen  []time.Duration
}

// NewChecker creates health checking service
func NewChecker(interval int) *Health {
	return &Health{
		interval: interval,
		baseline: 0,
		lastTen:  make([]time.Duration, 10),
	}
}

// Start a periodic healthCheck loop
func (c *Health) Start(out chan bool, in chan bool) {

	doCheck := func(client http.Client) (time.Duration, error) {
		start := time.Now()
		_, err := client.Get(checkURL)
		total := time.Since(start)
		if err != nil {
			return total, err
		}
		return total, nil
	}

	for {

		select {
		case <-in:
			c.baseline = 0
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
			c.baseline = latency

		default:
			logrus.Debugf("Periodic health checking")
			client := http.Client{
				Timeout:   maxWait,
				Transport: http.DefaultTransport.(*http.Transport).Clone(),
			}
			latency, err := doCheck(client)

			c.updateLastTen(latency)

			if err != nil {
				logrus.Infof("Failed health check: %s", err)
				out <- false
			} else if c.healthDegraded() {
				logrus.Infof("Degraded health check for baseline %d: %+v", c.baseline, c.lastTen)
				out <- false
			} else {
				logrus.Debugf("Health check successful, nothing to do...")
				out <- true
			}

			time.Sleep(time.Duration(c.interval) * time.Second)

		}
	}
}

func (c *Health) updateLastTen(t time.Duration) {
	c.lastTen = append(c.lastTen[1:], t)
}

// Health is degraded when an average of the last 10 healthchecks
// exceeds the 2 x baseline taken when the connection was established
func (c *Health) healthDegraded() bool {
	if c.baseline == 0 { // baseline is not set yet
		return false
	}
	var sum, avg float64
	for _, l := range c.lastTen {
		sum += float64(l)
	}

	avg = sum / 10

	if avg > 2*float64(c.baseline) {
		return true
	}

	return false
}
