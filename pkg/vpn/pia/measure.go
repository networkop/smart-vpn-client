package pia

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

var (
	defaultMeasureMaxWait = 1 * time.Second
	defaultMaxBestLatency = 10 * time.Second
	// lock                  = sync.RWMutex{}
)

// Measure latency to discovered headends
func (c *Client) Measure() {

	var wg sync.WaitGroup

	d := net.Dialer{Timeout: c.measureMaxWait}
	doConn := func(d net.Dialer) func(string, string) (net.Conn, error) {
		return d.Dial
	}(d)

	for id, r := range c.Headends {

		wg.Add(1)

		go func(id string, r *region, wg *sync.WaitGroup) {
			defer wg.Done()
			for _, server := range r.Servers.WG {

				url := fmt.Sprintf("%s:%d", server.IP, defaultHeadendPort)

				start := time.Now()
				_, err := doConn("tcp", url)
				if err != nil {
					logrus.Debugf("Failed to connect to wireguard headend %s: %s", server.CN, err)
				} else {

					total := time.Since(start)

					logrus.Debugf("Latency to %s was %d ms", server.CN, r.latency/time.Millisecond)

					r.latency = total

					logrus.Debugf("Latency to %s now %d ms", server.CN, r.latency/time.Millisecond)
				}

			}

			//lock.Lock()
			//c.Headends[id] = r
			//lock.Unlock()

		}(id, r, &wg)

	}

	wg.Wait()

}

// best headend is the one with lowest latency in the last round of measurements unless 'prefer' is defined
func (c *Client) bestHeadend() {
	var winnerURL string
	var winner region
	bestLatency := c.maxBestLatency

	for _, r := range c.Headends {

		// always use preferred when defined
		if c.preferVPN != "" && r.ID == c.preferVPN {

			logrus.Debugf("Using preferred candidate %s@%d ms", r.ID, (r.latency / time.Millisecond))
			bestLatency = r.latency
			winner = *r
			winnerURL = r.ID
			break
		}
		// otherwise pick the one with the lowest latency
		if (r.latency > 0) && (r.latency < bestLatency) {

			logrus.Debugf("New best candidate %s@%d ms", r.ID, (r.latency / time.Millisecond))
			bestLatency = r.latency
			winner = *r
			winnerURL = r.ID
		}
	}

	if bestLatency == c.maxBestLatency {
		logrus.Panicf("Failed to find the best VPN headend, something's gone wrong")
	}

	logrus.Infof("Winner is %s with latency %d ms", winnerURL, (bestLatency / time.Millisecond))
	c.winner = &winner
}
