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

// bestHeadend selects the lowest-latency available headend.
// excludeID, if non-empty, is skipped — used by forced re-election to
// guarantee a different region is chosen.
func (c *Client) bestHeadend(excludeID string) {
	var winnerURL string
	var winner region
	bestLatency := c.maxBestLatency

	for _, r := range c.Headends {

		// skip the explicitly excluded region (forced re-election)
		if excludeID != "" && r.ID == excludeID {
			continue
		}

		// skip regions that recently failed to connect
		if failedAt, ok := c.failedRegions[r.ID]; ok && time.Since(failedAt) < connectFailureCooldown {
			logrus.Debugf("Skipping %s: connect failed %s ago", r.ID, time.Since(failedAt).Round(time.Second))
			continue
		}

		// always use preferred when defined
		if c.preferVPN != "" && r.ID == c.preferVPN {
			logrus.Debugf("Using preferred candidate %s@%d ms", r.displayName(), (r.latency / time.Millisecond))
			bestLatency = r.latency
			winner = *r
			winnerURL = r.displayName()
			break
		}
		// otherwise pick the one with the lowest latency
		if (r.latency > 0) && (r.latency < bestLatency) {
			logrus.Debugf("New best candidate %s@%d ms", r.displayName(), (r.latency / time.Millisecond))
			bestLatency = r.latency
			winner = *r
			winnerURL = r.displayName()
		}
	}

	if bestLatency == c.maxBestLatency {
		logrus.Panicf("Failed to find the best VPN headend, something's gone wrong")
	}

	logrus.Infof("Winner is %s with latency %d ms", winnerURL, (bestLatency / time.Millisecond))
	c.winner = &winner
}
