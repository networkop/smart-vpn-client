package pia

// Cleanup pia configuration. Operates on c.wg, the live tunnel that holds the
// endpoint used by delBypassRoute; a throwaway wg.New() has a nil endpoint and
// link, so its Cleanup would leave the real bypass /32 and routes in place.
//
// Cleanup may be called via the standalone --cleanup flag before Init() has
// run, in which case c.wg is nil; initialise it lazily so cleanup is safe in
// both the standalone and running-monitor paths.
func (c *Client) Cleanup() error {
	if c.wg == nil {
		if err := c.initTunnel(); err != nil {
			return err
		}
	}
	c.wg.Cleanup()
	return nil
}
