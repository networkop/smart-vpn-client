package pia

// Cleanup pia configuration. Must operate on c.wg, the live tunnel that holds
// the endpoint used by delBypassRoute; a throwaway wg.New() has a nil endpoint
// and link, so its Cleanup leaves the real bypass /32 and routes in place.
func (c *Client) Cleanup() error {
	c.wg.Cleanup()
	return nil
}
