package pia

import "github.com/networkop/smart-vpn-client/pkg/wg"

// Cleanup pia configuration
func (c *Client) Cleanup() error {
	wg, err := wg.New()
	if err != nil {
		return err
	}

	wg.Cleanup()
	return nil
}
