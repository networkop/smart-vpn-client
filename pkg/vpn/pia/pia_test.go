package pia

import "testing"

func TestClientInit(t *testing.T) {
	var c Client
	if err := c.Init(); err != nil {
		t.Fatal(err)
	}
}
