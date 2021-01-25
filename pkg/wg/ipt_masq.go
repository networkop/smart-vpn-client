package wg

import (
	"github.com/networkop/smart-vpn-client/pkg/util"
)

const (
	postRoutingChain = "POSTROUTING"
	masqueradeAction = "MASQUERADE"
)

func iptablesNat() *util.Command {
	return util.NewCommand("iptables").With("-t").With("nat")
}

// EnsureMasquerade iptable rules are set up
func (t *Tunnel) EnsureMasquerade() error {

	if _, err := t.getIPtables(); err != nil {
		_, err := t.addIPtables()
		return err
	}

	return nil
}

func (t *Tunnel) getIPtables() (string, error) {
	ipt := iptablesNat()
	ipt.
		With("-C").
		With(postRoutingChain).
		With("-o").
		With(t.intfName).
		With("-j").
		With(masqueradeAction)
	out, err := ipt.Run()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func (t *Tunnel) addIPtables() (string, error) {
	ipt := iptablesNat()
	ipt.
		With("-I").
		With(postRoutingChain).
		With("1").
		With("-o").
		With(t.intfName).
		With("-j").
		With(masqueradeAction)

	out, err := ipt.Run()
	if err != nil {
		return string(out), err
	}
	return string(out), nil
}

func (t *Tunnel) delIPtables() (string, error) {
	if _, err := t.getIPtables(); err != nil {
		return "", err
	}

	ipt := iptablesNat()
	ipt.
		With("-D").
		With(postRoutingChain).
		With("-o").
		With(t.intfName).
		With("-j").
		With(masqueradeAction)

	out, err := ipt.Run()
	if err != nil {
		return string(out), err
	}
	return string(out), nil
}
