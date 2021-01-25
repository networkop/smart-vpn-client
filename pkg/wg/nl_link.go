package wg

import (
	"fmt"
	"net"
	"os"
	"syscall"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

func (t *Tunnel) getWgLink() netlink.Link {
	link, err := netlink.LinkByName(t.intfName)
	if err != nil {
		logrus.Debugf("Failed to get link by name: %s", err)
		return nil
	}
	err = netlink.LinkSetUp(link)
	if err != nil {
		logrus.Infof("Error LinkSetUp for %s: %s", link.Attrs().Name, err)
	}
	logrus.Debugf("Found link index %d", link.Attrs().Index)
	return link
}

func (t *Tunnel) delWgLink() error {
	logrus.Debugf("delWgLink %s", t.intfName)
	err := netlink.LinkDel(t.link)
	if err != nil {
		return err
	}
	return nil
}

func (t *Tunnel) newWgLink() error {

	existingLink := t.getWgLink()
	if existingLink != nil {
		t.link = existingLink
		err := t.delWgLink()
		if err != nil {
			return fmt.Errorf("Failed to delete link %s: %s", t.intfName, err)
		}
	}

	wgLink := netlink.GenericLink{
		LinkType:  "wireguard",
		LinkAttrs: netlink.NewLinkAttrs(),
	}
	wgLink.LinkAttrs.Name = t.intfName

	err := netlink.LinkAdd(&wgLink)
	syscallErr, ok := err.(syscall.Errno)
	if ok && syscallErr == syscall.EOPNOTSUPP {
		return fmt.Errorf("Wireguard is not supported by the kernel")
	}
	if err != nil {
		return fmt.Errorf("adding net link %q: %w", t.intfName, err)
	}

	t.link = t.getWgLink()

	return nil
}

func (t *Tunnel) addIP(ip string) error {
	logrus.Debugf("Adding ip to %+v", t.link.Attrs().Name)

	_, ipNet, err := net.ParseCIDR(ip)
	if err != nil {
		return fmt.Errorf("Failed to parse IP %s: %s", ip, err)
	}
	err = netlink.AddrAdd(t.link, &netlink.Addr{IPNet: ipNet})
	if os.IsExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("Error adding IP address %q: %w", ip, err)
	}
	return nil
}
