package pcapnet

import (
	"fmt"
	"net/netip"
)

const (
	DefaultMTU = 1200
	MinIPv4MTU = 576
)

// A Config represents the gVisor endpoint configuration.
type Config struct {
	// IPv4 address belonging to this gVisor endpoint.
	VirtualIP netip.Addr

	// Permitted remote IPv4 addresses routed through the tunnel.
	PeerSubnet netip.Prefix

	// MTU of the in-memory gVisor link.
	MTU uint32
}

// normalize returns a normalized Config, ensuring all values are valid.
func (c Config) normalize() (Config, error) {
	if c.MTU == 0 {
		c.MTU = DefaultMTU
	}

	if !validVirtualIP(c.VirtualIP) {
		return c, fmt.Errorf("invalid virtual IPv4 address")
	}

	if !c.PeerSubnet.IsValid() || !c.PeerSubnet.Addr().Is4() || c.PeerSubnet.Bits() == 0 || !validVirtualIP(c.PeerSubnet.Masked().Addr()) {
		return c, fmt.Errorf("invalid peer IPv4 subnet")
	}

	c.PeerSubnet = c.PeerSubnet.Masked()
	if c.PeerSubnet.Bits() == 32 && c.VirtualIP == c.PeerSubnet.Addr() {
		return c, fmt.Errorf("virtual IP and peer virtual IP must differ")
	}

	if c.MTU < MinIPv4MTU || c.MTU > 65535 {
		return c, fmt.Errorf("MTU must be between %d and 65535", MinIPv4MTU)
	}

	return c, nil
}

// validVirtualIP reports whether a netip.Addr is a valid IPv4 host address
func validVirtualIP(ip netip.Addr) bool {
	return ip.IsValid() &&
		ip.Is4() &&
		!ip.IsUnspecified() &&
		!ip.IsMulticast() &&
		!ip.IsLoopback() &&
		!ip.Is4In6()
}
