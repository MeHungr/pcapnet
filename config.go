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
	// DeviceName is retained for compatibility with existing callers.
	// New tunnel configuration uses PCAPConfig.DeviceName instead.
	DeviceName string

	// IPv4 address belonging to this gVisor endpoint.
	VirtualIP netip.Addr

	// IPv4 address belonging to the peer's gVisor endpoint.
	PeerVirtualIP netip.Addr

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

	if !validVirtualIP(c.PeerVirtualIP) {
		return c, fmt.Errorf("invalid peer virtual IPv4 address")
	}

	if c.VirtualIP == c.PeerVirtualIP {
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
