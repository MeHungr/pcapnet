package pcapnet

import (
	"fmt"
	"net/netip"
	"strings"
)

// maxUDPInnerMTU is the largest inner packet that fits in an IPv4 datagram
// with a standard IPv4 header and a UDP header, without fragmentation.
const maxUDPInnerMTU = 65535 - outerIPv4HeaderSize - outerUDPHeaderSize

// PCAPConfig describes the physical IPv4/UDP tunnel to one fixed peer.
// Virtual addresses remain in Config and are carried inside the UDP payload.
type PCAPConfig struct {
	// DeviceName identifies the Ethernet capture device used for both capture
	// and injection. Empty selects the device matching the physical peer route.
	// Explicit names are validated against that route when opening PCAP.
	DeviceName string

	// LocalPort is the nonzero outer UDP source port. The source IPv4 address
	// is selected during route lookup.
	LocalPort uint16

	// ReserveUDPPort binds a host UDP socket on the selected source address
	// and LocalPort for the tunnel's lifetime. The default, false, leaves the
	// port unreserved. Without a reservation, host applications can bind the
	// port and the host may send ICMP port-unreachable replies to tunnel traffic.
	// A CLI can set this option directly without changing packet I/O behavior.
	ReserveUDPPort bool

	// Peer is the physical IPv4 address and nonzero UDP port of the peer.
	// It is independent of Config.PeerSubnet.
	Peer netip.AddrPort

	// MTU is the maximum inner IPv4 packet size, including its IP header.
	// Zero selects DefaultMTU. It must match the attached virtual stack's MTU
	// and fit the physical route; those checks occur during tunnel setup.
	MTU uint32
}

// normalize validates settings that do not require a capture device or route.
// Physical MTU validation is deferred until the interface has been resolved.
func (c PCAPConfig) normalize() (PCAPConfig, error) {
	// Keep device names unchanged because capture drivers define their syntax.
	if c.DeviceName != "" && strings.TrimSpace(c.DeviceName) == "" {
		return c, fmt.Errorf("capture device name cannot contain only whitespace")
	}

	if c.LocalPort == 0 {
		return c, fmt.Errorf("local UDP port must be nonzero")
	}

	// Reject addresses unsuitable for a fixed Ethernet IPv4 peer. In
	// particular, IPv4-mapped IPv6 addresses must not bypass IPv4 validation.
	ip := c.Peer.Addr()
	if !validVirtualIP(ip) || ip == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return c, fmt.Errorf("peer must be a unicast IPv4 address")
	}
	if c.Peer.Port() == 0 {
		return c, fmt.Errorf("peer UDP port must be nonzero")
	}

	if c.MTU == 0 {
		c.MTU = DefaultMTU
	}
	if c.MTU < MinIPv4MTU || c.MTU > maxUDPInnerMTU {
		return c, fmt.Errorf("tunnel MTU must be between %d and %d", MinIPv4MTU, maxUDPInnerMTU)
	}

	return c, nil
}
