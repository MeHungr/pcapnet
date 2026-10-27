package pcapnet

import (
	"net/netip"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
)

// newTestConfig creates a generic test Config
func newTestConfig() Config {
	return Config{
		VirtualIP:     netip.MustParseAddr("10.200.0.1"),
		PeerVirtualIP: netip.MustParseAddr("10.200.0.2"),
		MTU:           1200,
	}
}

// TestNewVirtualStack tests that a VirtualStack is properly created
func TestNewVirtualStack(t *testing.T) {
	v, err := NewVirtualStack(newTestConfig())
	if err != nil {
		t.Fatalf("NewVirtualStack() failed: %v", err)
	}
	defer v.Close()

	if v.Stack == nil {
		t.Fatal("gVisor stack is nil")
	}

	if v.Link == nil {
		t.Fatal("gVisor channel endpoint is nil")
	}

	if got := v.Link.MTU(); got != 1200 {
		t.Errorf("MTU = %d, want 1200", got)
	}
}

// TestVirtualStackAddress tests that a virtual address can be properly assigned to an interface
func TestVirtualStackAddress(t *testing.T) {
	cfg := newTestConfig()

	v, err := NewVirtualStack(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()

	addresses := v.Stack.AllAddresses()
	nicAddresses, exists := addresses[virtualNICID]

	if !exists {
		t.Fatal("virtual NIC not found")
	}

	want := tcpip.AddrFrom4(cfg.VirtualIP.As4())
	found := false

	for _, addr := range nicAddresses {
		if addr.Protocol != ipv4.ProtocolNumber {
			continue
		}

		if addr.AddressWithPrefix.Address == want &&
			addr.AddressWithPrefix.PrefixLen == 32 {
			found = true
			break
		}
	}

	if !found {
		t.Fatalf("virtual address %s/32 not assigned", cfg.VirtualIP)
	}
}

// TestVirtualStackRoute tests that a route to a virtual peer can be properly established
func TestVirtualStackRoute(t *testing.T) {
	cfg := newTestConfig()

	v, err := NewVirtualStack(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()

	routes := v.Stack.GetRouteTable()
	want := tcpip.AddrFrom4(cfg.PeerVirtualIP.As4())

	found := false

	for _, route := range routes {
		if route.NIC != virtualNICID {
			continue
		}

		if route.Destination.Contains(want) {
			found = true
			break
		}

		if !found {
			t.Fatalf("no route to peer %s through virtual NIC", cfg.PeerVirtualIP)
		}
	}
}

// TestVirtualStackInvalidConfig tests that a VirtualStack cannot be created with an invalid Config
func TestVirtualStackInvalidConfig(t *testing.T) {
	_, err := NewVirtualStack(Config{})

	if err == nil {
		t.Fatal("expected invalid configuration error")
	}
}
