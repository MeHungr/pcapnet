package pcapnet

import (
	"context"
	"net/netip"
	"strings"
	"testing"
)

// TestDialValidation verifies that Dial rejects invalid
// destinations and TCP ports before attempting a handshake.
func TestDialValidation(t *testing.T) {
	// Initialize a virtual TCP/IP stack.
	v, err := NewVirtualStack(newTestConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()

	// Define invalid dialing scenarios.
	tests := []struct {
		name string
		ip   string
		port int
	}{
		{
			name: "invalid IP",
			ip:   "not-an-ip",
			port: 6767,
		},
		{
			name: "incorrect peer",
			ip:   "10.200.0.3",
			port: 6767,
		},
		{
			name: "IPv6 destination",
			ip:   "2001:db8::1",
			port: 6767,
		},
		{
			name: "zero port",
			ip:   "10.200.0.2",
			port: 0,
		},
		{
			name: "port too large",
			ip:   "10.200.0.2",
			port: 65536,
		},
	}

	// Execute every validation scenario.
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Attempt to dial the invalid destination.
			conn, err := v.Dial(
				context.Background(),
				tt.ip,
				tt.port,
			)

			// Ensure the destination was rejected.
			if err == nil {
				conn.Close()
				t.Fatal("expected dialing error")
			}
		})
	}
}

// TestDialCanceledContext verifies that Dial honors a
// context that has already been canceled.
func TestDialCanceledContext(t *testing.T) {
	// Initialize a virtual stack.
	v, err := NewVirtualStack(newTestConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()

	// Create and immediately cancel the context.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Attempt to dial the configured peer.
	conn, err := v.Dial(ctx, "10.200.0.2", 6767)
	if conn != nil {
		conn.Close()
		t.Fatal("expected no connection")
	}

	// Verify that the cancellation was propagated.
	if err != context.Canceled {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

// TestDialNilStack verifies that an uninitialized virtual
// stack cannot establish connections.
func TestDialNilStack(t *testing.T) {
	// Declare an uninitialized virtual stack.
	var v *VirtualStack

	// Attempt to establish a connection.
	conn, err := v.Dial(
		context.Background(),
		"10.200.0.2",
		6767,
	)

	if err == nil {
		conn.Close()
		t.Fatal("expected uninitialized stack error")
	}

	if !strings.Contains(err.Error(), "not initialized") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestDialConfiguration verifies that the configured
// virtual peer address is preserved.
func TestDialConfiguration(t *testing.T) {
	// Initialize a virtual stack.
	v, err := NewVirtualStack(newTestConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()

	// Verify the configured peer IP.
	want := netip.MustParseAddr("10.200.0.2")

	if v.config.PeerSubnet.Addr() != want {
		t.Fatalf(
			"peer IP = %s, want %s",
			v.config.PeerSubnet,
			want,
		)
	}
}
