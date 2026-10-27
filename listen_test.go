package pcapnet

import (
	"net"
	"testing"
)

// TestListen verifies that a TCP listener can be created
// on the configured virtual IPv4 address.
func TestListen(t *testing.T) {
	// Initialize a virtual TCP/IP stack.
	v, err := NewVirtualStack(newTestConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()

	// Start listening on the virtual TCP port.
	listener, err := v.Listen(6767)
	if err != nil {
		t.Fatalf("Listen() failed: %v", err)
	}
	defer listener.Close()

	// Retrieve the listener's local TCP address.
	addr, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf(
			"unexpected listener address type %T",
			listener.Addr(),
		)
	}

	// Verify that the listener uses the virtual IP.
	wantIP := net.ParseIP("10.200.0.1")

	if !addr.IP.Equal(wantIP) {
		t.Errorf("listener IP = %s, want %s", addr.IP, wantIP)
	}

	// Verify that the listener uses the requested TCP port.
	if addr.Port != 6767 {
		t.Errorf("listener port = %d, want 6767", addr.Port)
	}
}

// TestListenInvalidPort verifies that invalid TCP ports
// are rejected before creating a listener.
func TestListenInvalidPort(t *testing.T) {
	// Initialize a virtual TCP/IP stack.
	v, err := NewVirtualStack(newTestConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()

	// Test invalid listening ports.
	for _, port := range []int{-1, 0, 65536} {
		// Attempt to create the listener.
		listener, err := v.Listen(port)

		if err == nil {
			listener.Close()
			t.Fatalf("expected error for port %d", port)
		}
	}
}

// TestListenDuplicatePort verifies that two listeners
// cannot bind the same virtual address and TCP port.
func TestListenDuplicatePort(t *testing.T) {
	// Initialize a virtual TCP/IP stack.
	v, err := NewVirtualStack(newTestConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()

	// Create the first TCP listener.
	first, err := v.Listen(6767)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()

	// Attempt to create a second listener on the same port.
	second, err := v.Listen(6767)
	if err == nil {
		second.Close()
		t.Fatal("expected duplicate port binding error")
	}
}

// TestListenNilStack verifies that an uninitialized
// virtual stack cannot create TCP listeners.
func TestListenNilStack(t *testing.T) {
	// Declare an uninitialized virtual stack.
	var v *VirtualStack

	// Attempt to create a listener.
	listener, err := v.Listen(6767)

	if err == nil {
		listener.Close()
		t.Fatal("expected uninitialized stack error")
	}
}
