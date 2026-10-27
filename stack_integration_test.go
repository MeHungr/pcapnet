package pcapnet

import (
	"bytes"
	"context"
	"io"
	"net/netip"
	"testing"
	"time"
)

// TestVirtualStacksTCPEcho verifies that two independent gVisor TCP/IP
// stacks can establish a TCP connection and exchange application data.
func TestVirtualStacksTCPEcho(t *testing.T) {
	// Set a timeout for the complete integration test.
	ctx, cancel := context.WithTimeout(
		context.Background(),
		5*time.Second,
	)
	defer cancel()

	// Create transports before attaching them. Successful construction transfers
	// ownership to each stack; constructor failures leave cleanup to this test.
	controlTransport, targetTransport := NewMemoryPair(256)

	// Create the control host's in-memory TCP/IP stack.
	control, err := NewVirtualStackWithTransport(Config{
		VirtualIP:  netip.MustParseAddr("10.200.0.1"),
		PeerSubnet: netip.MustParsePrefix("10.200.0.2/32"),
		MTU:        1200,
	}, controlTransport)
	if err != nil {
		_ = controlTransport.Close()
		_ = targetTransport.Close()
		t.Fatalf("create control stack: %v", err)
	}
	defer control.Close()

	// Create the target host's in-memory TCP/IP stack.
	target, err := NewVirtualStackWithTransport(Config{
		VirtualIP:  netip.MustParseAddr("10.200.0.2"),
		PeerSubnet: netip.MustParsePrefix("10.200.0.1/32"),
		MTU:        1200,
	}, targetTransport)
	if err != nil {
		_ = targetTransport.Close()
		t.Fatalf("create target stack: %v", err)
	}
	defer target.Close()

	// Create a TCP listener using the public pcapnet API.
	listener, err := target.Listen(6767)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	// Create a channel to receive the server worker's result.
	serverDone := make(chan error, 1)

	// Start the TCP echo server.
	go func() {
		// Accept an incoming TCP connection.
		conn, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()

		// Echo all received application data back to the client.
		_, err = io.Copy(conn, conn)

		// Report the server's result.
		serverDone <- err
	}()

	// Establish a TCP connection through the control's virtual stack.
	conn, err := control.Dial(
		ctx,          // Dial context
		"10.200.0.2", // Target virtual IPv4 address
		6767,         // Target TCP port
	)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Set a deadline for the TCP connection's read and write operations.
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}

	// Prepare the message that the control host will send.
	message := bytes.Repeat([]byte("hello from gVisor"), 1024)

	// Send the message through the TCP connection.
	if _, err := conn.Write(message); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Allocate a buffer to receive the echoed message.
	response := make([]byte, len(message))

	// Read the complete echoed response.
	if _, err := io.ReadFull(conn, response); err != nil {
		t.Fatalf("read: %v", err)
	}

	// Verify that the response matches the original message.
	if !bytes.Equal(response, message) {
		t.Fatalf(
			"echo mismatch: received %d bytes, expected %d bytes",
			len(response),
			len(message),
		)
	}

	t.Logf("TCP echo successful: %d bytes across the production bridge", len(response))

	// Close the client connection to signal EOF to the echo server.
	if err := conn.Close(); err != nil {
		t.Fatalf("close client: %v", err)
	}

	// Wait for the TCP echo server to finish.
	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatalf("server: %v", err)
		}

	case <-ctx.Done():
		t.Fatal("server did not finish before timeout")
	}
}
