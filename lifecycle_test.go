package pcapnet

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// TestVirtualStackClose verifies that closing a VirtualStack
// prevents new TCP connections and listeners.
func TestVirtualStackClose(t *testing.T) {
	// Create an in-memory virtual stack.
	v, err := NewVirtualStack(newTestConfig())
	if err != nil {
		t.Fatal(err)
	}

	// Close the virtual stack.
	v.Close()

	// Verify that the stack rejects new listeners.
	listener, err := v.Listen(6767)
	if listener != nil {
		_ = listener.Close()
		t.Fatal("expected no listener after shutdown")
	}

	if !errors.Is(err, ErrClosed) {
		t.Fatalf("expected ErrClosed, got %v", err)
	}

	// Verify that the stack rejects new dial operations.
	conn, err := v.Dial(
		context.Background(),
		"10.200.0.2",
		6767,
	)
	if conn != nil {
		_ = conn.Close()
		t.Fatal("expected no connection after shutdown")
	}

	if !errors.Is(err, ErrClosed) {
		t.Fatalf("expected ErrClosed, got %v", err)
	}
}

// TestVirtualStackConcurrentClose verifies that multiple goroutines
// can close the same VirtualStack without causing a panic or data race.
func TestVirtualStackConcurrentClose(t *testing.T) {
	// Create an in-memory virtual stack.
	v, err := NewVirtualStack(newTestConfig())
	if err != nil {
		t.Fatal(err)
	}

	// Start multiple concurrent shutdown operations.
	var wg sync.WaitGroup

	for i := 0; i < 100; i++ {
		wg.Add(1)

		go func() {
			defer wg.Done()

			// Attempt to close the shared stack.
			v.Close()
		}()
	}

	// Wait for every shutdown operation to complete.
	wg.Wait()

	// Verify that shutdown was completed.
	v.mu.Lock()
	closing := v.closing
	v.mu.Unlock()

	if !closing {
		t.Fatal("expected virtual stack to be closed")
	}
}

// TestVirtualStackClosesListener verifies that closing the stack
// automatically closes its active TCP listeners.
func TestVirtualStackClosesListener(t *testing.T) {
	// Create an in-memory virtual stack.
	v, err := NewVirtualStack(newTestConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()

	// Create a TCP listener.
	listener, err := v.Listen(6767)
	if err != nil {
		t.Fatal(err)
	}

	// Start a goroutine waiting for a connection.
	acceptDone := make(chan error, 1)

	go func() {
		// Accept should unblock when the listener closes.
		conn, err := listener.Accept()
		if conn != nil {
			_ = conn.Close()
		}

		acceptDone <- err
	}()

	// Close the stack and all of its listeners.
	v.Close()

	// Verify that Accept terminates.
	select {
	case err := <-acceptDone:
		if err == nil {
			t.Fatal("expected Accept to fail after shutdown")
		}

	case <-time.After(3 * time.Second):
		t.Fatal("Accept remained blocked after shutdown")
	}
}

// TestVirtualStackConnectionRegistration verifies that tracked
// TCP connections are automatically closed during shutdown.
func TestVirtualStackConnectionRegistration(t *testing.T) {
	// Create an in-memory virtual stack.
	v, err := NewVirtualStack(newTestConfig())
	if err != nil {
		t.Fatal(err)
	}

	// Create a local mock connection using net.Pipe.
	local, remote := net.Pipe()
	defer remote.Close()

	// Register the connection with the virtual stack.
	conn, err := v.registerConn(local)
	if err != nil {
		t.Fatal(err)
	}

	// Verify that the connection was registered.
	v.mu.Lock()
	count := len(v.conns)
	v.mu.Unlock()

	if count != 1 {
		t.Fatalf("expected 1 connection, got %d", count)
	}

	// Close the stack.
	v.Close()

	// Verify that the connection was unregistered.
	v.mu.Lock()
	count = len(v.conns)
	v.mu.Unlock()

	if count != 0 {
		t.Fatalf("expected 0 connections, got %d", count)
	}

	// Verify that the underlying connection is closed.
	if _, err := conn.Write([]byte("test")); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("expected io.ErrClosedPipe, got %v", err)
	}
}
