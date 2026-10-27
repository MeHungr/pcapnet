package pcapnet

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// TestMemoryTransportBidirectional tests that the MemoryTransport sends and receives the proper data
func TestMemoryTransportBidirectional(t *testing.T) {
	a, b := NewMemoryPair(16)
	defer a.Close()

	ctx := context.Background()

	aMessage := []byte("hello from A")
	bMessage := []byte("hello from B")

	if err := a.Send(ctx, aMessage); err != nil {
		t.Fatal(err)
	}

	if err := b.Send(ctx, bMessage); err != nil {
		t.Fatal(err)
	}

	receivedB, err := b.Receive(ctx)
	if err != nil {
		t.Fatal(err)
	}

	receivedA, err := a.Receive(ctx)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(receivedB, aMessage) {
		t.Errorf("B received %q, want %q", receivedB, aMessage)
	}

	if !bytes.Equal(receivedA, bMessage) {
		t.Errorf("A received %q, want %q", receivedA, bMessage)
	}
}

// TestMemoryTransportOrdering tests that packets are received in the same order they were sent
func TestMemoryTransportOrdering(t *testing.T) {
	a, b := NewMemoryPair(10)
	defer a.Close()

	ctx := context.Background()

	for i := byte(0); i < 10; i++ {
		if err := a.Send(ctx, []byte{i}); err != nil {
			t.Fatal(err)
		}
	}

	for i := byte(0); i < 10; i++ {
		packet, err := b.Receive(ctx)
		if err != nil {
			t.Fatal(err)
		}

		if len(packet) != 1 || packet[0] != i {
			t.Fatalf("packet %d: got %v", i, packet)
		}
	}
}

// TestMemoryTransportCopiesPackets tests that the transport copies the packet and sends the copy instead of the original
func TestMemoryTransportCopiesPackets(t *testing.T) {
	a, b := NewMemoryPair(1)
	defer a.Close()

	ctx := context.Background()
	original := []byte{1, 2, 3, 4}

	if err := a.Send(ctx, original); err != nil {
		t.Fatal(err)
	}

	original[0] = 99

	received, err := b.Receive(ctx)
	if err != nil {
		t.Fatal(err)
	}

	if received[0] != 1 {
		t.Fatal("transport did not copy the packet")
	}
}

// TestMemoryTransportReceiveCancellation tests that a canceled context returns the proper error
func TestMemoryTransportReceiveCancellation(t *testing.T) {
	a, _ := NewMemoryPair(1)
	defer a.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := a.Receive(ctx)

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

// TestMemoryTransportSendTimeout tests that a context with exceeded deadline returns the proper error
func TestMemoryTransportSendTimeout(t *testing.T) {
	a, _ := NewMemoryPair(1)
	defer a.Close()

	// Fill the queue so the next send blocks.
	if err := a.Send(context.Background(), []byte{1}); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(
		context.Background(),
		100*time.Millisecond,
	)
	defer cancel()

	err := a.Send(ctx, []byte{2})

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline exceeded, got %v", err)
	}
}

// TestMemoryTransportCloseUnblocksReceive tests that closing the transport unblocks the Receive() function
func TestMemoryTransportCloseUnblocksReceive(t *testing.T) {
	a, b := NewMemoryPair(1)

	result := make(chan error, 1)

	go func() {
		_, err := b.Receive(context.Background())
		result <- err
	}()

	if err := a.Close(); err != nil {
		t.Fatal(err)
	}

	select {
	case err := <-result:
		if !errors.Is(err, ErrClosed) {
			t.Fatalf("expected ErrClosed, got %v", err)
		}

	case <-time.After(time.Second):
		t.Fatal("Receive remained blocked after Close")
	}
}

// TestMemoryTransportCloseUnblocksSend tests that closing the transport unblocks the Send() function
func TestMemoryTransportCloseUnblocksSend(t *testing.T) {
	a, _ := NewMemoryPair(1)

	if err := a.Send(context.Background(), []byte{1}); err != nil {
		t.Fatal(err)
	}

	result := make(chan error, 1)

	go func() {
		result <- a.Send(context.Background(), []byte{2})
	}()

	if err := a.Close(); err != nil {
		t.Fatal(err)
	}

	select {
	case err := <-result:
		if !errors.Is(err, ErrClosed) {
			t.Fatalf("expected ErrClosed, got %v", err)
		}

	case <-time.After(time.Second):
		t.Fatal("Send remained blocked after Close")
	}
}

// TestMemoryTransportConcurrentClose tests that concurrent calls to Close() close both MemoryTransports
func TestMemoryTransportConcurrentClose(t *testing.T) {
	a, b := NewMemoryPair(8)

	var wg sync.WaitGroup

	for i := 0; i < 100; i++ {
		wg.Add(1)

		go func(i int) {
			defer wg.Done()

			if i%2 == 0 {
				_ = a.Close()
			} else {
				_ = b.Close()
			}
		}(i)
	}

	wg.Wait()

	if err := a.Send(context.Background(), []byte{1}); !errors.Is(err, ErrClosed) {
		t.Fatalf("expected ErrClosed, got %v", err)
	}

	if _, err := b.Receive(context.Background()); !errors.Is(err, ErrClosed) {
		t.Fatalf("expected ErrClosed, got %v", err)
	}
}

func TestMemoryCloseReleasesQueuedPackets(t *testing.T) {
	a, b := NewMemoryPair(2)
	if err := a.Send(context.Background(), []byte("outbound")); err != nil {
		t.Fatal(err)
	}
	if err := b.Send(context.Background(), []byte("inbound")); err != nil {
		t.Fatal(err)
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	if len(a.pair.aToB) != 0 || len(a.pair.bToA) != 0 {
		t.Fatal("closed pair retained packet buffers")
	}
	if _, err := b.Receive(context.Background()); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
}
