package pcapnet

import (
	"context"
	"fmt"
	"sync"

	"github.com/MeHungr/pcapnet/internal/queue"
)

// A memoryPair represents a pair of in-memory queues
type memoryPair struct {
	aToB chan []byte
	bToA chan []byte

	mu        sync.Mutex // Registers operations before Close waits for them.
	active    sync.WaitGroup
	closed    bool
	done      chan struct{}
	closeOnce sync.Once
}

// A MemoryTransport represents an in-memory bidirectional transport
type MemoryTransport struct {
	pair *memoryPair

	inbound  <-chan []byte
	outbound chan<- []byte
}

// NewMemoryPair creates two connected, bidirectional transports.
//
// The capacity specifies the number of packets buffered in each
// direction.
//
// Closing either transport closes the entire pair.
func NewMemoryPair(capacity int) (*MemoryTransport, *MemoryTransport) {
	if capacity < 1 {
		capacity = 1
	}

	pair := &memoryPair{
		aToB: make(chan []byte, capacity),
		bToA: make(chan []byte, capacity),
		done: make(chan struct{}),
	}

	a := &MemoryTransport{
		pair:     pair,
		inbound:  pair.bToA,
		outbound: pair.aToB,
	}

	b := &MemoryTransport{
		pair:     pair,
		inbound:  pair.aToB,
		outbound: pair.bToA,
	}

	return a, b
}

// Send sends a packet over the MemoryTransport.outbound channel
func (m *MemoryTransport) Send(ctx context.Context, packet []byte) error {
	if ctx == nil {
		return fmt.Errorf("packet context is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	if !m.begin() {
		return ErrClosed
	}
	defer m.pair.active.Done()

	// The receiver must own an independent copy of the packet
	data := append([]byte(nil), packet...)

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-m.pair.done:
		return ErrClosed
	case m.outbound <- data:
		return nil
	}
}

// Receive receives a packet over the MemoryTransport.inbound channel
func (m *MemoryTransport) Receive(ctx context.Context) ([]byte, error) {
	if ctx == nil {
		return nil, fmt.Errorf("packet context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if !m.begin() {
		return nil, ErrClosed
	}
	defer m.pair.active.Done()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-m.pair.done:
		return nil, ErrClosed
	case packet := <-m.inbound:
		return packet, nil
	}
}

// Close interrupts operations and releases both directions' buffered packets.
func (m *MemoryTransport) Close() error {
	if m == nil || m.pair == nil {
		return nil
	}
	m.pair.closeOnce.Do(func() {
		m.pair.mu.Lock()
		m.pair.closed = true
		close(m.pair.done)
		m.pair.mu.Unlock()
		m.pair.active.Wait()
		queue.Drain(m.pair.aToB)
		queue.Drain(m.pair.bToA)
	})

	return nil
}

// begin prevents a new operation from racing with Close's WaitGroup wait.
func (m *MemoryTransport) begin() bool {
	if m == nil || m.pair == nil {
		return false
	}
	m.pair.mu.Lock()
	defer m.pair.mu.Unlock()
	if m.pair.closed {
		return false
	}
	m.pair.active.Add(1)
	return true
}
