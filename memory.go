package pcapnet

import (
	"context"
	"sync"
)

// A memoryPair represents a pair of in-memory queues
type memoryPair struct {
	aToB chan []byte
	bToA chan []byte

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
	if err := ctx.Err(); err != nil {
		return err
	}

	select {
	case <-m.pair.done:
		return ErrClosed
	default:
	}

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
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	select {
	case <-m.pair.done:
		return nil, ErrClosed
	default:
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-m.pair.done:
		return nil, ErrClosed
	case packet := <-m.inbound:
		return packet, nil
	}
}

// Close gracefully closes the MemoryTransport
func (m *MemoryTransport) Close() error {
	m.pair.closeOnce.Do(func() {
		close(m.pair.done)
	})

	return nil
}
