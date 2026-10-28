package pcapnet

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/MeHungr/pcapnet/internal/queue"
)

// ClientTransport owns an allocated session. Its keepalives retain the lease
// while idle; Close releases local resources and the server later expires it.
// Construct with AllocateClient before attaching it to a VirtualStack.
type ClientTransport struct {
	endpoint   DatagramEndpoint
	peer       Peer
	assignment Assignment
	token      sessionID
	ctx        context.Context
	cancel     context.CancelFunc
	incoming   chan []byte
	workers    sync.WaitGroup
	once       sync.Once
	closeErr   error
	mu         sync.Mutex // Retains the first unexpected endpoint failure.
	failure    error
}

// AllocateClient negotiates configuration with bounded retry intervals until
// ctx expires. On success it owns endpoint; on failure the caller retains it.
// mtu is the largest inner packet the client can accept (zero uses DefaultMTU).
// The returned configuration is not authenticated by a plain UDP endpoint.
func AllocateClient(ctx context.Context, endpoint DatagramEndpoint, peer Peer, mtu uint32) (*ClientTransport, Assignment, error) {
	var empty Assignment
	if ctx == nil || nilInterface(endpoint) || !validUDPHost(peer.Addr()) || peer.Port() == 0 {
		return nil, empty, fmt.Errorf("invalid allocation arguments")
	}
	if mtu == 0 {
		mtu = DefaultMTU
	}
	if mtu < MinIPv4MTU || mtu > 65535 || endpoint.MaxDatagramSize() < int(mtu)+sessionHeaderSize {
		return nil, empty, fmt.Errorf("invalid client MTU")
	}
	var request sessionID
	if _, err := rand.Read(request[:]); err != nil {
		return nil, empty, err
	}
	for {
		if err := ctx.Err(); err != nil {
			return nil, empty, err
		}
		if err := endpoint.SendTo(ctx, sessionMessage(sessionRequest, request, nil), peer); err != nil {
			return nil, empty, err
		}
		attempt, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		for attempt.Err() == nil {
			b, from, err := endpoint.ReceiveFrom(attempt)
			if err != nil {
				if attempt.Err() != nil {
					break
				}
				cancel()
				return nil, empty, err
			}
			kind, id, payload, err := parseSessionMessage(b)
			if err != nil || from != peer || id != request {
				continue
			}
			if kind == sessionRejected {
				cancel()
				return nil, empty, fmt.Errorf("tunnel allocation rejected")
			}
			if kind != sessionAssignment {
				continue
			}
			a, token, lease, err := decodeAssignment(payload, mtu)
			cancel()
			if err != nil {
				return nil, empty, err
			}
			life, stop := context.WithCancel(context.Background())
			c := &ClientTransport{
				endpoint: endpoint, peer: peer, assignment: a, token: token,
				ctx: life, cancel: stop, incoming: make(chan []byte, 256),
			}
			c.workers.Add(2)
			if lifecycle, ok := endpoint.(PeerLifecycle); ok {
				done, lookupErr := lifecycle.PeerDone(peer)
				if lookupErr != nil {
					stop()
					return nil, empty, lookupErr
				}
				c.workers.Add(1)
				go func() {
					defer c.workers.Done()
					select {
					case <-c.ctx.Done():
					case <-done:
						c.failed(ErrPeerNotFound)
					}
				}()
			}
			go c.readLoop()
			go c.keepalive(lease / 3)
			return c, a, nil
		}
		cancel()
	}
}
func (c *ClientTransport) keepalive(interval time.Duration) {
	defer c.workers.Done()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			if err := c.endpoint.SendTo(c.ctx, sessionMessage(sessionKeepalive, c.token, nil), c.peer); err != nil {
				c.failed(err)
				return
			}
		}
	}
}
func (c *ClientTransport) readLoop() {
	defer c.workers.Done()
	for {
		b, peer, err := c.endpoint.ReceiveFrom(c.ctx)
		if err != nil {
			c.failed(err)
			return
		}
		kind, id, payload, err := parseSessionMessage(b)
		if err != nil || peer != c.peer || kind != sessionData || id != c.token || validateInnerIPv4(payload, c.assignment.MTU) != nil {
			continue
		}
		if netip.AddrFrom4([4]byte(payload[12:16])) != c.assignment.ServerIP || netip.AddrFrom4([4]byte(payload[16:20])) != c.assignment.VirtualIP {
			continue
		}
		select {
		case c.incoming <- append([]byte(nil), payload...):
		default:
		}
	}
}

// Send transmits one inner packet through its assigned session.
func (c *ClientTransport) Send(ctx context.Context, packet []byte) error {
	if ctx == nil {
		return fmt.Errorf("packet context is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if c.ctx.Err() != nil {
		return ErrClosed
	}
	if validateInnerIPv4(packet, c.assignment.MTU) != nil || netip.AddrFrom4([4]byte(packet[12:16])) != c.assignment.VirtualIP || netip.AddrFrom4([4]byte(packet[16:20])) != c.assignment.ServerIP {
		return fmt.Errorf("invalid client packet")
	}
	return c.endpoint.SendTo(ctx, sessionMessage(sessionData, c.token, packet), c.peer)
}

// Receive returns one validated, independently owned inner packet.
func (c *ClientTransport) Receive(ctx context.Context) ([]byte, error) {
	if ctx == nil {
		return nil, fmt.Errorf("packet context is required")
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.ctx.Done():
		return nil, ErrClosed
	case b := <-c.incoming:
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if c.ctx.Err() != nil {
			return nil, ErrClosed
		}
		return b, nil
	}
}

// Close cancels workers and releases the owned endpoint exactly once.
func (c *ClientTransport) Close() error {
	c.once.Do(func() {
		c.cancel()
		err := c.endpoint.Close()
		c.workers.Wait()
		queue.Drain(c.incoming)
		c.mu.Lock()
		c.closeErr = errors.Join(c.failure, err)
		c.mu.Unlock()
	})
	return c.closeErr
}

// failed preserves a native endpoint failure before waking the owning bridge.
// Normal shutdown cancellation is deliberately excluded from the error result.
func (c *ClientTransport) failed(err error) {
	c.mu.Lock()
	if c.ctx.Err() != nil {
		c.mu.Unlock()
		return
	}
	c.failure = err
	c.cancel()
	c.mu.Unlock()
	// Close joins the reporting worker, so cleanup runs outside that worker.
	go c.Close()
}

var _ PacketTransport = (*ClientTransport)(nil)
