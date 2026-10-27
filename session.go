package pcapnet

import (
	"context"
	"fmt"
	"net/netip"
)

// Peer identifies a delivery address and an optional opaque connection identity.
// Plain UDP uses a zero ConnectionID. Secure adapters assign a fresh local ID
// after authentication, so reconnects and clients sharing an address stay distinct.
// ConnectionID is not transmitted by the allocation protocol.
type Peer struct {
	netip.AddrPort
	ConnectionID [16]byte
}

// DatagramEndpoint is the boundary between tunnel sessions and packet delivery.
// Implementations preserve message boundaries, own received bytes, support one
// receiver concurrent with multiple senders, and honor context cancellation.
// Close is idempotent and unblocks all operations. MaxDatagramSize is the largest
// application datagram, after the implementation's own encryption/framing costs.
// Peer.ConnectionID distinguishes authenticated connections when supplied by a
// secure adapter; a plain endpoint supplies only a delivery address.
// SendTo must reject an unknown or stale ConnectionID, never silently fall back
// to another connection at the same address.
type DatagramEndpoint interface {
	SendTo(context.Context, []byte, Peer) error
	ReceiveFrom(context.Context) ([]byte, Peer, error)
	MaxDatagramSize() int
	Close() error
}

// PlainUDPEndpoint adapts PCAP UDP to the session layer without encryption or
// authentication. Construct it with NewPlainUDPEndpoint; it owns the UDPConn.
type PlainUDPEndpoint struct{ conn *UDPConn }

// NewPlainUDPEndpoint transfers ownership of conn. conn may be connected for a
// client or unconnected for a server; its existing deadlines remain effective.
func NewPlainUDPEndpoint(conn *UDPConn) (*PlainUDPEndpoint, error) {
	if conn == nil {
		return nil, fmt.Errorf("UDP connection is required")
	}
	return &PlainUDPEndpoint{conn: conn}, nil
}

// MaxDatagramSize accounts for IPv4/UDP and optional UDP magic framing.
func (p *PlainUDPEndpoint) MaxDatagramSize() int { return p.conn.MaxDatagramSize() }

// Close releases the owned UDP endpoint and unblocks operations.
func (p *PlainUDPEndpoint) Close() error { return p.conn.Close() }

// SendTo sends one datagram, respecting the caller and endpoint lifetimes.
func (p *PlainUDPEndpoint) SendTo(ctx context.Context, data []byte, peer Peer) error {
	if ctx == nil {
		return fmt.Errorf("datagram context is required")
	}
	if peer.ConnectionID != ([16]byte{}) {
		return fmt.Errorf("plain UDP cannot address secure sessions")
	}
	if p.conn.peer.IsValid() && peer.AddrPort != p.conn.peer {
		return fmt.Errorf("endpoint peer mismatch")
	}
	_, err := p.conn.writeToContext(ctx, data, peer.AddrPort)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

// ReceiveFrom waits for one datagram without changing shared UDP deadlines.
func (p *PlainUDPEndpoint) ReceiveFrom(parent context.Context) ([]byte, Peer, error) {
	if parent == nil {
		return nil, Peer{}, fmt.Errorf("datagram context is required")
	}
	if err := parent.Err(); err != nil {
		return nil, Peer{}, err
	}
	ctx, finish, err := p.conn.operation(false)
	if err != nil {
		return nil, Peer{}, err
	}
	defer finish()
	select {
	case <-parent.Done():
		return nil, Peer{}, parent.Err()
	case <-ctx.Done():
		return nil, Peer{}, udpContextError(ctx)
	case packet := <-p.conn.inbox:
		if parent.Err() != nil {
			return nil, Peer{}, parent.Err()
		}
		if ctx.Err() != nil {
			return nil, Peer{}, udpContextError(ctx)
		}
		return append([]byte(nil), packet.Payload...), Peer{AddrPort: netip.AddrPortFrom(packet.SourceIP, packet.SourcePort)}, nil
	}
}
