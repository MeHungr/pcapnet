package pcapnet

import (
	"context"
	"net"
)

// PeerConnection optionally exposes a TCP connection's original allocation peer.
// The returned handle is historical after that generation is retired; use
// PeerLifecycle or PeerInfo to check current validity rather than its remote IP.
type PeerConnection interface {
	net.Conn
	Peer() Peer
}

// AcceptWithPeer returns a TCP connection and the exact peer captured by its SYN
// generation. Multiple connections in an allocation return the same handle. A
// queued connection whose allocation retired is closed and skipped. Accept keeps
// its net.Listener signature and uses this same generation-aware listener.
func (s *TCPServer) AcceptWithPeer() (net.Conn, Peer, error) {
	conn, err := s.Accept()
	if err != nil {
		return nil, Peer{}, err
	}
	return conn, conn.(PeerConnection).Peer(), nil
}
func (s *TCPServer) sessions() *ServerTransport { return s.stack.bridge.transport.(*ServerTransport) }

// PeerInfo returns current authentication evidence for an exact admitted peer.
// Retained snapshots are historical after Done closes. Raw mode reports no
// cryptographic authentication; its Done is this allocation's lifetime.
func (s *TCPServer) PeerInfo(peer Peer) (PeerInformation, error) {
	transport := s.sessions()
	transport.mu.Lock()
	var generation *allocation
	for _, a := range transport.tokens {
		if a.key.endpoint == peer && a.live() {
			generation = a
			break
		}
	}
	transport.mu.Unlock()
	if generation == nil {
		return PeerInformation{}, ErrPeerNotFound
	}
	if provider, ok := transport.endpoint.(PeerInfoProvider); ok {
		info, err := provider.PeerInfo(peer)
		if !info.Encrypted {
			info.Done = generation.done
		}
		return info, err
	}
	return PeerInformation{Peer: peer, Done: generation.done}, nil
}

// PeerDone closes when this peer's current PCAT generation is invalidated.
// Secure endpoint retirement also closes it without waiting for lease timeout.
// Retained channels remain closed and cannot refer to a replacement allocation.
func (s *TCPServer) PeerDone(peer Peer) (<-chan struct{}, error) {
	transport := s.sessions()
	transport.mu.Lock()
	defer transport.mu.Unlock()
	for _, a := range transport.tokens {
		if a.key.endpoint == peer && a.live() {
			return a.done, nil
		}
	}
	return nil, ErrPeerNotFound
}

// DisconnectPeer invalidates the exact secure peer and every associated PCAT
// allocation, aborts TCP (including blocked operations and pending accepts), and
// waits for generation cleanup. ctx bounds waiting; cancellation never restores
// a retired generation. Stale handles are idempotent and cannot select a secure
// replacement at the same address. Raw mode retires current leases only: raw UDP
// has no authenticated connection identity or remote-reconnection detector.
func (s *TCPServer) DisconnectPeer(ctx context.Context, peer Peer) error {
	if ctx == nil {
		return errPacketContext
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	transport := s.sessions()
	// Retire PCAT first, before potentially blocking on native DTLS cleanup.
	done := transport.retirePeer(peer)
	var err error
	if disconnector, ok := transport.endpoint.(PeerDisconnecter); ok {
		err = disconnector.DisconnectPeer(ctx, peer)
	}
	done = append(done, transport.retirePeer(peer)...)
	for _, retired := range done {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-retired:
		}
	}
	return err
}
