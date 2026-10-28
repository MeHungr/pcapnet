package pcapnet

import (
	"context"
	"errors"
	"net/netip"
	"time"
)

var errPacketContext = errors.New("packet context is required")

func channelClosed(ch <-chan struct{}) bool {
	if ch == nil {
		return false
	}
	select {
	case <-ch:
		return true
	default:
		return false
	}
}
func (a *allocation) live() bool { return !channelClosed(a.done) && !channelClosed(a.peerDone) }

// retireLocked invalidates routing before cleanup begins. With a generation-aware
// listener the address remains quarantined until its handshake/TCP workers and
// queued egress are gone. Cleanup checks allocation identity before releasing it.
func (s *ServerTransport) retireLocked(a *allocation) {
	if channelClosed(a.done) {
		return
	}
	close(a.done)
	delete(s.tokens, a.token)
	delete(s.requests, a.key)
	delete(s.marks, a.mark)
	if s.retire == nil || s.ctx.Err() != nil {
		if s.expire != nil && s.ctx.Err() == nil {
			s.expire(a.ip)
		}
		if s.addresses[a.ip] == a {
			delete(s.addresses, a.ip)
		}
		close(a.cleaned)
		return
	}
	cleanup := s.retire
	s.workers.Add(1)
	go func() {
		defer s.workers.Done()
		cleanup(a)
		s.mu.Lock()
		if s.addresses[a.ip] == a {
			delete(s.addresses, a.ip)
		}
		close(a.cleaned)
		s.mu.Unlock()
	}()
}
func (s *ServerTransport) retirePeer(peer Peer) []<-chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	var done []<-chan struct{}
	for _, a := range s.addresses {
		if a.key.endpoint == peer {
			s.retireLocked(a)
			done = append(done, a.cleaned)
		}
	}
	return done
}
func (s *ServerTransport) watchPeer(a *allocation) {
	defer s.workers.Done()
	select {
	case <-s.ctx.Done():
	case <-a.done:
	case <-a.peerDone:
		s.retirePeer(a.key.endpoint)
	}
}

// receiveSessionPacket retains its allocation token until the bridge has taken
// the allocation lock and stamped the packet. This closes the dequeue/injection
// race in addition to checking generation ownership while the packet is queued.
func (s *ServerTransport) receiveSessionPacket(ctx context.Context) (sessionPacket, error) {
	if ctx == nil {
		return sessionPacket{}, errPacketContext
	}
	for {
		select {
		case <-ctx.Done():
			return sessionPacket{}, ctx.Err()
		case <-s.ctx.Done():
			return sessionPacket{}, ErrClosed
		case packet := <-s.incoming:
			s.mu.Lock()
			a := s.tokens[packet.token]
			valid := s.ctx.Err() == nil && a != nil && a.live() && time.Since(a.seen) < s.config.IdleTimeout
			s.mu.Unlock()
			if valid && ctx.Err() == nil {
				return packet, nil
			}
		}
	}
}

func (s *ServerTransport) sendMarked(ctx context.Context, packet []byte, mark uint32) error {
	// Marked endpoint output can never be routed using a replacement's IP lease.
	if mark != 0 {
		s.mu.Lock()
		a := s.marks[mark]
		if a == nil || !a.live() || time.Since(a.seen) >= s.config.IdleTimeout || a.ip != netip.AddrFrom4([4]byte(packet[16:20])) {
			s.mu.Unlock()
			return nil
		}
		peer, token := a.key.endpoint, a.token
		s.mu.Unlock()
		_ = s.endpoint.SendTo(ctx, sessionMessage(sessionData, token, packet), peer)
		return ctx.Err()
	}
	return s.Send(ctx, packet)
}

// injectGeneration serializes in-flight injection with retirement cleanup while
// permitting the stack's synchronous transport handler to take the lease lock.
func (s *ServerTransport) injectGeneration(packet sessionPacket, inject func([]byte, uint32)) bool {
	s.injectMu.Lock()
	defer s.injectMu.Unlock()
	s.mu.Lock()
	a := s.tokens[packet.token]
	valid := a != nil && a.live() && s.ctx.Err() == nil && time.Since(a.seen) < s.config.IdleTimeout
	var mark uint32
	if valid {
		mark = a.mark
	}
	s.mu.Unlock()
	if valid {
		inject(packet.data, mark)
	}
	return valid
}
