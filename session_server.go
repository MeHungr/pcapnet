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

// ServerConfig defines the shared stack and allocation policy. VirtualIP must be
// a usable host in AddressPool. Network/broadcast and the server are excluded.
// IdleTimeout defaults to two minutes; MaxPeers defaults to 256. Idle sessions
// expire unless data or keepalives arrive. Addresses are assigned by the server.
type ServerConfig struct {
	VirtualIP   netip.Addr
	AddressPool netip.Prefix
	MTU         uint32
	MaxPeers    int
	IdleTimeout time.Duration
}

func (c ServerConfig) normalize() (ServerConfig, error) {
	if c.MTU == 0 {
		c.MTU = DefaultMTU
	}
	if c.MaxPeers == 0 {
		c.MaxPeers = 256
	}
	if c.IdleTimeout == 0 {
		c.IdleTimeout = 2 * time.Minute
	}
	c.AddressPool = c.AddressPool.Masked()
	if !c.AddressPool.IsValid() || !c.AddressPool.Addr().Is4() || c.AddressPool.Bits() < 1 || c.AddressPool.Bits() > 30 || !validVirtualIP(c.AddressPool.Addr()) || !usablePoolIP(c.AddressPool, c.VirtualIP) || c.MaxPeers < 1 || c.IdleTimeout < 3*time.Second || c.IdleTimeout > 24*time.Hour || c.IdleTimeout%time.Second != 0 {
		return c, fmt.Errorf("invalid address allocation configuration")
	}
	_, err := (Config{VirtualIP: c.VirtualIP, PeerSubnet: c.AddressPool, MTU: c.MTU}).normalize()
	return c, err
}
func usablePoolIP(pool netip.Prefix, ip netip.Addr) bool {
	return validVirtualIP(ip) && pool.Contains(ip) && ip != pool.Addr() && pool.Contains(ip.Next())
}

// sessionPacket retains its generation while queued so expiry/reassignment
// cannot deliver a previous client's buffered data into a replacement session.
type sessionPacket struct {
	token sessionID
	data  []byte
}

type allocationKey struct {
	endpoint Peer
	request  sessionID
}
type allocation struct {
	key   allocationKey
	token sessionID
	ip    netip.Addr
	seen  time.Time
}

// ServerTransport multiplexes assigned virtual addresses onto a DatagramEndpoint.
// A successful construction transfers endpoint ownership. Exactly one shared
// VirtualStack should own this transport. Tokens are bearer routing identifiers,
// not authentication; use a secure endpoint when confidentiality is required.
type ServerTransport struct {
	endpoint  DatagramEndpoint
	config    ServerConfig
	ctx       context.Context
	cancel    context.CancelFunc
	mu        sync.Mutex // Serializes allocation, expiry, and reply lookup.
	requests  map[allocationKey]*allocation
	tokens    map[sessionID]*allocation
	addresses map[netip.Addr]*allocation
	next      netip.Addr
	incoming  chan sessionPacket
	workers   sync.WaitGroup
	once      sync.Once
	err       error
	// expire closes TCP endpoints before an address becomes available again.
	expire func(netip.Addr)
}

// NewServerTransport starts bounded allocation and packet dispatch. It sends no
// stack-specific information on the wire. endpoint remains caller-owned on error.
func NewServerTransport(endpoint DatagramEndpoint, cfg ServerConfig) (*ServerTransport, error) {
	cfg, err := cfg.normalize()
	if err != nil {
		return nil, err
	}
	if nilInterface(endpoint) || endpoint.MaxDatagramSize() < int(cfg.MTU)+sessionHeaderSize {
		return nil, fmt.Errorf("endpoint cannot carry tunnel MTU")
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &ServerTransport{
		endpoint: endpoint, config: cfg, ctx: ctx, cancel: cancel,
		requests: make(map[allocationKey]*allocation), tokens: make(map[sessionID]*allocation),
		addresses: make(map[netip.Addr]*allocation), next: cfg.AddressPool.Addr().Next(),
		incoming: make(chan sessionPacket, 256),
	}

	s.workers.Add(2)
	go s.readLoop()
	go s.expireLoop()
	return s, nil
}
func (s *ServerTransport) expireLocked(now time.Time) {
	for token, a := range s.tokens {
		if now.Sub(a.seen) < s.config.IdleTimeout {
			continue
		}
		if s.expire != nil {
			s.expire(a.ip)
		}
		delete(s.tokens, token)
		delete(s.requests, a.key)
		delete(s.addresses, a.ip)
	}
}
func (s *ServerTransport) expireLoop() {
	defer s.workers.Done()
	ticker := time.NewTicker(s.config.IdleTimeout / 3)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case now := <-ticker.C:
			s.mu.Lock()
			s.expireLocked(now)
			s.mu.Unlock()
		}
	}
}

// allocate is atomic, including retries. Repeating a request cannot consume a
// second lease. Random failures and pool exhaustion produce only a generic reject.
func (s *ServerTransport) allocate(peer Peer, id sessionID, now time.Time) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireLocked(now)
	key := allocationKey{peer, id}
	if a := s.requests[key]; a != nil {
		a.seen = now
		return sessionMessage(sessionAssignment, id, encodeAssignment(Assignment{a.ip, s.config.VirtualIP, s.config.MTU}, a.token, uint32(s.config.IdleTimeout/time.Second))), nil
	}
	if len(s.tokens) >= s.config.MaxPeers {
		return sessionMessage(sessionRejected, id, nil), nil
	}
	// At most live allocations plus server/network/broadcast need skipping, even
	// for a large prefix. The cursor wraps without enumerating an entire subnet.
	var ip netip.Addr
	for i := 0; i < len(s.addresses)+4; i++ {
		candidate := s.next
		s.next = candidate.Next()
		if !s.config.AddressPool.Contains(s.next) {
			s.next = s.config.AddressPool.Addr().Next()
		}
		if usablePoolIP(s.config.AddressPool, candidate) && candidate != s.config.VirtualIP && s.addresses[candidate] == nil {
			ip = candidate
			break
		}
	}
	if !ip.IsValid() {
		return sessionMessage(sessionRejected, id, nil), nil
	}
	var token sessionID
	for {
		if _, err := rand.Read(token[:]); err != nil {
			return nil, err
		}
		if s.tokens[token] == nil {
			break
		}
	}
	a := &allocation{key, token, ip, now}
	s.requests[key] = a
	s.tokens[token] = a
	s.addresses[ip] = a
	return sessionMessage(sessionAssignment, id, encodeAssignment(Assignment{ip, s.config.VirtualIP, s.config.MTU}, token, uint32(s.config.IdleTimeout/time.Second))), nil
}
func (s *ServerTransport) readLoop() {
	defer s.workers.Done()
	for {
		b, peer, err := s.endpoint.ReceiveFrom(s.ctx)
		if err != nil {
			if s.ctx.Err() == nil {
				s.mu.Lock()
				s.err = err
				s.mu.Unlock()
				s.cancel()
				go s.Close()
			}
			return
		}
		kind, id, payload, err := parseSessionMessage(b)
		if err != nil || !peer.IsValid() {
			continue
		}
		if kind == sessionRequest {
			response, err := s.allocate(peer, id, time.Now())
			if err != nil {
				response = sessionMessage(sessionRejected, id, nil)
			}
			_ = s.endpoint.SendTo(s.ctx, response, peer)
			continue
		}
		if kind != sessionData && kind != sessionKeepalive {
			continue
		}
		s.mu.Lock()
		a := s.tokens[id]
		valid := a != nil && a.key.endpoint == peer && time.Since(a.seen) < s.config.IdleTimeout
		if valid && kind == sessionData {
			valid = validateInnerIPv4(payload, s.config.MTU) == nil && netip.AddrFrom4([4]byte(payload[12:16])) == a.ip && netip.AddrFrom4([4]byte(payload[16:20])) == s.config.VirtualIP
		}
		if valid {
			a.seen = time.Now()
		}
		s.mu.Unlock()
		if valid && kind == sessionData {
			select {
			case s.incoming <- sessionPacket{id, append([]byte(nil), payload...)}:
			default:
			}
		}
	}
}

// Send resolves an inner destination to its lease. Unknown or expired
// destinations are dropped so a stale TCP retransmission cannot stop the stack.
func (s *ServerTransport) Send(ctx context.Context, packet []byte) error {
	if ctx == nil {
		return fmt.Errorf("packet context is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.ctx.Err() != nil {
		return ErrClosed
	}
	if validateInnerIPv4(packet, s.config.MTU) != nil {
		return fmt.Errorf("invalid inner packet")
	}
	if netip.AddrFrom4([4]byte(packet[12:16])) != s.config.VirtualIP {
		return fmt.Errorf("invalid server source")
	}
	s.mu.Lock()
	a := s.addresses[netip.AddrFrom4([4]byte(packet[16:20]))]
	if a == nil || time.Since(a.seen) >= s.config.IdleTimeout {
		s.mu.Unlock()
		return nil
	}
	peer, token := a.key.endpoint, a.token
	s.mu.Unlock()
	// A peer-specific delivery error must not terminate the shared stack.
	_ = s.endpoint.SendTo(ctx, sessionMessage(sessionData, token, packet), peer)
	return ctx.Err()
}

// Receive returns one validated, independently owned inner packet.
func (s *ServerTransport) Receive(ctx context.Context) ([]byte, error) {
	if ctx == nil {
		return nil, fmt.Errorf("packet context is required")
	}
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-s.ctx.Done():
			return nil, ErrClosed
		case packet := <-s.incoming:
			s.mu.Lock()
			a := s.tokens[packet.token]
			valid := s.ctx.Err() == nil && a != nil && time.Since(a.seen) < s.config.IdleTimeout
			s.mu.Unlock()
			if valid {
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}
				return packet.data, nil
			}
		}
	}
}

// Close cancels workers and releases the owned endpoint exactly once.
func (s *ServerTransport) Close() error {
	s.once.Do(func() {
		s.cancel()
		err := s.endpoint.Close()
		s.workers.Wait()
		queue.Drain(s.incoming)
		s.mu.Lock()
		clear(s.tokens)
		clear(s.addresses)
		clear(s.requests)
		s.expire = nil
		s.err = errors.Join(s.err, err)
		s.mu.Unlock()
	})
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

var _ PacketTransport = (*ServerTransport)(nil)
