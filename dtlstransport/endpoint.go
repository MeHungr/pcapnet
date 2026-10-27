package dtlstransport

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/MeHungr/pcapnet"
	"github.com/MeHungr/pcapnet/internal/queue"
	"github.com/pion/dtls/v3"
)

type connection struct {
	packets  *packetConn
	conn     *dtls.Conn   // Published and read under Endpoint.mu; immutable thereafter.
	peer     pcapnet.Peer // Published only after verification and authorization.
	sendGate chan struct{}
	activity time.Time // Successful application sends/receives; protected by Endpoint.mu.
}
type message struct {
	data []byte
	peer pcapnet.Peer
}

// Endpoint implements pcapnet.DatagramEndpoint using authenticated DTLS records.
// Server endpoints multiplex independent connections, including clients sharing a
// physical UDP tuple. Each accepted connection gets a fresh local Peer identity;
// neither routing IDs nor caller-supplied addresses authenticate a connection.
// ReceiveFrom returns only decrypted application data from verified connections.
// Construct with Listen or Dial; its zero value is not usable.
type Endpoint struct {
	raw        pcapnet.DatagramEndpoint
	limits     Limits
	capacity   int
	server     *ServerConfig // Nil for clients; immutable after construction.
	ctx        context.Context
	cancel     context.CancelFunc
	mu         sync.Mutex
	routes     map[routeKey]*connection
	peers      map[pcapnet.Peer]*connection
	clientPeer pcapnet.Peer
	incoming   chan message
	workers    sync.WaitGroup
	closing    bool
	err        error
	once       sync.Once
}

func newEndpoint(raw pcapnet.DatagramEndpoint, limits Limits) *Endpoint {
	ctx, cancel := context.WithCancel(context.Background())
	recordMTU := min(raw.MaxDatagramSize()-muxHeaderSize, maxDTLSDatagramSize)
	return &Endpoint{
		raw: raw, limits: limits, capacity: recordMTU - recordOverhead,
		ctx: ctx, cancel: cancel,
		routes: make(map[routeKey]*connection), peers: make(map[pcapnet.Peer]*connection),
		incoming: make(chan message, 256),
	}

}

// Listen starts secure server dispatch over an existing datagram endpoint. It
// takes ownership only on success. Handshake slots and queues are bounded; one
// failed or idle peer never closes the listener or another peer's connection.
func Listen(raw pcapnet.DatagramEndpoint, cfg ServerConfig) (*Endpoint, error) {
	if err := validateRaw(raw); err != nil {
		return nil, err
	}
	if err := validCertificates(cfg.Certificates); err != nil {
		return nil, err
	}
	limits, err := cfg.Limits.normalized()
	if err != nil {
		return nil, err
	}
	e := newEndpoint(raw, limits)
	e.server = &cfg
	e.workers.Add(1)
	go e.route()
	return e, nil
}

// Dial authenticates the remote certificate before returning. Initial argument
// errors leave raw caller-owned; once the handshake starts, raw is owned here
// and closed on failure. Use the returned Peer(), not the raw physical address,
// with AllocateClient. ctx bounds setup, not the established endpoint's lifetime.
func Dial(ctx context.Context, raw pcapnet.DatagramEndpoint, remote pcapnet.Peer, cfg ClientConfig) (*Endpoint, error) {
	if err := invalidContext(ctx); err != nil {
		return nil, err
	}
	if err := validateRaw(raw); err != nil {
		return nil, err
	}
	if !remote.IsValid() || remote.Port() == 0 || cfg.ServerName == "" {
		return nil, fmt.Errorf("remote address and verified server name are required")
	}
	if len(cfg.Certificates) > 0 {
		if err := validCertificates(cfg.Certificates); err != nil {
			return nil, err
		}
	}
	limits, err := cfg.Limits.normalized()
	if err != nil {
		return nil, err
	}
	id, err := randomID()
	if err != nil {
		return nil, err
	}
	e := newEndpoint(raw, limits)
	p := e.newConnection(routeKey{remote, id})
	e.routes[p.packets.key] = p
	e.workers.Add(1)
	go e.route()
	options := []dtls.ClientOption{dtls.WithServerName(cfg.ServerName), dtls.WithRootCAs(cfg.RootCAs)}
	for _, opt := range commonOptions(e.capacity + recordOverhead) {
		options = append(options, opt)
	}
	if len(cfg.Certificates) > 0 {
		options = append(options, dtls.WithCertificates(cfg.Certificates...))
	}
	conn, err := dtls.ClientWithOptions(p.packets, net.UDPAddrFromAddrPort(remote.AddrPort), options...)
	if err != nil {
		return nil, errors.Join(err, e.Close())
	}
	e.mu.Lock()
	p.conn = conn
	closed := e.closing || e.ctx.Err() != nil
	e.mu.Unlock()
	if closed {
		p.packets.Close()
		_ = conn.Close()
		return nil, errors.Join(net.ErrClosed, e.Close())
	}
	handshake, cancel := context.WithTimeout(ctx, limits.HandshakeTimeout)
	defer cancel()
	if err = conn.HandshakeContext(handshake); err == nil {
		err = e.authorize(handshake, p, cfg.Authorize)
	}
	if err != nil {
		return nil, errors.Join(fmt.Errorf("DTLS client handshake: %w", err), e.Close())
	}
	e.mu.Lock()
	if e.closing || e.ctx.Err() != nil {
		e.mu.Unlock()
		return nil, errors.Join(net.ErrClosed, e.Close())
	}
	e.clientPeer = p.peer
	e.peers[p.peer] = p
	e.workers.Add(1)
	e.mu.Unlock()
	go e.read(p)
	return e, nil
}
func (e *Endpoint) newConnection(key routeKey) *connection {
	p := &connection{packets: newPacketConn(e, key), sendGate: make(chan struct{}, 1)}
	p.sendGate <- struct{}{}
	return p
}

// Peer returns a client's authenticated server handle. A listener returns a zero
// Peer; it learns client handles from ReceiveFrom instead. The handle is local
// to this Endpoint and becomes invalid when its DTLS connection closes.
func (e *Endpoint) Peer() pcapnet.Peer {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.clientPeer
}

// MaxDatagramSize reserves the public routing header and DTLS AES-GCM overhead.
// The allocation layer additionally subtracts its own session header.
func (e *Endpoint) MaxDatagramSize() int { return e.capacity }

func (e *Endpoint) route() {
	defer e.workers.Done()
	for {
		b, remote, err := e.raw.ReceiveFrom(e.ctx)
		if err != nil {
			e.failed(err)
			return
		}
		id, record, ok := unframe(b)
		if !ok || !remote.IsValid() || remote.Port() == 0 || len(record) > e.capacity+recordOverhead {
			continue
		}
		key := routeKey{remote, id}
		e.mu.Lock()
		if e.closing {
			e.mu.Unlock()
			return
		}
		p := e.routes[key]
		if p == nil && e.server != nil && len(e.routes) < e.limits.MaxPeers && initialHello(record) {
			p = e.newConnection(key)
			e.routes[key] = p
			e.workers.Add(1)
			go e.accept(p)
		}
		e.mu.Unlock()
		if p != nil {
			select {
			case p.packets.incoming <- append([]byte(nil), record...):
			default:
			}
		}
	}
}
func (e *Endpoint) accept(p *connection) {
	// The lifetime worker remains registered through both handshake and reads.
	defer e.workers.Done()
	defer e.remove(p)
	options := []dtls.ServerOption{dtls.WithCertificates(e.server.Certificates...), dtls.WithClientCAs(e.server.ClientCAs)}
	for _, opt := range commonOptions(e.capacity + recordOverhead) {
		options = append(options, opt)
	}
	if e.server.RequireClientCertificate {
		options = append(options, dtls.WithClientAuth(dtls.RequireAndVerifyClientCert))
	}
	conn, err := dtls.ServerWithOptions(p.packets, net.UDPAddrFromAddrPort(p.packets.key.peer.AddrPort), options...)
	if err != nil {
		return
	}
	e.mu.Lock()
	p.conn = conn
	closed := e.closing
	e.mu.Unlock()
	if closed {
		return
	}
	ctx, cancel := context.WithTimeout(e.ctx, e.limits.HandshakeTimeout)
	defer cancel()
	if conn.HandshakeContext(ctx) != nil || e.authorize(ctx, p, e.server.Authorize) != nil {
		return
	}
	e.mu.Lock()
	if e.closing {
		e.mu.Unlock()
		return
	}
	e.peers[p.peer] = p
	e.mu.Unlock()
	e.readMessages(p)
}
func (e *Endpoint) authorize(ctx context.Context, p *connection, callback func(context.Context, PeerInfo) error) error {
	state, ok := p.conn.ConnectionState()
	if !ok {
		return fmt.Errorf("DTLS handshake did not complete")
	}
	id, err := randomID()
	if err != nil {
		return err
	}
	// Preserve local delivery metadata so an all-port raw endpoint can select
	// the contacted port for replies. routeKey already includes the full raw
	// Peer, keeping the same remote endpoint isolated across local ports.
	peer := p.packets.key.peer
	peer.ConnectionID = [16]byte(id)
	info := PeerInfo{Peer: peer}
	for _, der := range state.PeerCertificates {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return err
		}
		info.Certificates = append(info.Certificates, cert)
	}
	if callback != nil {
		if err := callback(ctx, info); err != nil {
			return err
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	e.mu.Lock()
	p.peer = info.Peer
	p.activity = time.Now()
	e.mu.Unlock()
	return nil
}
func (e *Endpoint) read(p *connection) {
	defer e.workers.Done()
	defer e.remove(p)
	e.readMessages(p)
}
func (e *Endpoint) readMessages(p *connection) {
	b := make([]byte, e.capacity)
	for {
		e.mu.Lock()
		expires := p.activity.Add(e.limits.IdleTimeout)
		e.mu.Unlock()
		_ = p.conn.SetReadDeadline(expires)
		n, err := p.conn.Read(b)
		if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
			// Outbound keepalives count as activity too. A write can extend the idle
			// lifetime while Read is waiting on the previously computed deadline.
			e.mu.Lock()
			active := time.Since(p.activity) < e.limits.IdleTimeout
			e.mu.Unlock()
			if active {
				continue
			}
		}
		if err != nil {
			if e.server == nil {
				e.failed(err)
			}
			return
		}
		e.mu.Lock()
		p.activity = time.Now()
		e.mu.Unlock()
		select {
		case e.incoming <- message{append([]byte(nil), b[:n]...), p.peer}:
		default:
		}
	}
}
func (e *Endpoint) remove(p *connection) {
	e.mu.Lock()
	delete(e.routes, p.packets.key)
	delete(e.peers, p.peer)
	conn := p.conn
	e.mu.Unlock()
	p.packets.Close()
	if conn != nil {
		_ = conn.Close()
	}
}
func (e *Endpoint) failed(err error) {
	e.mu.Lock()
	if e.ctx.Err() != nil || e.closing {
		e.mu.Unlock()
		return
	}
	e.err = err
	e.cancel()
	e.mu.Unlock()
	// Close joins workers, so it must run outside the worker reporting failure.
	go e.Close()
}

// ReceiveFrom returns a fresh plaintext datagram and its authenticated connection
// handle. Pending handshakes, rejected peers, and expired-connection queues are
// never exposed to allocation. Server-side per-peer errors do not stop this call.
func (e *Endpoint) ReceiveFrom(ctx context.Context) ([]byte, pcapnet.Peer, error) {
	if err := invalidContext(ctx); err != nil {
		return nil, pcapnet.Peer{}, err
	}
	for {
		select {
		case <-ctx.Done():
			return nil, pcapnet.Peer{}, ctx.Err()
		case <-e.ctx.Done():
			return nil, pcapnet.Peer{}, net.ErrClosed
		case m := <-e.incoming:
			e.mu.Lock()
			p := e.peers[m.peer]
			valid := p != nil && p.packets.ctx.Err() == nil
			e.mu.Unlock()
			if valid {
				return m.data, m.peer, nil
			}
		}
	}
}

// SendTo requires an exact live authenticated Peer handle. Caller cancellation
// interrupts queued sends and the DTLS write without changing another peer's
// deadlines. A native PCAP injection already in progress cannot be interrupted.
func (e *Endpoint) SendTo(ctx context.Context, b []byte, peer pcapnet.Peer) error {
	if err := invalidContext(ctx); err != nil {
		return err
	}
	if len(b) > e.capacity {
		return pcapnet.ErrDatagramTooLarge
	}
	e.mu.Lock()
	p := e.peers[peer]
	e.mu.Unlock()
	if p == nil {
		return net.ErrClosed
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-p.packets.ctx.Done():
		return net.ErrClosed
	case <-e.ctx.Done():
		return net.ErrClosed
	case <-p.sendGate:
	}
	defer func() { p.sendGate <- struct{}{} }()
	if err := ctx.Err(); err != nil {
		return err
	}
	at, _ := ctx.Deadline()
	_ = p.conn.SetWriteDeadline(at)
	interrupted := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = p.conn.SetWriteDeadline(time.Now()); close(interrupted) })
	_, err := p.conn.Write(b)
	if err == nil {
		e.mu.Lock()
		p.activity = time.Now()
		e.mu.Unlock()
	}
	if !stop() {
		<-interrupted
	}
	_ = p.conn.SetWriteDeadline(time.Time{})
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

// Close cancels handshakes, closes every DTLS connection and the owned raw
// endpoint, and joins all workers. Repeated and concurrent calls are safe.
func (e *Endpoint) Close() error {
	e.once.Do(func() {
		e.mu.Lock()
		e.closing = true
		e.cancel()
		connections := make([]*connection, 0, len(e.routes))
		conns := make([]*dtls.Conn, 0, len(e.routes))
		for _, p := range e.routes {
			connections = append(connections, p)
			if p.conn != nil {
				conns = append(conns, p.conn)
			}
		}
		e.mu.Unlock()
		for _, p := range connections {
			p.packets.Close()
		}
		err := e.raw.Close()
		for _, c := range conns {
			_ = c.Close()
		}
		e.workers.Wait()
		queue.Drain(e.incoming)
		e.mu.Lock()
		clear(e.routes)
		clear(e.peers)
		e.err = errors.Join(e.err, err)
		e.mu.Unlock()
	})
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.err
}

var _ pcapnet.DatagramEndpoint = (*Endpoint)(nil)
