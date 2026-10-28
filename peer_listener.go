package pcapnet

import (
	"net"
	"net/netip"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// peerListener binds each incoming SYN to a generation-specific forwarder before
// gVisor launches a handshake goroutine. Acceptance never looks up a peer by IP.
// Its pending handshakes and accepted queue each have a fixed capacity of 256.
type peerListener struct {
	v          *VirtualStack
	transport  *ServerTransport
	port       uint16
	ready      chan *managedConn
	done       chan struct{}
	once       sync.Once
	mu         sync.Mutex
	closed     bool
	forwarders map[*allocation]*tcp.Forwarder
	pending    map[*allocation]map[stack.TransportEndpointID]bool
	workers    sync.WaitGroup
}

func newPeerListener(v *VirtualStack, transport *ServerTransport, port int) *peerListener {
	l := &peerListener{v: v, transport: transport, port: uint16(port), ready: make(chan *managedConn, 256), done: make(chan struct{}), forwarders: make(map[*allocation]*tcp.Forwarder), pending: make(map[*allocation]map[stack.TransportEndpointID]bool)}
	transport.mu.Lock()
	transport.expire = nil
	transport.retire = l.retire
	transport.mu.Unlock()
	v.Stack.SetTransportProtocolHandler(tcp.ProtocolNumber, l.handle)
	return l
}
func (l *peerListener) handle(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
	if id.LocalPort != l.port {
		return false
	}
	// Mark is local packet metadata stamped while the allocation lock is held.
	l.transport.mu.Lock()
	a := l.transport.marks[pkt.Mark]
	valid := a != nil && a.live()
	l.transport.mu.Unlock()
	if !valid {
		return true
	}
	l.mu.Lock()
	if l.closed || !a.live() {
		l.mu.Unlock()
		return true
	}
	total := 0
	for _, pending := range l.pending {
		total += len(pending)
	}
	if l.pending[a][id] || total >= 256 {
		l.mu.Unlock()
		return true
	}
	f := l.forwarders[a]
	if f == nil {
		f = tcp.NewForwarder(l.v.Stack, 0, 256, func(r *tcp.ForwarderRequest) { l.acceptRequest(a, r) })
		l.forwarders[a] = f
	}
	if l.pending[a] == nil {
		l.pending[a] = make(map[stack.TransportEndpointID]bool)
	}
	l.pending[a][id] = true
	l.workers.Add(1)
	l.mu.Unlock()
	if !f.HandlePacket(id, pkt) {
		l.finishRequest(a, id)
		return false
	}
	return true
}
func (l *peerListener) finishRequest(a *allocation, id stack.TransportEndpointID) {
	l.mu.Lock()
	delete(l.pending[a], id)
	if len(l.pending[a]) == 0 {
		delete(l.pending, a)
	}
	l.mu.Unlock()
	l.workers.Done()
}
func (l *peerListener) acceptRequest(a *allocation, r *tcp.ForwarderRequest) {
	id := r.ID()
	// Complete removes the native in-flight entry before our duplicate guard.
	defer l.finishRequest(a, id)
	defer r.Complete(false)
	if !a.live() || channelClosed(l.done) {
		return
	}
	var wq waiter.Queue
	ep, err := r.CreateEndpoint(&wq)
	if err != nil {
		return
	}
	// All later output carries its generation, including retransmits after expiry.
	ep.SocketOptions().SetMark(a.mark)
	conn := gonet.NewTCPConn(&wq, ep)
	l.transport.mu.Lock()
	if !a.live() || l.transport.ctx.Err() != nil || channelClosed(l.done) {
		l.transport.mu.Unlock()
		ep.Abort()
		ep.(interface{ Wait() }).Wait()
		_ = conn.Close()
		return
	}
	registered, registerErr := l.v.registerGenerationConn(conn, a)
	if registerErr != nil {
		l.transport.mu.Unlock()
		ep.Abort()
		ep.(interface{ Wait() }).Wait()
		_ = conn.Close()
		return
	}
	managed := registered.(*managedConn)
	select {
	case l.ready <- managed:
		l.transport.mu.Unlock()
	default:
		l.transport.mu.Unlock()
		ep.Abort()
		ep.(interface{ Wait() }).Wait()
		_ = managed.Close()
	}
}
func (l *peerListener) Accept() (net.Conn, error) {
	for {
		select {
		case <-l.done:
			return nil, net.ErrClosed
		case <-l.v.closeCtx.Done():
			return nil, net.ErrClosed
		case conn := <-l.ready:
			l.transport.mu.Lock()
			valid := conn.generation.live()
			l.transport.mu.Unlock()
			if valid {
				return conn, nil
			}
			_ = conn.Close()
		}
	}
}
func (l *peerListener) Addr() net.Addr {
	return net.TCPAddrFromAddrPort(netip.AddrPortFrom(l.transport.config.VirtualIP, l.port))
}

// abortIP is used only while this IP is quarantined. Wait joins the exact
// endpoint objects captured here, never a future endpoint found by address.
func (l *peerListener) abortIP(ip netip.Addr) {
	endpoints := append(l.v.Stack.RegisteredEndpoints(), l.v.Stack.CleanupEndpoints()...)
	for _, endpoint := range endpoints {
		addressed, ok := endpoint.(tcpip.Endpoint)
		if !ok {
			continue
		}
		info, ok := addressed.Info().(*stack.TransportEndpointInfo)
		if ok && info.ID.RemoteAddress == tcpip.AddrFrom4(ip.As4()) {
			endpoint.Abort()
			endpoint.Wait()
		}
	}
}
func (l *peerListener) retire(a *allocation) {
	l.transport.injectMu.Lock()
	l.transport.injectMu.Unlock()
	// A handler can be scheduled before retirement and enter CreateEndpoint later.
	// Keep the address reserved and abort until every such handler has returned.
	for {
		l.abortIP(a.ip)
		l.mu.Lock()
		pending := len(l.pending[a])
		l.mu.Unlock()
		if pending == 0 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	// Bind managed connection teardown to the generation pointer, never its IP.
	l.v.mu.Lock()
	var conns []*managedConn
	for conn := range l.v.conns {
		if conn.generation == a {
			conns = append(conns, conn)
		}
	}
	l.v.mu.Unlock()
	for _, conn := range conns {
		_ = conn.Close()
	}
	l.abortIP(a.ip)
	// Drain every older outbound packet before allowing this address to be reused.
	// In particular, initial SYN-ACKs precede the endpoint's socket mark.
	l.v.mu.Lock()
	bridge := l.v.bridge
	l.v.mu.Unlock()
	if bridge != nil {
		bridge.flushEgress()
	}
	l.mu.Lock()
	delete(l.forwarders, a)
	l.mu.Unlock()
}
func (l *peerListener) Close() error {
	l.once.Do(func() {
		l.mu.Lock()
		l.closed = true
		close(l.done)
		l.mu.Unlock()
		for {
			l.mu.Lock()
			pending := make(map[stack.TransportEndpointID]bool)
			for _, ids := range l.pending {
				for id := range ids {
					pending[id] = true
				}
			}
			l.mu.Unlock()
			if len(pending) == 0 {
				break
			}
			endpoints := append(l.v.Stack.RegisteredEndpoints(), l.v.Stack.CleanupEndpoints()...)
			for _, endpoint := range endpoints {
				ep, ok := endpoint.(tcpip.Endpoint)
				if !ok {
					continue
				}
				info, ok := ep.Info().(*stack.TransportEndpointInfo)
				if ok && pending[info.ID] {
					endpoint.Abort()
					endpoint.Wait()
				}
			}
			time.Sleep(time.Millisecond)
		}
		l.workers.Wait()
		for {
			select {
			case conn := <-l.ready:
				_ = conn.Close()
			default:
				return
			}
		}
	})
	return nil
}

// egressBarrier travels through the same FIFO as TCP output. It is entirely
// local and intercepted before packet validation, so it never reaches the wire.
type egressBarrier struct{ done chan struct{} }

func (*egressBarrier) KUID() uint32 { return 0 }
func (*egressBarrier) KGID() uint32 { return 0 }
func (b *packetBridge) flushEgress() {
	barrier := &egressBarrier{done: make(chan struct{})}
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{})
	pkt.Owner = barrier
	defer pkt.DecRef()
	for {
		if b.lifetime.Err() != nil {
			return
		}
		var list stack.PacketBufferList
		list.PushBack(pkt)
		n, _ := b.link.WritePackets(list)
		if n == 1 {
			break
		}
		select {
		case <-b.lifetime.Done():
			return
		case <-time.After(time.Millisecond):
		}
	}
	select {
	case <-barrier.done:
	case <-b.lifetime.Done():
	}
}

// Keep imports and interface expectations explicit for this local listener.
var _ net.Listener = (*peerListener)(nil)
