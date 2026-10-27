package pcapnet

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// datagramHub models independent PCAP receivers. Endpoints sharing an outer
// address all see the same datagrams, reproducing concurrent client processes.
type datagramHub struct {
	mu             sync.Mutex
	endpoints      []*testDatagramEndpoint
	dropAssignment bool
}
type testDatagram struct {
	data []byte
	peer Peer
}
type testDatagramEndpoint struct {
	hub      *datagramHub
	addr     Peer
	incoming chan testDatagram
	done     chan struct{}
	once     sync.Once
	failure  chan error
}

func (h *datagramHub) endpoint(addr string) *testDatagramEndpoint {
	e := &testDatagramEndpoint{hub: h, addr: Peer{AddrPort: netip.MustParseAddrPort(addr)}, incoming: make(chan testDatagram, 1024), done: make(chan struct{})}
	h.mu.Lock()
	h.endpoints = append(h.endpoints, e)
	h.mu.Unlock()
	return e
}
func (e *testDatagramEndpoint) MaxDatagramSize() int { return 1472 }
func (e *testDatagramEndpoint) Close() error         { e.once.Do(func() { close(e.done) }); return nil }
func (e *testDatagramEndpoint) SendTo(ctx context.Context, b []byte, peer Peer) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case <-e.done:
		return ErrClosed
	default:
	}
	e.hub.mu.Lock()
	defer e.hub.mu.Unlock()
	if len(b) > 5 && b[5] == sessionAssignment && e.hub.dropAssignment {
		e.hub.dropAssignment = false
		return nil
	}
	for _, target := range e.hub.endpoints {
		if target.addr == peer {
			select {
			case <-target.done:
			case target.incoming <- testDatagram{append([]byte(nil), b...), e.addr}:
			default:
			}
		}
	}
	return nil
}
func (e *testDatagramEndpoint) ReceiveFrom(ctx context.Context) ([]byte, Peer, error) {
	select {
	case err := <-e.failure:
		return nil, Peer{}, err
	case <-ctx.Done():
		return nil, Peer{}, ctx.Err()
	case <-e.done:
		return nil, Peer{}, ErrClosed
	case d := <-e.incoming:
		return d.data, d.peer, nil
	}
}
func testServerConfig() ServerConfig {
	return ServerConfig{VirtualIP: netip.MustParseAddr("10.200.0.2"), AddressPool: netip.MustParsePrefix("10.200.0.0/24"), MTU: 1200, MaxPeers: 32, IdleTimeout: 6 * time.Second}
}

// TestAllocatedConcurrentTCP exercises five independent clients on the same
// physical tuple against one shared gVisor stack. Session IDs must prevent the
// cross-stack reset failures produced by the original unframed tunnel.
func TestAllocatedConcurrentTCP(t *testing.T) {
	h := &datagramHub{dropAssignment: true}
	serverEndpoint := h.endpoint("192.0.2.2:45001")
	server, err := NewTCPServer(serverEndpoint, testServerConfig(), 6767)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { server.Close() })
	defer stop()
	const count = 5
	endpoints := make([]*testDatagramEndpoint, count)
	for i := range endpoints {
		endpoints[i] = h.endpoint("192.0.2.1:45000")
	}
	results := make(chan error, count*2)
	go func() {
		for i := 0; i < count; i++ {
			conn, err := server.Accept()
			if err != nil {
				results <- err
				continue
			}
			go func() {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				b := make([]byte, 7)
				_, err := io.ReadFull(conn, b)
				if err == nil {
					_, err = conn.Write(b)
				}
				results <- err
			}()
		}
	}()
	assigned := make(chan netip.Addr, count)
	for i, e := range endpoints {
		go func(i int, e *testDatagramEndpoint) {
			transport, a, err := AllocateClient(ctx, e, serverEndpoint.addr, 1200)
			if err != nil {
				e.Close()
				results <- err
				return
			}
			assigned <- a.VirtualIP
			v, err := NewVirtualStackWithTransport(Config{VirtualIP: a.VirtualIP, PeerSubnet: netip.PrefixFrom(a.ServerIP, 32), MTU: a.MTU}, transport)
			if err != nil {
				transport.Close()
				results <- err
				return
			}
			defer v.Close()
			conn, err := v.Dial(ctx, a.ServerIP.String(), 6767)
			if err != nil {
				results <- err
				return
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			message := []byte(fmt.Sprintf("hello-%d", i))
			_, err = conn.Write(message)
			if err == nil {
				reply := make([]byte, len(message))
				_, err = io.ReadFull(conn, reply)
				if err == nil && !bytes.Equal(reply, message) {
					err = fmt.Errorf("wrong peer reply: %q", reply)
				}
			}
			results <- err
		}(i, e)
	}
	for i := 0; i < count*2; i++ {
		select {
		case err := <-results:
			if err != nil {
				t.Fatal(err)
			}
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	seen := map[netip.Addr]bool{}
	for i := 0; i < count; i++ {
		ip := <-assigned
		if seen[ip] || ip == testServerConfig().VirtualIP {
			t.Fatalf("duplicate/reserved assignment: %s", ip)
		}
		seen[ip] = true
	}
}

// TestAllocationRetryExpiryAndExhaustion checks atomic allocation independently
// of gVisor and uses explicit timestamps rather than timing-sensitive sleeps.
func TestAllocationRetryExpiryAndExhaustion(t *testing.T) {
	h := &datagramHub{}
	e := h.endpoint("192.0.2.2:45001")
	cfg := testServerConfig()
	cfg.AddressPool = netip.MustParsePrefix("10.200.0.0/30")
	s, err := NewServerTransport(e, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	peer := Peer{AddrPort: netip.MustParseAddrPort("192.0.2.1:45000")}
	now := time.Now()
	id := sessionID{1}
	first, err := s.allocate(peer, id, now)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := s.allocate(peer, id, now)
	if err != nil || !bytes.Equal(first, retry) {
		t.Fatal("retry changed assignment")
	}
	exhausted, _ := s.allocate(peer, sessionID{2}, now)
	kind, _, _, _ := parseSessionMessage(exhausted)
	if kind != sessionRejected {
		t.Fatal("pool did not exhaust")
	}
	replacement, _ := s.allocate(peer, sessionID{2}, now.Add(cfg.IdleTimeout))
	kind, _, payload, err := parseSessionMessage(replacement)
	if err != nil || kind != sessionAssignment {
		t.Fatal("expired allocation was not reclaimed")
	}
	_, _, old, _ := parseSessionMessage(first)
	if bytes.Equal(old[:16], payload[:16]) {
		t.Fatal("reused session token")
	}
	if len(s.tokens) != 1 || len(s.requests) != 1 || len(s.addresses) != 1 {
		t.Fatal("expired allocation retained")
	}
}

// TestSessionPacketBinding confirms that neither an invalid token, another
// physical endpoint, nor a forged virtual source can inject into the stack.
func TestSessionPacketBinding(t *testing.T) {
	h := &datagramHub{}
	e := h.endpoint("192.0.2.2:45001")
	client := h.endpoint("192.0.2.1:45000")
	other := h.endpoint("192.0.2.3:45000")
	s, err := NewServerTransport(e, testServerConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	response, _ := s.allocate(client.addr, sessionID{1}, time.Now())
	_, _, a, _ := parseSessionMessage(response)
	var token sessionID
	copy(token[:], a[:16])
	packet := make([]byte, 20)
	packet[0] = 0x45
	packet[3] = 20
	copy(packet[12:16], a[16:20])
	copy(packet[16:20], a[20:24])
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	client.SendTo(ctx, sessionMessage(sessionData, sessionID{99}, packet), e.addr)
	other.SendTo(ctx, sessionMessage(sessionData, token, packet), e.addr)
	forged := append([]byte(nil), packet...)
	forged[15] = 99
	client.SendTo(ctx, sessionMessage(sessionData, token, forged), e.addr)
	// A valid packet is a barrier behind all invalid packets on the same queue.
	client.SendTo(ctx, sessionMessage(sessionData, token, packet), e.addr)
	received, err := s.Receive(ctx)
	if err != nil || !bytes.Equal(received, packet) {
		t.Fatalf("bad delivery: %x %v", received, err)
	}
	if len(s.incoming) != 0 {
		t.Fatal("invalid packets passed session checks")
	}
}

func TestSessionWireFormat(t *testing.T) {
	id := sessionID{1, 2, 3}
	request := sessionMessage(sessionRequest, id, nil)
	if len(request) != 24 || !bytes.Equal(request[:8], []byte{'P', 'C', 'A', 'T', 1, 1, 0, 0}) || !bytes.Equal(request[8:], id[:]) {
		t.Fatalf("unexpected request fields: %x", request)
	}
	a := Assignment{netip.MustParseAddr("10.200.0.3"), netip.MustParseAddr("10.200.0.2"), 1200}
	response := sessionMessage(sessionAssignment, id, encodeAssignment(a, sessionID{9}, 120))
	if len(response) != 54 {
		t.Fatal("unexpected assignment fields")
	}
	for _, bad := range [][]byte{nil, request[:23], append(request, 0), sessionMessage(99, id, nil), sessionMessage(sessionAssignment, id, nil), sessionMessage(sessionData, id, []byte{1})} {
		if _, _, _, err := parseSessionMessage(bad); err == nil {
			t.Fatalf("accepted malformed message: %x", bad)
		}
	}
	bad := append([]byte(nil), request...)
	bad[4] = 2
	if _, _, _, err := parseSessionMessage(bad); err == nil {
		t.Fatal("accepted unknown version")
	}
	bad[4] = 1
	bad[6] = 1
	if _, _, _, err := parseSessionMessage(bad); err == nil {
		t.Fatal("accepted reserved bits")
	}
}

func TestAllocationCancellation(t *testing.T) {
	h := &datagramHub{}
	e := h.endpoint("192.0.2.1:45000")
	defer e.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err := AllocateClient(ctx, e, Peer{AddrPort: netip.MustParseAddrPort("192.0.2.2:45001")}, 1200)
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestSubnetBridgeAndConfiguration(t *testing.T) {
	cfg := newTestConfig()
	cfg.PeerSubnet = netip.MustParsePrefix("10.200.0.123/24")
	normalized, err := cfg.normalize()
	if err != nil {
		t.Fatal(err)
	}
	if normalized.PeerSubnet.String() != "10.200.0.0/24" {
		t.Fatal(normalized)
	}
	b := &packetBridge{config: normalized}
	packet := make([]byte, 20)
	packet[0] = 0x45
	packet[3] = 20
	src := netip.MustParseAddr("10.200.0.99").As4()
	dst := cfg.VirtualIP.As4()
	copy(packet[12:16], src[:])
	copy(packet[16:20], dst[:])
	if !b.validPacket(packet, true) {
		t.Fatal("subnet peer dropped")
	}
	packet[14] = 1
	if b.validPacket(packet, true) {
		t.Fatal("outside subnet accepted")
	}
}

// TestSessionLimitsAndShutdown verifies peer limits even when the address pool
// has space, and checks that closing transports wakes blocked receives.
func TestSessionLimitsAndShutdown(t *testing.T) {
	h := &datagramHub{}
	endpoint := h.endpoint("192.0.2.2:45001")
	cfg := testServerConfig()
	cfg.MaxPeers = 1
	s, err := NewServerTransport(endpoint, cfg)
	if err != nil {
		t.Fatal(err)
	}
	peer := Peer{AddrPort: netip.MustParseAddrPort("192.0.2.1:45000")}
	first, _ := s.allocate(peer, sessionID{1}, time.Now())
	kind, _, _, _ := parseSessionMessage(first)
	if kind != sessionAssignment {
		t.Fatal("first allocation failed")
	}
	rejected, _ := s.allocate(peer, sessionID{2}, time.Now())
	kind, _, _, _ = parseSessionMessage(rejected)
	if kind != sessionRejected {
		t.Fatal("peer limit ignored")
	}
	done := make(chan error, 1)
	go func() { _, err := s.Receive(context.Background()); done <- err }()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, ErrClosed) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not wake Receive")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestSessionConfigurationRejected(t *testing.T) {
	h := &datagramHub{}
	e := h.endpoint("192.0.2.2:45001")
	defer e.Close()
	for _, modify := range []func(*ServerConfig){
		func(c *ServerConfig) { c.AddressPool = netip.Prefix{} },
		func(c *ServerConfig) { c.AddressPool = netip.MustParsePrefix("10.200.0.2/31") },
		func(c *ServerConfig) { c.VirtualIP = netip.MustParseAddr("10.200.0.0") },
		func(c *ServerConfig) { c.VirtualIP = netip.MustParseAddr("10.200.0.255") },
		func(c *ServerConfig) { c.MTU = 1500 },
		func(c *ServerConfig) { c.MaxPeers = -1 },
		func(c *ServerConfig) { c.IdleTimeout = time.Millisecond },
	} {
		cfg := testServerConfig()
		modify(&cfg)
		if s, err := NewServerTransport(e, cfg); err == nil {
			s.Close()
			t.Fatal("accepted invalid config", cfg)
		}
	}
	var typedNil *testDatagramEndpoint
	if _, err := NewServerTransport(typedNil, testServerConfig()); err == nil {
		t.Fatal("accepted typed nil")
	}
	if _, _, err := AllocateClient(context.Background(), typedNil, e.addr, 1200); err == nil {
		t.Fatal("accepted typed nil client")
	}
}

// TestClientKeepalive observes a real client heartbeat without injecting any
// inner TCP traffic. Its wire payload must contain only the session header.
func TestClientKeepalive(t *testing.T) {
	h := &datagramHub{}
	server := h.endpoint("192.0.2.2:45001")
	defer server.Close()
	client := h.endpoint("192.0.2.1:45000")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		request, peer, err := server.ReceiveFrom(ctx)
		if err != nil {
			result <- err
			return
		}
		_, id, _, err := parseSessionMessage(request)
		if err != nil {
			result <- err
			return
		}
		token := sessionID{42}
		a := Assignment{netip.MustParseAddr("10.200.0.3"), netip.MustParseAddr("10.200.0.2"), 1200}
		err = server.SendTo(ctx, sessionMessage(sessionAssignment, id, encodeAssignment(a, token, 3)), peer)
		if err != nil {
			result <- err
			return
		}
		heartbeat, _, err := server.ReceiveFrom(ctx)
		if err != nil {
			result <- err
			return
		}
		kind, got, payload, err := parseSessionMessage(heartbeat)
		if err == nil && (kind != sessionKeepalive || got != token || len(payload) != 0) {
			err = fmt.Errorf("invalid heartbeat")
		}
		result <- err
	}()
	transport, _, err := AllocateClient(ctx, client, server.addr, 1200)
	if err != nil {
		client.Close()
		t.Fatal(err)
	}
	defer transport.Close()
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	// Close interrupts the client's blocked receiver and joins its timer worker.
	if err := transport.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestPlainEndpointCancellation(t *testing.T) {
	f := newUDPFixture(t)
	conn := f.open(t, false)
	endpoint, err := NewPlainUDPEndpoint(conn)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := endpoint.ReceiveFrom(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := endpoint.SendTo(ctx, []byte("data"), Peer{AddrPort: netip.MustParseAddrPort("192.0.2.1:45000")}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func FuzzSessionWire(f *testing.F) {
	f.Add(sessionMessage(sessionRequest, sessionID{1}, nil))
	f.Add([]byte("invalid"))
	f.Fuzz(func(t *testing.T, b []byte) {
		kind, id, payload, err := parseSessionMessage(b)
		if err != nil {
			return
		}
		if !bytes.Equal(sessionMessage(kind, id, payload), b) {
			t.Fatal("wire parser did not round trip")
		}
	})
}

// TestExpiredSessionClosesTCP checks the shared stack's lease cleanup callback,
// including an accepted connection that would otherwise outlive its assignment.
func TestExpiredSessionClosesTCP(t *testing.T) {
	h := &datagramHub{}
	e := h.endpoint("192.0.2.2:45001")
	client := h.endpoint("192.0.2.1:45000")
	cfg := testServerConfig()
	server, err := NewTCPServer(e, cfg, 6767)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { server.Close() })
	defer stop()
	transport, a, err := AllocateClient(ctx, client, e.addr, 1200)
	if err != nil {
		client.Close()
		t.Fatal(err)
	}
	v, err := NewVirtualStackWithTransport(Config{VirtualIP: a.VirtualIP, PeerSubnet: netip.PrefixFrom(a.ServerIP, 32), MTU: 1200}, transport)
	if err != nil {
		transport.Close()
		t.Fatal(err)
	}
	defer v.Close()
	outgoing, err := v.Dial(ctx, a.ServerIP.String(), 6767)
	if err != nil {
		t.Fatal(err)
	}
	defer outgoing.Close()
	accepted, err := server.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer accepted.Close()
	sessions := server.stack.bridge.transport.(*ServerTransport)
	sessions.mu.Lock()
	sessions.expireLocked(time.Now().Add(cfg.IdleTimeout))
	remaining := len(sessions.tokens)
	sessions.mu.Unlock()
	if remaining != 0 {
		t.Fatal("session retained after expiry")
	}
	accepted.SetReadDeadline(time.Now().Add(time.Second))
	_, err = accepted.Read(make([]byte, 1))
	if err == nil {
		t.Fatal("expired connection remained readable")
	}
	if timeout, ok := err.(interface{ Timeout() bool }); ok && timeout.Timeout() {
		t.Fatalf("expired connection was not closed: %v", err)
	}
}

// TestSessionEndpointFailure checks that worker shutdown preserves the native
// cause in Close rather than masking it with the cancellation used to wake I/O.
func TestSessionEndpointFailure(t *testing.T) {
	for _, clientMode := range []bool{false, true} {
		t.Run(fmt.Sprint(clientMode), func(t *testing.T) {
			h := &datagramHub{}
			e := h.endpoint("192.0.2.2:45001")
			e.failure = make(chan error, 1)
			server, err := NewServerTransport(e, testServerConfig())
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			var transport PacketTransport = server
			if clientMode {
				endpoint := h.endpoint("192.0.2.1:45000")
				endpoint.failure = make(chan error, 1)
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				client, _, err := AllocateClient(ctx, endpoint, e.addr, 1200)
				if err != nil {
					endpoint.Close()
					t.Fatal(err)
				}
				defer client.Close()
				transport = client
				e = endpoint
			}
			cause := errors.New("simulated capture failure")
			e.failure <- cause
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_, err = transport.Receive(ctx)
			if !errors.Is(err, ErrClosed) {
				t.Fatal(err)
			}
			select {
			case <-e.done:
			case <-ctx.Done():
				t.Fatal("failed transport did not release its owned endpoint")
			}
			if err := transport.Close(); !errors.Is(err, cause) {
				t.Fatalf("native cause lost: %v", err)
			}
		})
	}
}

// TestQueuedPacketExpires ensures buffered ingress cannot survive reassignment
// just because its token was valid when the datagram first arrived.
func TestQueuedPacketExpires(t *testing.T) {
	h := &datagramHub{}
	e := h.endpoint("192.0.2.2:45001")
	s, err := NewServerTransport(e, testServerConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	reply, _ := s.allocate(Peer{AddrPort: netip.MustParseAddrPort("192.0.2.1:45000")}, sessionID{1}, time.Now())
	_, _, payload, _ := parseSessionMessage(reply)
	var token sessionID
	copy(token[:], payload[:16])
	s.incoming <- sessionPacket{token, []byte("expired packet")}
	s.mu.Lock()
	s.expireLocked(time.Now().Add(s.config.IdleTimeout))
	s.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := s.Receive(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expired ingress delivered: %v", err)
	}
}

func TestServerCloseReleasesSessionState(t *testing.T) {
	h := &datagramHub{}
	endpoint := h.endpoint("192.0.2.2:45001")
	server, err := NewServerTransport(endpoint, testServerConfig())
	if err != nil {
		t.Fatal(err)
	}
	response, _ := server.allocate(Peer{AddrPort: netip.MustParseAddrPort("192.0.2.1:45000")}, sessionID{1}, time.Now())
	_, _, body, _ := parseSessionMessage(response)
	var token sessionID
	copy(token[:], body[:16])
	server.incoming <- sessionPacket{token, []byte("queued")}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	if len(server.incoming) != 0 || len(server.requests) != 0 || len(server.tokens) != 0 || len(server.addresses) != 0 || server.expire != nil {
		t.Fatal("closed server retained leases or packets")
	}
	if _, err := server.Receive(context.Background()); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
}

func TestPlainEndpointPreservesInFlightCancellation(t *testing.T) {
	f := newUDPFixture(t)
	conn := f.open(t, false)
	endpoint, _ := NewPlainUDPEndpoint(conn)
	// Keep the injection gate occupied so the send must wait for its context.
	<-conn.sendGate
	defer func() { conn.sendGate <- struct{}{} }()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Millisecond)
	defer cancel()
	if err := endpoint.SendTo(ctx, []byte("blocked"), Peer{AddrPort: netip.MustParseAddrPort("192.0.2.1:45000")}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("caller cancellation was masked: %v", err)
	}
}

func TestDialStackOwnsFailedEndpoint(t *testing.T) {
	h := &datagramHub{}
	endpoint := h.endpoint("192.0.2.1:45000")
	_, _, err := DialStack(context.Background(), endpoint, Peer{}, 1200)
	if err == nil {
		t.Fatal("invalid peer accepted")
	}
	select {
	case <-endpoint.done:
	default:
		t.Fatal("failed setup leaked endpoint")
	}
}

func TestOldSessionMarkerRejected(t *testing.T) {
	request := sessionMessage(sessionRequest, sessionID{1}, nil)
	copy(request, "PCNT")
	if _, _, _, err := parseSessionMessage(request); err == nil {
		t.Fatal("obsolete session marker accepted")
	}
}

// Independent fixture from the protocol specification, rather than another
// round-trip through the same encoder, locks the v1 field offsets and byte order.
func TestAssignmentSpecificationVector(t *testing.T) {
	want, err := hex.DecodeString(
		"5043415401020000" +
			"01020300000000000000000000000000" +
			"09000000000000000000000000000000" +
			"0ac800030ac8000204b000000078")
	if err != nil {
		t.Fatal(err)
	}
	assignment := Assignment{VirtualIP: netip.MustParseAddr("10.200.0.3"), ServerIP: netip.MustParseAddr("10.200.0.2"), MTU: 1200}
	got := sessionMessage(sessionAssignment, sessionID{1, 2, 3}, encodeAssignment(assignment, sessionID{9}, 120))
	if !bytes.Equal(got, want) {
		t.Fatalf("assignment disagrees with specification: %x", got)
	}
}
