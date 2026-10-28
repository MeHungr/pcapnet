package pcapnet

import (
	"context"
	"errors"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"io"
	"net/netip"
	"testing"
	"time"
)

// TestAcceptGenerationAfterIPReuse keeps an old accepted connection and an old
// queued accept across /30 address reuse. Synthetic exact handles exercise the
// core independently of DTLS; real shared-tuple DTLS is tested in its package.
func TestAcceptGenerationAfterIPReuse(t *testing.T) {
	h := &datagramHub{}
	raw := h.endpoint("192.0.2.2:45001")
	server, err := NewTCPServer(raw, ServerConfig{VirtualIP: netip.MustParseAddr("10.200.0.1"), AddressPool: netip.MustParsePrefix("10.200.0.0/30")}, 6767)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { server.Close() })
	defer stop()
	open := func(id byte) (*VirtualStack, Assignment, Peer) {
		endpoint := h.endpoint("192.0.2.1:45000")
		h.mu.Lock()
		endpoint.addr.ConnectionID[0] = id
		h.mu.Unlock()
		v, a, err := DialStack(ctx, endpoint, raw.addr, 1200)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(v.Close)
		return v, a, endpoint.addr
	}
	first, assignment, original := open(1)
	outgoing, err := first.Dial(ctx, assignment.ServerIP.String(), 6767)
	if err != nil {
		t.Fatal(err)
	}
	defer outgoing.Close()
	accepted, peer, err := server.AcceptWithPeer()
	if err != nil || peer != original {
		t.Fatalf("first accept: %+v %v", peer, err)
	}
	defer accepted.Close()
	queued, err := first.Dial(ctx, assignment.ServerIP.String(), 6767)
	if err != nil {
		t.Fatal(err)
	}
	defer queued.Close()
	listener := server.Listener.(*peerListener)
	for len(listener.ready) == 0 {
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(time.Millisecond):
		}
	}
	transport := server.sessions()
	transport.mu.Lock()
	generation := transport.addresses[assignment.VirtualIP]
	oldMark := generation.mark
	oldPacket := sessionPacket{generation.token, []byte("dequeued before retirement")}
	transport.mu.Unlock()
	if err := server.DisconnectPeer(ctx, original); err != nil {
		t.Fatal(err)
	}
	replacement, next, newer := open(2)
	if next.VirtualIP != assignment.VirtualIP {
		t.Fatal("test did not reuse virtual IP")
	}
	out, err := replacement.Dial(ctx, next.ServerIP.String(), 6767)
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	in, got, err := server.AcceptWithPeer()
	if err != nil || got != newer {
		t.Fatalf("stale queued acceptance rebound: %+v %v", got, err)
	}
	defer in.Close()
	if accepted.(PeerConnection).Peer() != original {
		t.Fatal("retained connection metadata changed")
	}
	if transport.injectGeneration(oldPacket, func([]byte, uint32) { t.Fatal("stale dequeued packet injected") }) {
		t.Fatal("old generation accepted")
	}
	// Already queued old endpoint output must not be sent using the new lease.
	packet := testInnerIPv4(t, 60)
	copy(packet[12:16], server.sessions().config.VirtualIP.AsSlice())
	copy(packet[16:20], next.VirtualIP.AsSlice())
	// Mark rejection precedes payload serialization; IPv4 checksum is irrelevant.
	if err := transport.sendMarked(ctx, packet, oldMark); err != nil {
		t.Fatal(err)
	}
	if err := server.DisconnectPeer(ctx, original); err != nil {
		t.Fatal(err)
	}
	if _, err := out.Write([]byte("new")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(in, make([]byte, 3)); err != nil {
		t.Fatal(err)
	}
}

// TestRetirementQuarantinesAddress delays cleanup deliberately. Invalidation is
// immediate and cancellation bounds the caller, but the allocator cannot hand a
// still-retiring address to a replacement. Late cleanup compares generation
// pointers before release, and stale handles cannot select a replacement.
func TestRetirementQuarantinesAddress(t *testing.T) {
	h := &datagramHub{}
	endpoint := h.endpoint("192.0.2.2:45001")
	s, err := NewServerTransport(endpoint, ServerConfig{VirtualIP: netip.MustParseAddr("10.200.0.1"), AddressPool: netip.MustParsePrefix("10.200.0.0/30")})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	release, started := make(chan struct{}), make(chan struct{})
	s.mu.Lock()
	s.retire = func(*allocation) { close(started); <-release }
	s.mu.Unlock()
	original := Peer{AddrPort: netip.MustParseAddrPort("192.0.2.1:45000"), ConnectionID: [16]byte{1}}
	_, err = s.allocate(original, sessionID{1}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	var old *allocation
	for _, a := range s.tokens {
		old = a
	}
	s.mu.Unlock()
	wrapper := &TCPServer{stack: &VirtualStack{bridge: &packetBridge{transport: s}}}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- wrapper.DisconnectPeer(ctx, original) }()
	<-started
	if err := awaitError(t, result); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("cleanup wait not cancellable: %v", err)
	}
	done := []<-chan struct{}{old.cleaned}
	select {
	case <-old.done:
	default:
		t.Fatal("delayed cleanup deferred invalidation")
	}
	replacement := original
	replacement.ConnectionID[0] = 2
	rejected, err := s.allocate(replacement, sessionID{2}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	kind, _, _, _ := parseSessionMessage(rejected)
	if kind != sessionRejected {
		t.Fatal("quarantined IP reassigned before cleanup")
	}
	close(release)
	<-done[0]
	if _, err := s.allocate(replacement, sessionID{2}, time.Now()); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	a := s.addresses[old.ip]
	s.mu.Unlock()
	if a == nil || a.key.endpoint != replacement || a == old {
		t.Fatal("replacement generation missing")
	}
	if len(s.retirePeer(original)) != 0 {
		t.Fatal("old handle selected replacement")
	}
}

func TestRawPeerInformation(t *testing.T) {
	f := newUDPFixture(t)
	conn := f.open(t, true)
	endpoint, _ := NewPlainUDPEndpoint(conn)
	peer := Peer{AddrPort: netip.MustParseAddrPort("192.0.2.1:40000")}
	info, err := endpoint.PeerInfo(peer)
	if err != nil || info.Encrypted || info.PeerCertificateAuthenticated || info.ClientCertificateAuthenticated || len(info.Certificates) != 0 || len(info.VerifiedChains) != 0 || len(info.LocalCertificates) != 0 {
		t.Fatalf("raw authentication: %+v %v", info, err)
	}
	endpoint.Close()
	select {
	case <-info.Done:
	default:
		t.Fatal("raw endpoint closure not reflected")
	}
	if _, err := endpoint.PeerInfo(peer); !errors.Is(err, ErrPeerNotFound) {
		t.Fatal(err)
	}
}

// TestDisconnectPendingHandshake deliberately never ACKs the server's SYN-ACK.
// Connecting endpoints have no GetRemoteAddress result; retirement must use the
// immutable endpoint ID and abort them without waiting for TCP retry timeouts.
func TestDisconnectPendingHandshake(t *testing.T) {
	h := &datagramHub{}
	endpoint := h.endpoint("192.0.2.2:45001")
	client := h.endpoint("192.0.2.1:45000")
	server, err := NewTCPServer(endpoint, ServerConfig{VirtualIP: netip.MustParseAddr("10.200.0.1"), AddressPool: netip.MustParsePrefix("10.200.0.0/30")}, 6767)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	transport := server.sessions()
	response, err := transport.allocate(client.addr, sessionID{1}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	_, _, payload, err := parseSessionMessage(response)
	if err != nil {
		t.Fatal(err)
	}
	assignment, token, _, err := decodeAssignment(payload, 1200)
	if err != nil {
		t.Fatal(err)
	}
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: assignment.VirtualIP.AsSlice(), DstIP: assignment.ServerIP.AsSlice()}
	syn := &layers.TCP{SrcPort: 12345, DstPort: 6767, SYN: true, Seq: 1, Window: 65535}
	if err := syn.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ip, syn); err != nil {
		t.Fatal(err)
	}
	if err := client.SendTo(ctx, sessionMessage(sessionData, token, buffer.Bytes()), endpoint.addr); err != nil {
		t.Fatal(err)
	}
	listener := server.Listener.(*peerListener)
	for {
		listener.mu.Lock()
		count := len(listener.pending)
		listener.mu.Unlock()
		if count != 0 && len(server.stack.Stack.RegisteredEndpoints()) != 0 {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("handshake did not start")
		case <-time.After(time.Millisecond):
		}
	}
	if err := server.DisconnectPeer(ctx, client.addr); err != nil {
		t.Fatalf("pending handshake not interrupted: %v", err)
	}
	listener.mu.Lock()
	count := len(listener.pending)
	listener.mu.Unlock()
	if count != 0 {
		t.Fatal("handshake worker remained registered")
	}
}
