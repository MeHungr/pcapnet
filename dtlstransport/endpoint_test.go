package dtlstransport

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/MeHungr/pcapnet"
)

type wirePacket struct {
	data     []byte
	from, to pcapnet.Peer
}

// hub broadcasts records to every PCAP receiver with the matching physical
// address. This reproduces independent client processes sharing one UDP tuple.
type hub struct {
	mu         sync.Mutex
	endpoints  []*rawEndpoint
	wire       []wirePacket
	tamperNext bool
}
type rawEndpoint struct {
	hub              *hub
	addr             pcapnet.Peer
	incoming         chan wirePacket
	done             chan struct{}
	once             sync.Once
	blockApplication chan struct{}
	sendStarted      chan struct{}
}

func (h *hub) endpoint(address string) *rawEndpoint {
	e := &rawEndpoint{hub: h, addr: pcapnet.Peer{AddrPort: netip.MustParseAddrPort(address)}, incoming: make(chan wirePacket, 2048), done: make(chan struct{})}
	h.mu.Lock()
	h.endpoints = append(h.endpoints, e)
	h.mu.Unlock()
	return e
}
func (e *rawEndpoint) MaxDatagramSize() int { return 1472 }
func (e *rawEndpoint) Close() error         { e.once.Do(func() { close(e.done) }); return nil }
func (e *rawEndpoint) SendTo(ctx context.Context, b []byte, to pcapnet.Peer) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case <-e.done:
		return net.ErrClosed
	default:
	}
	e.hub.mu.Lock()
	blocked := e.blockApplication
	started := e.sendStarted
	e.hub.mu.Unlock()
	if len(b) > muxHeaderSize && b[muxHeaderSize] == 23 && blocked != nil {
		if started != nil {
			select {
			case started <- struct{}{}:
			default:
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-e.done:
			return net.ErrClosed
		case <-blocked:
		}
	}
	e.hub.mu.Lock()
	defer e.hub.mu.Unlock()
	b = append([]byte(nil), b...)
	if len(b) > muxHeaderSize && b[muxHeaderSize] == 23 && e.hub.tamperNext {
		b[len(b)-1] ^= 1
		e.hub.tamperNext = false
	}
	packet := wirePacket{b, e.addr, to}
	e.hub.wire = append(e.hub.wire, packet)
	for _, target := range e.hub.endpoints {
		if target.addr == to {
			select {
			case <-target.done:
			case target.incoming <- packet:
			default:
			}
		}
	}
	return nil
}
func (e *rawEndpoint) ReceiveFrom(ctx context.Context) ([]byte, pcapnet.Peer, error) {
	select {
	case <-ctx.Done():
		return nil, pcapnet.Peer{}, ctx.Err()
	case <-e.done:
		return nil, pcapnet.Peer{}, net.ErrClosed
	case p := <-e.incoming:
		return append([]byte(nil), p.data...), p.from, nil
	}
}

// credentials creates test-only CA-issued server and client certificates. No
// certificate files or host trust-store changes are needed for these tests.
func credentials(t *testing.T) (*x509.CertPool, tls.Certificate, tls.Certificate) {
	t.Helper()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, root, root, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	leaf := func(serial int64, server bool) tls.Certificate {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		cert := &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: root.NotBefore, NotAfter: root.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
		if server {
			cert.DNSNames = []string{"server.test"}
			cert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		}
		der, err := x509.CreateCertificate(rand.Reader, cert, ca, &key.PublicKey, rootKey)
		if err != nil {
			t.Fatal(err)
		}
		return tls.Certificate{Certificate: [][]byte{der, ca.Raw}, PrivateKey: key}
	}
	return roots, leaf(2, true), leaf(3, false)
}
func securePair(t *testing.T) (*Endpoint, *Endpoint, *hub, *rawEndpoint, *rawEndpoint) {
	t.Helper()
	roots, serverCert, clientCert := credentials(t)
	h := &hub{}
	sr := h.endpoint("192.0.2.2:45001")
	cr := h.endpoint("192.0.2.1:45000")
	server, err := Listen(sr, ServerConfig{Certificates: []tls.Certificate{serverCert}, ClientCAs: roots, RequireClientCertificate: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := Dial(ctx, cr, sr.addr, ClientConfig{ServerName: "server.test", RootCAs: roots, Certificates: []tls.Certificate{clientCert}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	return server, client, h, sr, cr
}

func TestSecureAllocatedConcurrentTCP(t *testing.T) {
	roots, serverCert, clientCert := credentials(t)
	h := &hub{}
	sr := h.endpoint("192.0.2.2:45001")
	secure, err := Listen(sr, ServerConfig{Certificates: []tls.Certificate{serverCert}, ClientCAs: roots, RequireClientCertificate: true})
	if err != nil {
		t.Fatal(err)
	}
	defer secure.Close()
	server, err := pcapnet.NewTCPServer(secure, pcapnet.ServerConfig{VirtualIP: netip.MustParseAddr("10.200.0.1"), AddressPool: netip.MustParsePrefix("10.200.0.0/24"), MTU: 1200}, 6767)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { server.Close() })
	defer stop()
	const count = 5
	results := make(chan error, count*2)
	handles := make(chan pcapnet.Peer, count)
	addresses := make(chan netip.Addr, count)
	clients := make([]*rawEndpoint, count)
	for i := range clients {
		clients[i] = h.endpoint("192.0.2.1:45000")
	}
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
				b := make([]byte, 22)
				_, err := io.ReadFull(conn, b)
				if err == nil {
					_, err = conn.Write(b)
				}
				results <- err
			}()
		}
	}()
	for i, raw := range clients {
		go func(i int, raw *rawEndpoint) {
			secure, err := Dial(ctx, raw, sr.addr, ClientConfig{ServerName: "server.test", RootCAs: roots, Certificates: []tls.Certificate{clientCert}})
			if err != nil {
				raw.Close()
				results <- err
				return
			}
			defer secure.Close()
			handles <- secure.Peer()
			transport, a, err := pcapnet.AllocateClient(ctx, secure, secure.Peer(), 1200)
			if err != nil {
				results <- err
				return
			}
			addresses <- a.VirtualIP
			v, err := pcapnet.NewVirtualStackWithTransport(pcapnet.Config{VirtualIP: a.VirtualIP, PeerSubnet: netip.PrefixFrom(a.ServerIP, 32), MTU: a.MTU}, transport)
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
			message := []byte(fmt.Sprintf("confidential-client-%02d", i))
			_, err = conn.Write(message)
			if err == nil {
				reply := make([]byte, len(message))
				_, err = io.ReadFull(conn, reply)
				if err == nil && !bytes.Equal(reply, message) {
					err = fmt.Errorf("wrong echo: %q", reply)
				}
			}
			results <- err
		}(i, raw)
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
	seen := map[[16]byte]bool{}
	allocated := map[netip.Addr]bool{}
	for i := 0; i < count; i++ {
		peer := <-handles
		if peer.ConnectionID == ([16]byte{}) || seen[peer.ConnectionID] {
			t.Fatal("missing/duplicate secure peer identity")
		}
		seen[peer.ConnectionID] = true
		ip := <-addresses
		if allocated[ip] {
			t.Fatal("duplicate allocated IP")
		}
		allocated[ip] = true
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, packet := range h.wire {
		if len(packet.data) > 1472 {
			t.Fatal("physical MTU exceeded")
		}
		if bytes.Contains(packet.data, []byte("PCAT")) || bytes.Contains(packet.data, []byte("confidential-client-")) {
			t.Fatal("plaintext allocation/data leaked to the wire")
		}
	}
}

func TestTamperReplayAndMTU(t *testing.T) {
	server, client, h, sr, cr := securePair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	h.mu.Lock()
	h.tamperNext = true
	h.mu.Unlock()
	if err := client.SendTo(ctx, []byte("modified-record"), client.Peer()); err != nil {
		t.Fatal(err)
	}
	if err := client.SendTo(ctx, []byte("authentic-record"), client.Peer()); err != nil {
		t.Fatal(err)
	}
	b, peer, err := server.ReceiveFrom(ctx)
	if err != nil || string(b) != "authentic-record" {
		t.Fatalf("tampered data accepted or connection failed: %q %v", b, err)
	}
	if peer.ConnectionID == ([16]byte{}) {
		t.Fatal("server exposed only the physical address")
	}
	// Copy the final client application record and replay it verbatim.
	h.mu.Lock()
	var replay []byte
	for i := len(h.wire) - 1; i >= 0; i-- {
		p := h.wire[i]
		if p.from == cr.addr && p.data[muxHeaderSize] == 23 {
			replay = append([]byte(nil), p.data...)
			break
		}
	}
	h.mu.Unlock()
	if err := cr.SendTo(ctx, replay, sr.addr); err != nil {
		t.Fatal(err)
	}
	short, stop := context.WithTimeout(ctx, 30*time.Millisecond)
	defer stop()
	if _, _, err := server.ReceiveFrom(short); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("replayed application record delivered: %v", err)
	}
	payload := bytes.Repeat([]byte{0xab}, client.MaxDatagramSize())
	if err := client.SendTo(ctx, payload, client.Peer()); err != nil {
		t.Fatal(err)
	}
	got, _, err := server.ReceiveFrom(ctx)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("MTU-sized delivery failed: %v", err)
	}
	if err := client.SendTo(ctx, append(payload, 0), client.Peer()); !errors.Is(err, pcapnet.ErrDatagramTooLarge) {
		t.Fatal(err)
	}
	if err := server.SendTo(ctx, []byte("reply"), peer); err != nil {
		t.Fatal(err)
	}
	got, _, err = client.ReceiveFrom(ctx)
	if err != nil || string(got) != "reply" {
		t.Fatal(string(got), err)
	}
	stale := peer
	stale.ConnectionID[0] ^= 1
	if err := server.SendTo(ctx, []byte("wrong-session"), stale); !errors.Is(err, net.ErrClosed) {
		t.Fatal("unknown peer did not fail", err)
	}
}

func TestCertificateVerification(t *testing.T) {
	roots, serverCert, clientCert := credentials(t)
	for _, mode := range []string{"wrong-name", "untrusted-server", "missing-client-certificate", "untrusted-client"} {
		t.Run(mode, func(t *testing.T) {
			h := &hub{}
			sr := h.endpoint("192.0.2.2:45001")
			cr := h.endpoint("192.0.2.1:45000")
			server, err := Listen(sr, ServerConfig{Certificates: []tls.Certificate{serverCert}, ClientCAs: roots, RequireClientCertificate: true})
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			cfg := ClientConfig{ServerName: "server.test", RootCAs: roots, Certificates: []tls.Certificate{clientCert}}
			switch mode {
			case "wrong-name":
				cfg.ServerName = "wrong.test"
			case "untrusted-server":
				cfg.RootCAs = x509.NewCertPool()
			case "missing-client-certificate":
				cfg.Certificates = nil
			case "untrusted-client":
				_, _, other := credentials(t)
				cfg.Certificates = []tls.Certificate{other}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			client, err := Dial(ctx, cr, sr.addr, cfg)
			if err == nil {
				client.Close()
				t.Fatal("invalid credentials accepted")
			}
			select {
			case <-cr.done:
			default:
				t.Fatal("failed handshake leaked raw endpoint")
			}
		})
	}
}

func TestHandshakeCancellationAndClose(t *testing.T) {
	roots, _, _ := credentials(t)
	h := &hub{}
	raw := h.endpoint("192.0.2.1:45000")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	client, err := Dial(ctx, raw, pcapnet.Peer{AddrPort: netip.MustParseAddrPort("192.0.2.2:45001")}, ClientConfig{RootCAs: roots, ServerName: "server.test"})
	if client != nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("handshake cancellation: %v", err)
	}
	select {
	case <-raw.done:
	default:
		t.Fatal("canceled handshake leaked endpoint")
	}
	server, connected, _, _, _ := securePair(t)
	done := make(chan error, 1)
	go func() { _, _, err := server.ReceiveFrom(context.Background()); done <- err }()
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not wake ReceiveFrom")
	}
	connected.Close()
	server.Close()
}

// TestCanceledSend verifies the entire caller-context -> DTLS deadline -> packet
// deadline -> raw send path. Canceling one write must not poison the next write.
func TestCanceledSend(t *testing.T) {
	server, client, h, _, raw := securePair(t)
	h.mu.Lock()
	raw.blockApplication = make(chan struct{})
	h.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if err := client.SendTo(ctx, []byte("blocked"), client.Peer()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	h.mu.Lock()
	close(raw.blockApplication)
	raw.blockApplication = nil
	h.mu.Unlock()
	ctx2, cancel2 := context.WithTimeout(context.Background(), time.Second)
	defer cancel2()
	if err := client.SendTo(ctx2, []byte("after-cancellation"), client.Peer()); err != nil {
		t.Fatal(err)
	}
	b, _, err := server.ReceiveFrom(ctx2)
	if err != nil || string(b) != "after-cancellation" {
		t.Fatal(string(b), err)
	}
}

func TestAuthorizationAndServerOnlyAuthentication(t *testing.T) {
	roots, serverCert, _ := credentials(t)
	for _, deny := range []bool{false, true} {
		t.Run(fmt.Sprint(deny), func(t *testing.T) {
			h := &hub{}
			sr := h.endpoint("192.0.2.2:45001")
			cr := h.endpoint("192.0.2.1:45000")
			observed := make(chan PeerInfo, 1)
			server, err := Listen(sr, ServerConfig{Certificates: []tls.Certificate{serverCert}, Authorize: func(ctx context.Context, p PeerInfo) error {
				observed <- p
				if deny {
					return errors.New("private authorization details")
				}
				return nil
			}})
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			client, err := Dial(ctx, cr, sr.addr, ClientConfig{RootCAs: roots, ServerName: "server.test"})
			if err != nil {
				if !deny {
					t.Fatal(err)
				}
			} else {
				defer client.Close()
				sendErr := client.SendTo(ctx, []byte("authorized-data"), client.Peer())
				if sendErr != nil && !deny {
					t.Fatal(sendErr)
				}
			}
			select {
			case peer := <-observed:
				if peer.Peer.ConnectionID == ([16]byte{}) || len(peer.Certificates) != 0 {
					t.Fatal("unexpected server-only identity")
				}
			case <-ctx.Done():
				t.Fatal("authorization callback did not run")
			}
			receive, cancelReceive := context.WithTimeout(ctx, 30*time.Millisecond)
			defer cancelReceive()
			b, _, err := server.ReceiveFrom(receive)
			if deny {
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("rejected client exposed data: %q %v", b, err)
				}
			} else if err != nil || string(b) != "authorized-data" {
				t.Fatal(string(b), err)
			}
			// Callback error strings are local policy details, never protocol payloads.
			h.mu.Lock()
			defer h.mu.Unlock()
			for _, packet := range h.wire {
				if bytes.Contains(packet.data, []byte("private authorization details")) {
					t.Fatal("authorization details leaked")
				}
			}
		})
	}
}

func TestBoundedPendingHandshakes(t *testing.T) {
	_, cert, _ := credentials(t)
	h := &hub{}
	sr := h.endpoint("192.0.2.2:45001")
	sender := h.endpoint("192.0.2.1:45000")
	defer sender.Close()
	server, err := Listen(sr, ServerConfig{Certificates: []tls.Certificate{cert}, Limits: Limits{MaxPeers: 1, HandshakeTimeout: time.Minute}})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	// A record that resembles ClientHello reserves a slot, then waits for a valid
	// flight. The cryptographic implementation, not the router, validates its body.
	hello := make([]byte, 25)
	hello[0] = 22
	hello[1] = 0xfe
	hello[2] = 0xfd
	hello[13] = 1
	for i := byte(1); i <= 8; i++ {
		if err := sender.SendTo(context.Background(), frame(routeID{i}, hello), sr.addr); err != nil {
			t.Fatal(err)
		}
	}
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	timeout := time.After(time.Second)
	for {
		server.mu.Lock()
		count := len(server.routes)
		server.mu.Unlock()
		if count > 1 {
			t.Fatal("handshake limit exceeded")
		}
		if count == 1 && len(sr.incoming) == 0 {
			break
		}
		select {
		case <-ticker.C:
		case <-timeout:
			t.Fatal("pending handshakes did not dispatch")
		}
	}
	done := make(chan error, 1)
	go func() { done <- server.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close blocked on pending handshake")
	}
}

func TestInvalidConfigurationAndFraming(t *testing.T) {
	h := &hub{}
	raw := h.endpoint("192.0.2.2:45001")
	defer raw.Close()
	if _, err := Listen(raw, ServerConfig{}); err == nil {
		t.Fatal("server accepted missing certificate")
	}
	var typedNil *rawEndpoint
	if _, err := Listen(typedNil, ServerConfig{}); err == nil {
		t.Fatal("typed nil endpoint accepted")
	}
	for _, bad := range [][]byte{nil, make([]byte, 36), frame(routeID{1}, nil)} {
		if _, _, ok := unframe(bad); ok {
			t.Fatal("invalid framing accepted")
		}
	}
	record := make([]byte, 13)
	valid := frame(routeID{1}, record)
	for _, offset := range []int{0, 4, 5, 6, 7} {
		bad := append([]byte(nil), valid...)
		bad[offset] ^= 1
		if _, _, ok := unframe(bad); ok {
			t.Fatal("invalid header accepted")
		}
	}
	select {
	case <-raw.done:
		t.Fatal("validation error took endpoint ownership")
	default:
	}
}

func FuzzFraming(f *testing.F) {
	f.Add(frame(routeID{1}, make([]byte, 13)))
	f.Add([]byte("bad"))
	f.Fuzz(func(t *testing.T, b []byte) {
		id, record, ok := unframe(b)
		if ok && !bytes.Equal(frame(id, record), b) {
			t.Fatal("framing did not round trip")
		}
	})
}

// TestReconnectIsolation repeats the same allocation request from the same
// physical endpoint over a new DTLS connection. It must get a new lease, and a
// token stolen from the previous connection must not work on the replacement.
func TestReconnectIsolation(t *testing.T) {
	roots, cert, _ := credentials(t)
	h := &hub{}
	sr := h.endpoint("192.0.2.2:45001")
	server, err := Listen(sr, ServerConfig{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	sessions, err := pcapnet.NewServerTransport(server, pcapnet.ServerConfig{VirtualIP: netip.MustParseAddr("10.200.0.1"), AddressPool: netip.MustParsePrefix("10.200.0.0/24"), MTU: 1200})
	if err != nil {
		t.Fatal(err)
	}
	defer sessions.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	open := func() *Endpoint {
		raw := h.endpoint("192.0.2.1:45000")
		client, err := Dial(ctx, raw, sr.addr, ClientConfig{ServerName: "server.test", RootCAs: roots})
		if err != nil {
			t.Fatal(err)
		}
		return client
	}
	request := make([]byte, 24)
	copy(request, "PCAT")
	request[4] = 1
	request[5] = 1
	request[8] = 42
	assign := func(client *Endpoint) []byte {
		if err := client.SendTo(ctx, request, client.Peer()); err != nil {
			t.Fatal(err)
		}
		response, _, err := client.ReceiveFrom(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(response) != 54 || response[5] != 2 {
			t.Fatal("invalid assignment")
		}
		return response
	}
	first := open()
	old := assign(first)
	first.Close()
	second := open()
	defer second.Close()
	current := assign(second)
	if bytes.Equal(old[40:44], current[40:44]) || bytes.Equal(old[24:40], current[24:40]) {
		t.Fatal("reconnected endpoint reused a previous connection's allocation")
	}
	data := func(assignment []byte) []byte {
		b := make([]byte, 44)
		copy(b, "PCAT")
		b[4] = 1
		b[5] = 4
		copy(b[8:24], assignment[24:40])
		b[24] = 0x45
		b[27] = 20
		copy(b[36:40], assignment[40:44])
		copy(b[40:44], assignment[44:48])
		return b
	}
	if err := second.SendTo(ctx, data(old), second.Peer()); err != nil {
		t.Fatal(err)
	}
	valid := data(current)
	if err := second.SendTo(ctx, valid, second.Peer()); err != nil {
		t.Fatal(err)
	}
	packet, err := sessions.Receive(ctx)
	if err != nil || !bytes.Equal(packet, valid[24:]) {
		t.Fatalf("cross-connection allocation accepted: %x %v", packet, err)
	}
}

// TestOutboundActivityExtendsIdle protects an idle allocated tunnel: its client
// sends keepalives without requiring the server to send application replies.
func TestOutboundActivityExtendsIdle(t *testing.T) {
	roots, cert, _ := credentials(t)
	h := &hub{}
	sr := h.endpoint("192.0.2.2:45001")
	cr := h.endpoint("192.0.2.1:45000")
	limits := Limits{IdleTimeout: 150 * time.Millisecond}
	server, err := Listen(sr, ServerConfig{Certificates: []tls.Certificate{cert}, Limits: limits})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	client, err := Dial(ctx, cr, sr.addr, ClientConfig{RootCAs: roots, ServerName: "server.test", Limits: limits})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ticker := time.NewTicker(30 * time.Millisecond)
	defer ticker.Stop()
	var peer pcapnet.Peer
	for i := 0; i < 10; i++ {
		select {
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		if err := client.SendTo(ctx, []byte("keepalive"), client.Peer()); err != nil {
			t.Fatal(err)
		}
		_, peer, err = server.ReceiveFrom(ctx)
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := server.SendTo(ctx, []byte("still-connected"), peer); err != nil {
		t.Fatal(err)
	}
	b, _, err := client.ReceiveFrom(ctx)
	if err != nil || string(b) != "still-connected" {
		t.Fatal(string(b), err)
	}
	// With no further application traffic the same idle timeout closes the client.
	if _, _, err := client.ReceiveFrom(ctx); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("idle connection did not expire: %v", err)
	}
}

func TestCloseInterruptsSend(t *testing.T) {
	_, client, h, _, raw := securePair(t)
	started := make(chan struct{}, 1)
	h.mu.Lock()
	raw.blockApplication = make(chan struct{})
	raw.sendStarted = started
	h.mu.Unlock()
	sent := make(chan error, 1)
	go func() { sent <- client.SendTo(context.Background(), []byte("blocked-until-close"), client.Peer()) }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("send did not reach the raw endpoint")
	}
	closed := make(chan error, 1)
	go func() { closed <- client.Close() }()
	select {
	case err := <-sent:
		if err == nil {
			t.Fatal("closed send unexpectedly succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not interrupt SendTo")
	}
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not join workers")
	}
}

type closeErrorEndpoint struct {
	*rawEndpoint
	closeError error
}

func (e *closeErrorEndpoint) Close() error { _ = e.rawEndpoint.Close(); return e.closeError }

func TestHandshakeFailurePreservesCleanupError(t *testing.T) {
	h := &hub{}
	cause := errors.New("raw endpoint cleanup failed")
	raw := &closeErrorEndpoint{h.endpoint("192.0.2.1:45000"), cause}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := Dial(ctx, raw, pcapnet.Peer{AddrPort: netip.MustParseAddrPort("192.0.2.2:45001")}, ClientConfig{ServerName: "server.test"})
	if !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, cause) {
		t.Fatalf("setup or cleanup error lost: %v", err)
	}
}

func TestInvalidCredentialsFailBeforeOwnershipTransfer(t *testing.T) {
	_, valid, other := credentials(t)
	malformed := valid
	malformed.Certificate = [][]byte{[]byte("invalid certificate")}
	mismatched := valid
	mismatched.PrivateKey = other.PrivateKey
	nilKey := valid
	var key *ecdsa.PrivateKey
	nilKey.PrivateKey = key
	for _, cert := range []tls.Certificate{malformed, mismatched, nilKey} {
		h := &hub{}
		raw := h.endpoint("192.0.2.2:45001")
		endpoint, err := Listen(raw, ServerConfig{Certificates: []tls.Certificate{cert}})
		if err == nil {
			endpoint.Close()
			t.Fatal("invalid server credentials accepted")
		}
		select {
		case <-raw.done:
			t.Fatal("invalid credentials consumed raw endpoint")
		default:
		}
		endpoint, err = Dial(context.Background(), raw, pcapnet.Peer{AddrPort: netip.MustParseAddrPort("192.0.2.1:45000")}, ClientConfig{ServerName: "server.test", Certificates: []tls.Certificate{cert}})
		if err == nil {
			endpoint.Close()
			t.Fatal("invalid client credentials accepted")
		}
		select {
		case <-raw.done:
			t.Fatal("invalid credentials consumed raw client endpoint")
		default:
		}
		raw.Close()
	}
}

func TestCloseReleasesBufferedPlaintext(t *testing.T) {
	server, client, _, _, _ := securePair(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := client.SendTo(ctx, []byte("identify"), client.Peer()); err != nil {
		t.Fatal(err)
	}
	_, peer, err := server.ReceiveFrom(ctx)
	if err != nil {
		t.Fatal(err)
	}
	server.incoming <- message{[]byte("buffered plaintext"), peer}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	server.mu.Lock()
	retained := len(server.incoming) + len(server.routes) + len(server.peers)
	server.mu.Unlock()
	if retained != 0 {
		t.Fatal("closed endpoint retained connection state or plaintext")
	}
}

type jumboEndpoint struct{ *rawEndpoint }

func (e *jumboEndpoint) MaxDatagramSize() int { return 9000 - 28 }

func TestJumboMTURespectsLibraryReceiveLimit(t *testing.T) {
	roots, cert, _ := credentials(t)
	h := &hub{}
	rawServer := &jumboEndpoint{h.endpoint("192.0.2.2:45001")}
	rawClient := &jumboEndpoint{h.endpoint("192.0.2.1:45000")}
	server, err := Listen(rawServer, ServerConfig{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	client, err := Dial(ctx, rawClient, rawServer.addr, ClientConfig{ServerName: "server.test", RootCAs: roots})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if client.MaxDatagramSize() != 8192-recordOverhead {
		t.Fatalf("unsafe jumbo capacity: %d", client.MaxDatagramSize())
	}
	payload := bytes.Repeat([]byte{0xab}, client.MaxDatagramSize())
	if err := client.SendTo(ctx, payload, client.Peer()); err != nil {
		t.Fatal(err)
	}
	got, _, err := server.ReceiveFrom(ctx)
	if err != nil || !bytes.Equal(payload, got) {
		t.Fatalf("jumbo record truncated: %d %v", len(got), err)
	}
	if err := client.SendTo(ctx, append(payload, 0), client.Peer()); !errors.Is(err, pcapnet.ErrDatagramTooLarge) {
		t.Fatal(err)
	}
}

func TestOldSecureMarkerRejected(t *testing.T) {
	datagram := frame(routeID{1}, make([]byte, 13))
	copy(datagram, "PCDS")
	if _, _, ok := unframe(datagram); ok {
		t.Fatal("obsolete secure-routing marker accepted")
	}
}

func TestRoutingHeaderSpecificationVector(t *testing.T) {
	want, err := hex.DecodeString("504344540100000001000000000000000000000000000000")
	if err != nil {
		t.Fatal(err)
	}
	got := frame(routeID{1}, make([]byte, 13))
	if !bytes.Equal(got[:muxHeaderSize], want) {
		t.Fatalf("routing header disagrees with specification: %x", got[:muxHeaderSize])
	}
}
