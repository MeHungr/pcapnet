package dtlstransport

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/MeHungr/pcapnet"
)

func TestPeerAuthenticationSnapshots(t *testing.T) {
	for _, mutual := range []bool{false, true} {
		name := "server-only"
		if mutual {
			name = "mutual"
		}
		t.Run(name, func(t *testing.T) {
			roots, sc, cc := credentials(t)
			h := &hub{}
			sr, cr := h.endpoint("192.0.2.2:45001"), h.endpoint("192.0.2.1:45000")
			server, err := Listen(sr, ServerConfig{Certificates: []tls.Certificate{cc, sc}, ClientCAs: roots, RequireClientCertificate: mutual})
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			// Configuring a client certificate does not mean it was requested or used.
			client, err := Dial(ctx, cr, sr.addr, ClientConfig{ServerName: "server.test", RootCAs: roots, Certificates: []tls.Certificate{cc}})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			if err := client.SendTo(ctx, []byte("hello"), client.Peer()); err != nil {
				t.Fatal(err)
			}
			_, peer, err := server.ReceiveFrom(ctx)
			if err != nil {
				t.Fatal(err)
			}
			si, err := server.PeerInfo(peer)
			if err != nil {
				t.Fatal(err)
			}
			ci, err := client.PeerInfo(client.Peer())
			if err != nil {
				t.Fatal(err)
			}
			if !si.Encrypted || si.PeerCertificateAuthenticated != mutual || si.ClientCertificateAuthenticated != mutual || (len(si.VerifiedChains) > 0) != mutual {
				t.Fatalf("server authentication: %+v", si)
			}
			if !ci.PeerCertificateAuthenticated || ci.ClientCertificateAuthenticated != mutual || (len(ci.LocalCertificates) > 0) != mutual {
				t.Fatalf("client authentication: %+v", ci)
			}
			if len(si.LocalCertificates) == 0 || !bytes.Equal(si.LocalCertificates[0].Raw, sc.Certificate[0]) {
				t.Fatal("wrong actual server certificate")
			}
			if mutual && !bytes.Equal(si.Certificates[0].Raw, cc.Certificate[0]) {
				t.Fatal("wrong client certificate")
			}
			ci.Certificates[0].Raw[0] ^= 1
			ci.VerifiedChains[0][0].Subject.CommonName = "mutated"
			again, err := client.PeerInfo(client.Peer())
			if err != nil || !bytes.Equal(again.Certificates[0].Raw, sc.Certificate[0]) || again.VerifiedChains[0][0].Subject.CommonName == "mutated" {
				t.Fatal("snapshot mutation affected retained evidence")
			}
			done, err := server.PeerDone(peer)
			if err != nil {
				t.Fatal(err)
			}
			if err := server.DisconnectPeer(ctx, peer); err != nil {
				t.Fatal(err)
			}
			select {
			case <-done:
			default:
				t.Fatal("peer did not invalidate")
			}
			select {
			case <-si.Done:
			default:
				t.Fatal("retained metadata did not become historical")
			}
			if _, err := server.PeerInfo(peer); !errors.Is(err, pcapnet.ErrPeerNotFound) {
				t.Fatal(err)
			}
			if err := server.DisconnectPeer(ctx, peer); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// TestPeerRevocationTCP exercises exact handles over shared physical tuples,
// multiple TCP connections per peer, autonomous disconnect propagation, and a
// stale handle presented after a replacement connection has been established.
func TestPeerRevocationTCP(t *testing.T) {
	roots, sc, cc := credentials(t)
	h := &hub{}
	sr := h.endpoint("192.0.2.2:45001")
	secure, err := Listen(sr, ServerConfig{Certificates: []tls.Certificate{sc}, ClientCAs: roots, RequireClientCertificate: true})
	if err != nil {
		t.Fatal(err)
	}
	server, err := pcapnet.NewTCPServer(secure, pcapnet.ServerConfig{VirtualIP: netip.MustParseAddr("10.200.0.1"), AddressPool: netip.MustParsePrefix("10.200.0.0/29")}, 6767)
	if err != nil {
		secure.Close()
		t.Fatal(err)
	}
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { server.Close() })
	defer stop()
	type clientStack struct {
		secure *Endpoint
		v      *pcapnet.VirtualStack
		a      pcapnet.Assignment
	}
	open := func() clientStack {
		raw := h.endpoint("192.0.2.1:45000")
		e, err := Dial(ctx, raw, sr.addr, ClientConfig{ServerName: "server.test", RootCAs: roots, Certificates: []tls.Certificate{cc}})
		if err != nil {
			t.Fatal(err)
		}
		v, a, err := pcapnet.DialStack(ctx, e, e.Peer(), 1200)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(v.Close)
		return clientStack{e, v, a}
	}
	connect := func(c clientStack) (net.Conn, net.Conn, pcapnet.Peer) {
		out, err := c.v.Dial(ctx, c.a.ServerIP.String(), 6767)
		if err != nil {
			t.Fatal(err)
		}
		accepted, peer, err := server.AcceptWithPeer()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { out.Close(); accepted.Close() })
		return out, accepted, peer
	}
	a, b := open(), open()
	_, a1, pa := connect(a)
	_, a2, pa2 := connect(a)
	bout, bin, pb := connect(b)
	if pa != pa2 || pa == pb || pa.ConnectionID == ([16]byte{}) || pa.AddrPort != pb.AddrPort {
		t.Fatal("incorrect accepted peer association")
	}
	for _, conn := range []net.Conn{a1, a2} {
		if conn.(pcapnet.PeerConnection).Peer() != pa {
			t.Fatal("missing immutable connection binding")
		}
	}
	retired, err := server.PeerDone(pa)
	if err != nil {
		t.Fatal(err)
	}
	reads := make(chan error, 3)
	writeStarted := make(chan struct{})
	go func() {
		close(writeStarted)
		_, err := a1.Write(make([]byte, 16<<20))
		reads <- err
	}()
	<-writeStarted
	for _, conn := range []net.Conn{a1, a2} {
		go func() { _, err := conn.Read(make([]byte, 1)); reads <- err }()
	}
	if err := server.DisconnectPeer(ctx, pa); err != nil {
		t.Fatal(err)
	}
	select {
	case <-retired:
	default:
		t.Fatal("allocation not invalidated")
	}
	for range 3 {
		select {
		case err := <-reads:
			if err == nil {
				t.Fatal("revoked read succeeded")
			}
		case <-ctx.Done():
			t.Fatal("revoked read blocked")
		}
	}
	if _, err := server.PeerInfo(pa); !errors.Is(err, pcapnet.ErrPeerNotFound) {
		t.Fatal(err)
	}
	// A different connection on the same physical tuple remains usable.
	if _, err := bout.Write([]byte("B")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(bin, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	replacement := open()
	rout, rin, pr := connect(replacement)
	if pr == pa {
		t.Fatal("replacement reused authenticated handle")
	}
	if err := server.DisconnectPeer(ctx, pa); err != nil {
		t.Fatal(err)
	}
	if _, err := rout.Write([]byte("R")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(rin, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	// Direct DTLS retirement must propagate into TCP without a lease-timeout poll.
	ended, err := server.PeerDone(pb)
	if err != nil {
		t.Fatal(err)
	}
	if err := secure.DisconnectPeer(ctx, pb); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ended:
	case <-ctx.Done():
		t.Fatal("DTLS retirement did not propagate")
	}
	result := make(chan error, 1)
	go func() { _, err := bin.Read(make([]byte, 1)); result <- err }()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("retired TCP read succeeded")
		}
	case <-ctx.Done():
		t.Fatal("retired TCP read blocked")
	}
}

// TestPeerIdleExpiryPropagates verifies automatic DTLS expiry closes blocked
// inner TCP reads well before the default two-minute PCAT allocation timeout.
func TestPeerIdleExpiryPropagates(t *testing.T) {
	roots, sc, cc := credentials(t)
	h := &hub{}
	sr := h.endpoint("192.0.2.2:45001")
	secure, err := Listen(sr, ServerConfig{Certificates: []tls.Certificate{sc}, ClientCAs: roots, RequireClientCertificate: true, Limits: Limits{IdleTimeout: 150 * time.Millisecond}, Authorize: func(_ context.Context, info PeerInfo) error {
		// Callback-owned certificates must not be the retained evidence objects.
		info.Certificates[0].Raw[0] ^= 1
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	server, err := pcapnet.NewTCPServer(secure, pcapnet.ServerConfig{VirtualIP: netip.MustParseAddr("10.200.0.1"), AddressPool: netip.MustParsePrefix("10.200.0.0/30")}, 6767)
	if err != nil {
		secure.Close()
		t.Fatal(err)
	}
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	raw := h.endpoint("192.0.2.1:45000")
	client, err := Dial(ctx, raw, sr.addr, ClientConfig{ServerName: "server.test", RootCAs: roots, Certificates: []tls.Certificate{cc}})
	if err != nil {
		t.Fatal(err)
	}
	v, a, err := pcapnet.DialStack(ctx, client, client.Peer(), 1200)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	out, err := v.Dial(ctx, a.ServerIP.String(), 6767)
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	conn, peer, err := server.AcceptWithPeer()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	info, err := secure.PeerInfo(peer)
	if err != nil || !bytes.Equal(info.Certificates[0].Raw, cc.Certificate[0]) {
		t.Fatal("authorization callback mutated retained evidence")
	}
	done, err := server.PeerDone(peer)
	if err != nil {
		t.Fatal(err)
	}
	results := make(chan error, 2)
	go func() { _, err := conn.Read(make([]byte, 1)); results <- err }()
	go func() { _, err := out.Read(make([]byte, 1)); results <- err }()
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("idle expiry waited for PCAT lease")
	}
	for range 2 {
		select {
		case err := <-results:
			if err == nil {
				t.Fatal("expired connection read succeeded")
			}
		case <-ctx.Done():
			t.Fatal("expiry did not wake blocked read")
		}
	}
}

// TestRetiredQueuedDatagramCannotReachReplacement retains old decrypted data
// while a new DTLS connection reuses the same UDP tuple. Exact IDs, not physical
// addresses, determine whether buffered data or authentication evidence is live.
func TestRetiredQueuedDatagramCannotReachReplacement(t *testing.T) {
	roots, sc, cc := credentials(t)
	h := &hub{}
	sr := h.endpoint("192.0.2.2:45001")
	server, err := Listen(sr, ServerConfig{Certificates: []tls.Certificate{sc}, ClientCAs: roots, RequireClientCertificate: true})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	open := func() *Endpoint {
		client, err := Dial(ctx, h.endpoint("192.0.2.1:45000"), sr.addr, ClientConfig{ServerName: "server.test", RootCAs: roots, Certificates: []tls.Certificate{cc}})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { client.Close() })
		return client
	}
	first := open()
	if err := first.SendTo(ctx, []byte("old queued plaintext"), first.Peer()); err != nil {
		t.Fatal(err)
	}
	for len(server.incoming) == 0 {
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(time.Millisecond):
		}
	}
	server.mu.Lock()
	var old pcapnet.Peer
	for peer := range server.peers {
		old = peer
	}
	server.mu.Unlock()
	if err := server.DisconnectPeer(ctx, old); err != nil {
		t.Fatal(err)
	}
	next := open()
	if err := next.SendTo(ctx, []byte("new plaintext"), next.Peer()); err != nil {
		t.Fatal(err)
	}
	body, peer, err := server.ReceiveFrom(ctx)
	if err != nil || string(body) != "new plaintext" || peer == old || peer.AddrPort != old.AddrPort {
		t.Fatalf("retired data reached replacement: %q %+v %v", body, peer, err)
	}
	if _, err := server.PeerInfo(old); !errors.Is(err, pcapnet.ErrPeerNotFound) {
		t.Fatalf("stale lookup identified replacement: %v", err)
	}
	if err := server.DisconnectPeer(ctx, old); err != nil {
		t.Fatal(err)
	}
	if err := server.SendTo(ctx, body, peer); err != nil {
		t.Fatal(err)
	}
	if reply, _, err := next.ReceiveFrom(ctx); err != nil || string(reply) != "new plaintext" {
		t.Fatalf("replacement affected: %q %v", reply, err)
	}
}
