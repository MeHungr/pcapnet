package dtlstransport

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/MeHungr/pcapnet"
)

// TestCaptureMutualDTLS isolates clients sharing one source tuple across local
// server ports. Actual DTLS handshakes run over simulated all-port raw delivery.
// Core capture endpoint tests independently verify its Ethernet serialization.
func TestCaptureMutualDTLS(t *testing.T) {
	roots, serverCert, clientCert := credentials(t)
	h := &hub{}
	sr := h.endpoint("192.0.2.2:0")
	sr.capture = true
	server, err := Listen(sr, ServerConfig{Certificates: []tls.Certificate{serverCert}, ClientCAs: roots, RequireClientCertificate: true})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	for _, missing := range []bool{true, false} {
		certs := []tls.Certificate{}
		if !missing {
			_, _, other := credentials(t)
			certs = []tls.Certificate{other}
		}
		raw := h.endpoint("192.0.2.1:45000")
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		rejected, err := Dial(ctx, raw, pcapnet.Peer{AddrPort: netip.MustParseAddrPort("192.0.2.2:45001")}, ClientConfig{ServerName: "server.test", RootCAs: roots, Certificates: certs})
		cancel()
		if err == nil {
			rejected.Close()
			t.Fatal("unauthenticated client accepted")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ports := []uint16{45001, 55002}
	clients := make([]*Endpoint, len(ports))
	failures := make(chan error, len(ports))
	var workers sync.WaitGroup
	for i, port := range ports {
		raw := h.endpoint("192.0.2.1:45000") // Same physical client address for both.
		workers.Go(func() {
			client, err := Dial(ctx, raw, pcapnet.Peer{AddrPort: netip.AddrPortFrom(sr.addr.Addr(), port)}, ClientConfig{ServerName: "server.test", RootCAs: roots, Certificates: []tls.Certificate{clientCert}})
			clients[i] = client
			failures <- err
		})
	}
	workers.Wait()
	for _, client := range clients {
		if client != nil {
			defer client.Close()
		}
	}
	for range ports {
		if err := <-failures; err != nil {
			t.Fatal(err)
		}
	}
	// A rejected peer must not stop either valid connection. Header-only and
	// maximum-size application datagrams also preserve the contacted port.
	for _, client := range clients {
		for _, size := range []int{0, 1, client.MaxDatagramSize()} {
			body := bytes.Repeat([]byte{0x77}, size)
			if err := client.SendTo(ctx, body, client.Peer()); err != nil {
				t.Fatal(err)
			}
			received, peer, err := server.ReceiveFrom(ctx)
			if err != nil || !bytes.Equal(received, body) || peer.LocalAddrPort != client.Peer().AddrPort || peer.ConnectionID == ([16]byte{}) {
				t.Fatalf("capture receive: %+v %v", peer, err)
			}
			altered := peer
			if altered.LocalAddrPort.Port() == ports[0] {
				altered.LocalAddrPort = netip.AddrPortFrom(sr.addr.Addr(), ports[1])
			} else {
				altered.LocalAddrPort = netip.AddrPortFrom(sr.addr.Addr(), ports[0])
			}
			if err := server.SendTo(ctx, body, altered); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("modified handle accepted: %v", err)
			}
			if err := server.SendTo(ctx, received, peer); err != nil {
				t.Fatal(err)
			}
			reply, from, err := client.ReceiveFrom(ctx)
			if err != nil || !bytes.Equal(reply, body) || from != client.Peer() {
				t.Fatalf("capture reply from %+v: %v", from, err)
			}
		}
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-sr.done:
	default:
		t.Fatal("secure close leaked raw capture")
	}
}
