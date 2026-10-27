package dtlstransport

import (
	"bytes"
	"context"
	"crypto/tls"
	"testing"
	"time"
)

// TestStandaloneDatagramEcho verifies DTLS and mDTLS for arbitrary application
// datagrams, without allocation messages, virtual addresses, or a TCP stack.
func TestStandaloneDatagramEcho(t *testing.T) {
	for _, mutual := range []bool{false, true} {
		name := "DTLS"
		if mutual {
			name = "mDTLS"
		}
		t.Run(name, func(t *testing.T) {
			roots, serverCert, clientCert := credentials(t)
			h := &hub{}
			sr, cr := h.endpoint("192.0.2.2:45001"), h.endpoint("192.0.2.1:45000")
			server, err := Listen(sr, ServerConfig{Certificates: []tls.Certificate{serverCert}, ClientCAs: roots, RequireClientCertificate: mutual})
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			cfg := ClientConfig{ServerName: "server.test", RootCAs: roots}
			if mutual {
				cfg.Certificates = []tls.Certificate{clientCert}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			client, err := Dial(ctx, cr, sr.addr, cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			for _, size := range []int{0, 1, client.MaxDatagramSize()} {
				body := bytes.Repeat([]byte{0xa5}, size)
				if err := client.SendTo(ctx, body, client.Peer()); err != nil {
					t.Fatal(err)
				}
				received, peer, err := server.ReceiveFrom(ctx)
				if err != nil || !bytes.Equal(received, body) {
					t.Fatalf("receive %d: %x, %v", size, received, err)
				}
				if peer.ConnectionID == ([16]byte{}) {
					t.Fatal("missing authenticated peer handle")
				}
				if err := server.SendTo(ctx, received, peer); err != nil {
					t.Fatal(err)
				}
				reply, from, err := client.ReceiveFrom(ctx)
				if err != nil || !bytes.Equal(reply, body) || from != client.Peer() {
					t.Fatalf("echo %d: %x, %v", size, reply, err)
				}
			}
		})
	}
}
