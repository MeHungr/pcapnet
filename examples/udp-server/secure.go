package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"time"

	"github.com/MeHungr/pcapnet"
	"github.com/MeHungr/pcapnet/dtlstransport"
	"github.com/MeHungr/pcapnet/examples/internal/certificates"
)

var (
	useDTLS           = flag.Bool("dtls", false, "encrypt datagrams with certificate-verified DTLS")
	certFile          = flag.String("cert", "", "server PEM certificate chain")
	keyFile           = flag.String("key", "", "server PEM private key")
	caFile            = flag.String("ca", "", "trusted client CA PEM bundle (empty uses system roots)")
	requireClientCert = flag.Bool("require-client-cert", false, "require mutual DTLS authentication")
)

// secureEcho dispatches authenticated datagrams from multiple peers. Replies
// retain the complete peer handle, including its opaque connection identity.
func secureEcho(ctx, setupCtx context.Context, cfg pcapnet.UDPConfig) (resultErr error) {
	certs, roots, err := certificates.Load(*certFile, *keyFile, *caFile)
	if err != nil {
		return err
	}
	if len(certs) == 0 {
		return fmt.Errorf("-dtls requires -cert and -key")
	}
	if *caFile != "" && !*requireClientCert {
		return fmt.Errorf("-ca requires -require-client-cert on the server")
	}
	conn, err := pcapnet.ListenUDP(setupCtx, cfg)
	if err != nil {
		return err
	}
	raw, _ := pcapnet.NewPlainUDPEndpoint(conn)
	secure, err := dtlstransport.Listen(raw, dtlstransport.ServerConfig{Certificates: certs, ClientCAs: roots, RequireClientCertificate: *requireClientCert})
	if err != nil {
		return errors.Join(err, raw.Close())
	}
	defer func() { resultErr = errors.Join(resultErr, secure.Close()) }()
	fmt.Printf("DTLS listening on %s (Ctrl+C to stop)\n", conn.LocalAddr())
	for {
		body, peer, err := secure.ReceiveFrom(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		sendCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		err = secure.SendTo(sendCtx, body, peer)
		cancel()
		if ctx.Err() != nil {
			return nil
		}
		// Peer expiry is isolated by the adapter; another client's echo can proceed.
		if err != nil {
			fmt.Printf("reply to %s failed: %v\n", peer.AddrPort, err)
			continue
		}
		fmt.Printf("DTLS echoed %d bytes to %s\n", len(body), peer.AddrPort)
	}
}
