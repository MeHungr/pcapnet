package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
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

// secureEcho authenticates clients before delivering application data. The raw
// capture endpoint retains each contacted port throughout handshake and replies.
func secureEcho(ctx, setupCtx context.Context, cfg pcapnet.UDPCaptureConfig) (resultErr error) {
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
	capture, err := pcapnet.ListenUDPCapture(setupCtx, cfg)
	if err != nil {
		return err
	}
	raw, _ := pcapnet.NewPlainUDPCaptureEndpoint(capture)
	secure, err := dtlstransport.Listen(raw, dtlstransport.ServerConfig{Certificates: certs, ClientCAs: roots, RequireClientCertificate: *requireClientCert})
	if err != nil {
		return errors.Join(err, raw.Close())
	}
	defer func() { resultErr = errors.Join(resultErr, secure.Close()) }()
	fmt.Printf("DTLS listening on %s, all UDP ports, magic %x (Ctrl+C to stop)\n", cfg.LocalIP, cfg.MagicHeader)
	for {
		body, peer, err := secure.ReceiveFrom(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		// The complete authenticated handle selects both the DTLS connection and
		// the local UDP source port. Never reconstruct it from the remote address.
		replyCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		err = secure.SendTo(replyCtx, body, peer)
		cancel()
		if ctx.Err() != nil {
			return nil
		}
		if err != nil {
			log.Printf("DTLS reply to %s: %v", peer.AddrPort, err)
			continue
		}
		fmt.Printf("DTLS echoed %d bytes from %s to %s\n", len(body), peer.LocalAddrPort, peer.AddrPort)
	}
}
