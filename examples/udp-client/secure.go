package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"time"

	"github.com/MeHungr/pcapnet"
	"github.com/MeHungr/pcapnet/dtlstransport"
	"github.com/MeHungr/pcapnet/examples/internal/certificates"
)

var (
	useDTLS    = flag.Bool("dtls", false, "encrypt datagrams with certificate-verified DTLS")
	certFile   = flag.String("cert", "", "client PEM certificate chain for mutual DTLS")
	keyFile    = flag.String("key", "", "client PEM private key for mutual DTLS")
	caFile     = flag.String("ca", "", "trusted server CA PEM bundle (empty uses system roots)")
	serverName = flag.String("server-name", "", "server certificate name (default peer IP)")
)

// secureEcho uses the datagram adapter directly: no virtual stack or allocation
// protocol is involved. The authenticated peer handle addresses the connection.
func secureEcho(ctx context.Context, cfg pcapnet.UDPConfig, peer netip.AddrPort) (resultErr error) {
	certs, roots, err := certificates.Load(*certFile, *keyFile, *caFile)
	if err != nil {
		return err
	}
	name := *serverName
	if name == "" {
		name = peer.Addr().String()
	}
	conn, err := pcapnet.DialUDP(ctx, cfg, peer)
	if err != nil {
		return err
	}
	raw, _ := pcapnet.NewPlainUDPEndpoint(conn)
	secure, err := dtlstransport.Dial(ctx, raw, pcapnet.Peer{AddrPort: peer}, dtlstransport.ClientConfig{ServerName: name, RootCAs: roots, Certificates: certs})
	if err != nil {
		return errors.Join(err, raw.Close())
	}
	defer func() { resultErr = errors.Join(resultErr, secure.Close()) }()
	ioCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := secure.SendTo(ioCtx, []byte(*message), secure.Peer()); err != nil {
		return err
	}
	reply, sender, err := secure.ReceiveFrom(ioCtx)
	if err != nil {
		return err
	}
	fmt.Printf("DTLS reply from %s: %q\n", sender.AddrPort, reply)
	return nil
}
