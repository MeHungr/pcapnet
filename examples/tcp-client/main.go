// Command tcp-client exchanges one message through a TCP-over-UDP tunnel.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/netip"
	"time"

	"github.com/MeHungr/pcapnet"
	"github.com/MeHungr/pcapnet/dtlstransport"
	"github.com/MeHungr/pcapnet/examples/internal/certificates"
)

var (
	useDTLS     = flag.Bool("dtls", false, "encrypt and authenticate the tunnel with DTLS")
	caFile      = flag.String("ca", "", "trusted server CA PEM file (empty uses system roots)")
	certFile    = flag.String("cert", "", "optional client certificate PEM file")
	keyFile     = flag.String("key", "", "optional client private key PEM file")
	serverName  = flag.String("server-name", "", "verified DTLS server name (defaults to peer IP)")
	peerAddress = flag.String("peer", "", "server physical IPv4 address and outer UDP port")
	localPort   = flag.Uint("local-port", 45000, "local outer UDP port")
	tcpPort     = flag.Uint("tcp-port", 6767, "server virtual TCP port")
	deviceName  = flag.String("device", "", "capture device (empty selects automatically)")
	reservePort = flag.Bool("reserve-port", false, "reserve the outer port with a host UDP socket")
	message     = flag.String("message", "hello", "nonempty message to echo")
)

func main() {
	flag.Parse()
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() (resultErr error) {
	peer, err := netip.ParseAddrPort(*peerAddress)
	if err != nil {
		return fmt.Errorf("invalid -peer: %w", err)
	}
	if *localPort == 0 || *localPort > 65535 || *tcpPort == 0 || *tcpPort > 65535 {
		return fmt.Errorf("ports must be between 1 and 65535")
	}
	if *message == "" {
		return fmt.Errorf("-message must not be empty")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cfg := pcapnet.UDPConfig{DeviceName: *deviceName, LocalPort: uint16(*localPort), ReserveUDPPort: *reservePort}
	var v *pcapnet.VirtualStack
	var assigned pcapnet.Assignment
	if *useDTLS {
		certs, roots, loadErr := certificates.Load(*certFile, *keyFile, *caFile)
		if loadErr != nil {
			return loadErr
		}
		name := *serverName
		if name == "" {
			name = peer.Addr().String()
		}
		udp, openErr := pcapnet.DialUDP(ctx, cfg, peer)
		if openErr != nil {
			return openErr
		}
		raw, _ := pcapnet.NewPlainUDPEndpoint(udp)
		secure, secureErr := dtlstransport.Dial(ctx, raw, pcapnet.Peer{AddrPort: peer}, dtlstransport.ClientConfig{ServerName: name, RootCAs: roots, Certificates: certs})
		if secureErr != nil {
			return errors.Join(secureErr, raw.Close())
		}
		v, assigned, err = pcapnet.DialStack(ctx, secure, secure.Peer(), 1200)
	} else {
		if *caFile != "" || *certFile != "" || *keyFile != "" || *serverName != "" {
			return fmt.Errorf("certificate flags require -dtls")
		}
		v, assigned, err = pcapnet.DialPCAPStack(ctx, cfg, peer, 1200)
	}
	if err != nil {
		return err
	}
	defer func() { v.Close(); resultErr = errors.Join(resultErr, v.Err()) }()

	conn, err := v.Dial(ctx, assigned.ServerIP.String(), int(*tcpPort))
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, conn.Close()) }()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
	if _, err := io.WriteString(conn, *message); err != nil {
		return err
	}
	reply := make([]byte, len(*message))
	if _, err := io.ReadFull(conn, reply); err != nil {
		return err
	}
	fmt.Printf("TCP echo: %q\n", reply)
	return nil
}
