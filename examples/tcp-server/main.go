// Command tcp-server serves concurrent TCP echo connections over a UDP tunnel.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/MeHungr/pcapnet"
	"github.com/MeHungr/pcapnet/dtlstransport"
	"github.com/MeHungr/pcapnet/examples/internal/certificates"
)

var (
	useDTLS           = flag.Bool("dtls", false, "encrypt and authenticate the tunnel with DTLS")
	certFile          = flag.String("cert", "", "server certificate PEM file (required with -dtls)")
	keyFile           = flag.String("key", "", "server private key PEM file (required with -dtls)")
	caFile            = flag.String("ca", "", "trusted client CA PEM file")
	requireClientCert = flag.Bool("require-client-cert", false, "require a trusted DTLS client certificate")
	localAddress      = flag.String("local-ip", "", "server physical IPv4 listening address")
	localPort         = flag.Uint("local-port", 45001, "local outer UDP port")
	virtualAddress    = flag.String("virtual-ip", "10.200.0.2", "local virtual IPv4 address")
	addressPool       = flag.String("subnet", "10.200.0.0/24", "virtual address allocation subnet")
	maxPeers          = flag.Int("max-peers", 64, "maximum active sessions")
	tcpPort           = flag.Uint("tcp-port", 6767, "virtual TCP listening port")
	deviceName        = flag.String("device", "", "capture device (empty selects automatically)")
	reservePort       = flag.Bool("reserve-port", false, "reserve the outer port with a host UDP socket")
)

func main() {
	flag.Parse()
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() (resultErr error) {
	localIP, err := netip.ParseAddr(*virtualAddress)
	if err != nil {
		return fmt.Errorf("invalid -virtual-ip: %w", err)
	}
	physicalIP, err := netip.ParseAddr(*localAddress)
	if err != nil {
		return fmt.Errorf("invalid -local-ip: %w", err)
	}
	if *localPort == 0 || *localPort > 65535 || *tcpPort == 0 || *tcpPort > 65535 {
		return fmt.Errorf("ports must be between 1 and 65535")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	setupCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	pool, err := netip.ParsePrefix(*addressPool)
	if err != nil {
		return fmt.Errorf("invalid -subnet: %w", err)
	}
	udpCfg := pcapnet.UDPConfig{DeviceName: *deviceName, LocalIP: physicalIP, LocalPort: uint16(*localPort), ReserveUDPPort: *reservePort}
	serverCfg := pcapnet.ServerConfig{VirtualIP: localIP, AddressPool: pool, MTU: 1200, MaxPeers: *maxPeers}
	var listener *pcapnet.TCPServer
	if *useDTLS {
		certs, roots, loadErr := certificates.Load(*certFile, *keyFile, *caFile)
		if loadErr != nil {
			return loadErr
		}
		if len(certs) == 0 {
			return fmt.Errorf("-dtls requires -cert and -key")
		}
		if *caFile != "" && !*requireClientCert {
			return fmt.Errorf("-ca requires -require-client-cert on the server")
		}
		udp, openErr := pcapnet.ListenUDP(setupCtx, udpCfg)
		if openErr != nil {
			return openErr
		}
		raw, _ := pcapnet.NewPlainUDPEndpoint(udp)
		secure, secureErr := dtlstransport.Listen(raw, dtlstransport.ServerConfig{Certificates: certs, ClientCAs: roots, RequireClientCertificate: *requireClientCert, Limits: dtlstransport.Limits{MaxPeers: *maxPeers}})
		if secureErr != nil {
			return errors.Join(secureErr, raw.Close())
		}
		listener, err = pcapnet.NewTCPServer(secure, serverCfg, int(*tcpPort))
		if err != nil {
			return errors.Join(err, secure.Close())
		}
	} else {
		if *certFile != "" || *keyFile != "" || *caFile != "" || *requireClientCert {
			return fmt.Errorf("certificate flags require -dtls")
		}
		listener, err = pcapnet.ListenPCAPTCP(setupCtx, udpCfg, serverCfg, int(*tcpPort))
	}
	if err != nil {
		return err
	}
	var workers sync.WaitGroup
	defer func() { resultErr = errors.Join(resultErr, listener.Close()); workers.Wait() }()
	stopClose := context.AfterFunc(ctx, func() { _ = listener.Close() })
	defer stopClose()
	fmt.Printf("TCP listening on %s over UDP port %d (Ctrl+C to stop)\n", listener.Addr(), *localPort)
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		workers.Add(1)
		go func() { defer workers.Done(); echo(ctx, conn) }()
	}
}

// echo closes only its connection; the shared server retains its sessions.
func echo(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		if ctx.Err() == nil {
			log.Print(err)
		}
		return
	}
	if _, err := io.Copy(conn, conn); err != nil && ctx.Err() == nil {
		log.Print(err)
	}
}
