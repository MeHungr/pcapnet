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
)

var (
	peerAddress        = flag.String("peer", "", "client physical IPv4 address and outer UDP port")
	localPort          = flag.Uint("local-port", 45001, "local outer UDP port")
	virtualAddress     = flag.String("virtual-ip", "10.200.0.2", "local virtual IPv4 address")
	peerVirtualAddress = flag.String("peer-virtual-ip", "10.200.0.1", "client virtual IPv4 address")
	tcpPort            = flag.Uint("tcp-port", 6767, "virtual TCP listening port")
	deviceName         = flag.String("device", "", "capture device (empty selects automatically)")
	reservePort        = flag.Bool("reserve-port", false, "reserve the outer port with a host UDP socket")
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
	localIP, err := netip.ParseAddr(*virtualAddress)
	if err != nil {
		return fmt.Errorf("invalid -virtual-ip: %w", err)
	}
	peerIP, err := netip.ParseAddr(*peerVirtualAddress)
	if err != nil {
		return fmt.Errorf("invalid -peer-virtual-ip: %w", err)
	}
	if *localPort == 0 || *localPort > 65535 || *tcpPort == 0 || *tcpPort > 65535 {
		return fmt.Errorf("ports must be between 1 and 65535")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	setupCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cfg := pcapnet.PCAPConfig{DeviceName: *deviceName, LocalPort: uint16(*localPort), Peer: peer, MTU: 1200, ReserveUDPPort: *reservePort}
	virtualCfg := pcapnet.Config{VirtualIP: localIP, PeerVirtualIP: peerIP, MTU: cfg.MTU}
	transport, err := pcapnet.NewPCAPTransport(setupCtx, cfg)
	if err != nil {
		return err
	}
	v, err := pcapnet.NewVirtualStackWithTransport(virtualCfg, transport)
	if err != nil {
		return errors.Join(err, transport.Close())
	}
	var workers sync.WaitGroup
	defer func() {
		v.Close() // Wake Accept and all connection I/O before joining handlers.
		workers.Wait()
		resultErr = errors.Join(resultErr, v.Err())
	}()
	stopClose := context.AfterFunc(ctx, v.Close)
	defer stopClose()
	listener, err := v.Listen(int(*tcpPort))
	if err != nil {
		return err
	}
	defer listener.Close()
	fmt.Printf("TCP listening on %s over UDP port %d (Ctrl+C to stop)\n", listener.Addr(), cfg.LocalPort)
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

// echo closes only its connection. The owning stack remains alive for queued
// replies, TCP teardown, and subsequent connections until the server stops.
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
