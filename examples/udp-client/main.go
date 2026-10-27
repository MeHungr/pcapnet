// Command udp-client sends one datagram and prints its echo.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/netip"
	"time"

	"github.com/MeHungr/pcapnet"
)

var (
	peerAddress = flag.String("peer", "", "server IPv4 address and UDP port")
	localPort   = flag.Uint("local-port", 45000, "local UDP source port")
	deviceName  = flag.String("device", "", "capture device (empty selects automatically)")
	reservePort = flag.Bool("reserve-port", false, "reserve the local port with a host UDP socket")
	magicHeader = flag.String("magic", "", "optional payload prefix; must match the other endpoint")
	message     = flag.String("message", "hello", "datagram payload")
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
	if *localPort == 0 || *localPort > 65535 {
		return fmt.Errorf("-local-port must be between 1 and 65535")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cfg := pcapnet.UDPConfig{
		DeviceName:     *deviceName,
		LocalPort:      uint16(*localPort),
		ReserveUDPPort: *reservePort,
		MagicHeader:    []byte(*magicHeader),
	}
	if *useDTLS {
		return secureEcho(ctx, cfg, peer)
	}
	if *certFile != "" || *keyFile != "" || *caFile != "" || *serverName != "" {
		return fmt.Errorf("certificate flags require -dtls")
	}
	conn, err := pcapnet.DialUDP(ctx, cfg, peer)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, conn.Close()) }()

	// Setup context and application I/O deadlines have separate lifetimes.
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
	if _, err := conn.Write([]byte(*message)); err != nil {
		return err
	}
	buffer := make([]byte, 65535)
	n, err := conn.Read(buffer)
	if err != nil {
		return err
	}
	fmt.Printf("reply from %s: %q\n", conn.RemoteAddr(), buffer[:n])
	return nil
}
