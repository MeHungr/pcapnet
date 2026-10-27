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
)

var (
	peerAddress        = flag.String("peer", "", "server physical IPv4 address and outer UDP port")
	localPort          = flag.Uint("local-port", 45000, "local outer UDP port")
	virtualAddress     = flag.String("virtual-ip", "10.200.0.1", "local virtual IPv4 address")
	peerVirtualAddress = flag.String("peer-virtual-ip", "10.200.0.2", "server virtual IPv4 address")
	tcpPort            = flag.Uint("tcp-port", 6767, "server virtual TCP port")
	deviceName         = flag.String("device", "", "capture device (empty selects automatically)")
	reservePort        = flag.Bool("reserve-port", false, "reserve the outer port with a host UDP socket")
	message            = flag.String("message", "hello", "nonempty message to echo")
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
	if *message == "" {
		return fmt.Errorf("-message must not be empty")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cfg := pcapnet.PCAPConfig{DeviceName: *deviceName, LocalPort: uint16(*localPort), Peer: peer, MTU: 1200, ReserveUDPPort: *reservePort}
	virtualCfg := pcapnet.Config{VirtualIP: localIP, PeerVirtualIP: peerIP, MTU: cfg.MTU}
	transport, err := pcapnet.NewPCAPTransport(ctx, cfg)
	if err != nil {
		return err
	}
	v, err := pcapnet.NewVirtualStackWithTransport(virtualCfg, transport)
	if err != nil {
		return errors.Join(err, transport.Close())
	}
	defer func() { v.Close(); resultErr = errors.Join(resultErr, v.Err()) }()

	conn, err := v.Dial(ctx, peerIP.String(), int(*tcpPort))
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
