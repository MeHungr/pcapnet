// Command udp-server echoes datagrams until interrupted.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"time"

	"github.com/MeHungr/pcapnet"
)

var (
	localAddress = flag.String("local", "", "host IPv4 address and UDP port to listen on")
	deviceName   = flag.String("device", "", "capture device (empty selects automatically)")
	reservePort  = flag.Bool("reserve-port", false, "reserve the local port with a host UDP socket")
)

func main() {
	flag.Parse()
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() (resultErr error) {
	local, err := netip.ParseAddrPort(*localAddress)
	if err != nil {
		return fmt.Errorf("invalid -local: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	setupCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cfg := pcapnet.UDPConfig{
		DeviceName:     *deviceName,
		LocalIP:        local.Addr(),
		LocalPort:      local.Port(),
		ReserveUDPPort: *reservePort,
	}
	listener, err := pcapnet.ListenUDP(setupCtx, cfg)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, listener.Close()) }()
	// The setup context does not close the endpoint; interrupt does.
	stopClose := context.AfterFunc(ctx, func() { _ = listener.Close() })
	defer stopClose()

	fmt.Printf("listening on %s (Ctrl+C to stop)\n", listener.LocalAddr())
	buffer := make([]byte, 65535)
	for {
		n, sender, err := listener.ReadFrom(buffer)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		if err := listener.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		if _, err := listener.WriteTo(buffer[:n], sender); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		fmt.Printf("echoed %d bytes to %s\n", n, sender)
	}
}
