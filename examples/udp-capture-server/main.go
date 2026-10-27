// Command udp-capture-server echoes magic-prefixed UDP datagrams on all ports.
package main

import (
	"context"
	"encoding/hex"
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

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() (resultErr error) {
	local := flag.String("local-ip", "", "local interface IPv4 address")
	device := flag.String("device", "", "capture device (empty selects automatically)")
	magic := flag.String("magic", "MYPROTO", "literal UDP payload prefix")
	magicHex := flag.String("magic-hex", "", "hexadecimal prefix, overriding -magic")
	flag.Parse()
	header := []byte(*magic)
	if *magicHex != "" {
		var err error
		header, err = hex.DecodeString(*magicHex)
		if err != nil {
			return fmt.Errorf("invalid -magic-hex: %w", err)
		}
	}
	ip, err := netip.ParseAddr(*local)
	if err != nil {
		return fmt.Errorf("invalid -local-ip: %w", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	setupCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cfg := pcapnet.UDPCaptureConfig{LocalIP: ip, DeviceName: *device, MagicHeader: header}
	if *useDTLS {
		return secureEcho(ctx, setupCtx, cfg)
	}
	if *certFile != "" || *keyFile != "" || *caFile != "" || *requireClientCert {
		return fmt.Errorf("certificate flags require -dtls")
	}
	server, err := pcapnet.ListenUDPCapture(setupCtx, cfg)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, server.Close()) }()
	fmt.Printf("listening on %s, all UDP ports, magic %x (Ctrl+C to stop)\n", ip, header)
	for {
		request, err := server.Receive(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		// Receive strips the header. Reply adds it once and swaps the captured
		// source/destination tuple, so a dialed UDP client accepts the response.
		replyCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		err = server.Reply(replyCtx, request, request.Payload)
		cancel()
		if ctx.Err() != nil {
			return nil
		}
		if err != nil {
			if server.Err() != nil {
				return err
			}
			log.Printf("reply: %v", err)
			continue
		}
		source := netip.AddrPortFrom(request.SourceIP, request.SourcePort)
		destination := netip.AddrPortFrom(request.DestinationIP, request.DestinationPort)
		fmt.Printf("echoed %d bytes from %s to %s\n", len(request.Payload), destination, source)
	}
}
