// Command udp-capture observes UDP payloads with a configurable magic prefix.
package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net/netip"
	"os"
	"os/signal"

	"github.com/MeHungr/pcapnet"
)

func main() {
	local := flag.String("local-ip", "", "local interface IPv4 address")
	device := flag.String("device", "", "capture device (empty selects automatically)")
	magic := flag.String("magic", "PCAT", "literal UDP payload prefix")
	magicHex := flag.String("magic-hex", "", "hexadecimal prefix, overriding -magic")
	flag.Parse()
	header := []byte(*magic)
	if *magicHex != "" {
		var err error
		header, err = hex.DecodeString(*magicHex)
		if err != nil {
			log.Fatal(err)
		}
	}
	ip, err := netip.ParseAddr(*local)
	if err != nil {
		log.Fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	cfg := pcapnet.UDPCaptureConfig{LocalIP: ip, DeviceName: *device, MagicHeader: header}
	capture, err := pcapnet.CaptureUDP(ctx, cfg)
	if err != nil {
		log.Fatal(err)
	}
	if err := receive(ctx, capture); err != nil {
		log.Fatal(err)
	}
}

func receive(ctx context.Context, capture *pcapnet.UDPCapture) error {
	defer capture.Close()
	for {
		packet, err := capture.Receive(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		source := netip.AddrPortFrom(packet.SourceIP, packet.SourcePort)
		destination := netip.AddrPortFrom(packet.DestinationIP, packet.DestinationPort)
		fmt.Printf("%s -> %s: %x\n", source, destination, packet.Payload)
	}
}
