package pcapnet

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// makeEthernetFrame takes values to create an ethernet frame and returns a layers.Ethernet
func makeEthernetFrame(srcMAC, dstMAC net.HardwareAddr, etherType layers.EthernetType) *layers.Ethernet {
	return &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: etherType,
	}
}

// makeARPPacket takes values to create an arp packet and returns a layers.ARP
func makeARPPacket(
	addrType layers.LinkType,
	proto layers.EthernetType,
	macSize, protoAddrSize uint8,
	operation uint16,
	sourceMAC, sourceProtoAddr, dstMAC, dstProtoAddr []byte,
) *layers.ARP {
	return &layers.ARP{
		AddrType:          addrType,
		Protocol:          proto,
		HwAddressSize:     macSize,
		ProtAddressSize:   protoAddrSize,
		Operation:         operation,
		SourceHwAddress:   sourceMAC,
		SourceProtAddress: sourceProtoAddr,
		DstHwAddress:      dstMAC,
		DstProtAddress:    dstProtoAddr,
	}
}

// resolveARP resolves a next-hop IPv4 address to its MAC address
func resolveARP(ctx context.Context, device *pcap.Interface, srcMAC net.HardwareAddr, srcIP, nextHop net.IP) (net.HardwareAddr, error) {
	// Reject invalid setup before acquiring a capture handle.
	if ctx == nil {
		return nil, fmt.Errorf("ARP context cannot be nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if device == nil || device.Name == "" {
		return nil, fmt.Errorf("ARP capture device is required")
	}

	src4 := srcIP.To4()   // Source IP in IPv4
	dst4 := nextHop.To4() // Next-hop IP in IPv4

	// Ensure addresses are IPv4 and exist
	if src4 == nil || dst4 == nil {
		return nil, fmt.Errorf("ARP requires IPv4 addresses")
	}

	// Ensure MAC address is 6 bytes long
	if len(srcMAC) != 6 {
		return nil, fmt.Errorf("expected 6-byte source MAC")
	}

	// Open a pcap device handle
	handle, err := pcap.OpenLive(
		device.Name,
		65535,
		false,
		500*time.Millisecond,
	)
	if err != nil {
		return nil, fmt.Errorf("opening pcap: %w", err)
	}
	// ARP uses a temporary handle independent of the tunnel's handle.
	// Release it on success and on every subsequent error path.
	defer handle.Close()

	// Ensure link layer is ethernet
	if handle.LinkType() != layers.LinkTypeEthernet {
		return nil, fmt.Errorf("interface is not Ethernet")
	}

	// Only capture ARP packets
	if err := handle.SetBPFFilter("arp"); err != nil {
		return nil, fmt.Errorf("set filter: %w", err)
	}

	// Broadcast MAC address
	broadcastMAC := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

	// Generate an Ethernet frame
	eth := makeEthernetFrame(
		srcMAC,
		broadcastMAC,
		layers.EthernetTypeARP,
	)

	// Generate an ARP packet
	arp := makeARPPacket(
		layers.LinkTypeEthernet,
		layers.EthernetTypeIPv4,
		6,
		4,
		layers.ARPRequest,
		[]byte(srcMAC),
		[]byte(src4),
		make([]byte, 6),
		[]byte(dst4),
	)

	// Create a buffer to serialize the structs to raw bytes
	buf := gopacket.NewSerializeBuffer()

	// Serialize the layers from the structs into the buffer
	if err := gopacket.SerializeLayers(
		buf,
		gopacket.SerializeOptions{FixLengths: true},
		eth,
		arp,
	); err != nil {
		return nil, fmt.Errorf("serialize ARP: %w", err)
	}

	// Write the data to the pcap handle (send the packet)
	if err := handle.WritePacketData(buf.Bytes()); err != nil {
		return nil, fmt.Errorf("send ARP: %w", err)
	}

	// Wait for the corresponding reply, and timeout if nothing happens
	return pollARPReply(ctx, handle, srcMAC, src4, dst4)
}

func pollARPReply(ctx context.Context, handle *pcap.Handle, srcMAC net.HardwareAddr, src4, dst4 net.IP) (net.HardwareAddr, error) {
	for {
		// Check for context error
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		// Read the next ARP packet received
		data, _, err := handle.ReadPacketData()
		if err != nil {
			// If no packets were captured, continue capturing packets
			if err == pcap.NextErrorTimeoutExpired {
				continue
			}
			return nil, fmt.Errorf("read ARP: %w", err)
		}

		// Deserialize raw bytes into packet object
		packet := gopacket.NewPacket(
			data,
			layers.LayerTypeEthernet,
			gopacket.Default,
		)

		// If packet doesn't contain ARP, continue
		layer := packet.Layer(layers.LayerTypeARP)
		if layer == nil {
			continue
		}

		// Type assertion saying that layer is *layers.ARP, so we can treat it as such, stored in reply variable
		reply := layer.(*layers.ARP)

		// If packet is not an ARP reply, continue
		if reply.Operation != layers.ARPReply {
			continue
		}

		// If the source IP doesn't match the ARP request destination IP, continue
		if !net.IP(reply.SourceProtAddress).Equal(dst4) {
			continue
		}

		// If the destination IP doesn't match the ARP request source IP, continue
		if !net.IP(reply.DstProtAddress).Equal(src4) {
			continue
		}

		// If the source MAC isn't 6 bytes long, continue
		if len(reply.SourceHwAddress) != 6 {
			continue
		}

		// If the destination MAC address is not our MAC address, continue
		if !equalMAC(reply.DstHwAddress, srcMAC) {
			continue
		}

		return append(net.HardwareAddr(nil), reply.SourceHwAddress...), nil
	}
}

// equalMAC determines whether 2 MAC addresses are equal
func equalMAC(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
