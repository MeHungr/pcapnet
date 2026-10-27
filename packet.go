package pcapnet

import (
	"encoding/binary"
	"fmt"
	"net/netip"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const (
	// ethernetHeaderSize is the length of an Ethernet II header.
	ethernetHeaderSize = 14

	// ipv4MinimumHeaderSize is the smallest valid IPv4 header.
	ipv4MinimumHeaderSize = 20

	// udpHeaderSize is the length of a UDP header.
	udpHeaderSize = 8
)

// UDPPacket represents a validated IPv4/UDP packet extracted
// from an Ethernet frame.
type UDPPacket struct {
	SourceIP        netip.Addr // Source IPv4 address
	DestinationIP   netip.Addr // Destination IPv4 address
	SourcePort      uint16     // Source UDP port
	DestinationPort uint16     // Destination UDP port
	Payload         []byte     // Independent copy of the UDP payload
}

// ParseUDPPacket parses an Ethernet II frame containing IPv4/UDP.
//
// It rejects truncated packets, malformed lengths, invalid checksums,
// and fragmented IPv4 datagrams. Up to two 802.1Q/802.1ad VLAN tags are supported.
//
// UDP payloads are treated as opaque application data.
func ParseUDPPacket(frame []byte) (*UDPPacket, error) {
	// Ensure the frame contains an Ethernet header.
	if len(frame) < ethernetHeaderSize {
		return nil, fmt.Errorf("truncated Ethernet header")
	}

	// Decode the Ethernet header.
	var ethernet layers.Ethernet
	if err := ethernet.DecodeFromBytes(frame, gopacket.NilDecodeFeedback); err != nil {
		return nil, fmt.Errorf("decode Ethernet: %w", err)
	}

	// Get the encapsulated Ethernet payload and EtherType.
	payload := ethernet.Payload
	etherType := ethernet.EthernetType

	// Process up to two VLAN headers, supporting standard
	// 802.1Q tagging and 802.1ad double tagging (Q-in-Q).
	for i := 0; i < 2; i++ {
		// Stop when the next header is not a VLAN header.
		if etherType != layers.EthernetTypeDot1Q &&
			etherType != 0x88a8 {
			break
		}

		// Decode the VLAN header.
		var vlan layers.Dot1Q

		if err := vlan.DecodeFromBytes(
			payload,
			gopacket.NilDecodeFeedback,
		); err != nil {
			return nil, fmt.Errorf("decode VLAN header: %w", err)
		}

		// Advance to the encapsulated payload and EtherType.
		payload = vlan.Payload
		etherType = vlan.Type
	}

	// Require IPv4 after processing the supported VLAN tags.
	if etherType != layers.EthernetTypeIPv4 {
		return nil, fmt.Errorf("unsupported inner EtherType: %s", etherType)
	}

	// Extract the IPv4 packet after the optional VLAN headers.
	ipData := payload

	// Ensure the IPv4 minimum header is present.
	if len(ipData) < ipv4MinimumHeaderSize {
		return nil, fmt.Errorf("truncated IPv4 header")
	}

	// Validate the IPv4 version and header length.
	version := ipData[0] >> 4
	headerSize := int(ipData[0]&0x0f) * 4

	if version != 4 || headerSize < ipv4MinimumHeaderSize {
		return nil, fmt.Errorf("invalid IPv4 header")
	}

	// Ensure all IPv4 header bytes are available.
	if headerSize > len(ipData) {
		return nil, fmt.Errorf("truncated IPv4 header")
	}

	// Read and validate the IPv4 total length.
	ipLength := int(binary.BigEndian.Uint16(ipData[2:4]))

	if ipLength < headerSize+udpHeaderSize || ipLength > len(ipData) {
		return nil, fmt.Errorf("invalid IPv4 total length")
	}

	// Restrict processing to the IPv4 datagram's declared length.
	ipData = ipData[:ipLength]

	// Verify the IPv4 header checksum.
	if !validChecksum(ipData[:headerSize]) {
		return nil, fmt.Errorf("invalid IPv4 header checksum")
	}

	// Decode the IPv4 header using gopacket.
	var ipv4 layers.IPv4
	if err := ipv4.DecodeFromBytes(ipData, gopacket.NilDecodeFeedback); err != nil {
		return nil, fmt.Errorf("decode IPv4: %w", err)
	}

	// Reject fragmented datagrams because this parser does
	// not implement IP fragment reassembly.
	if ipv4.Flags&layers.IPv4MoreFragments != 0 ||
		ipv4.FragOffset != 0 {
		return nil, fmt.Errorf("fragmented IPv4 datagram")
	}

	// Require UDP as the transport protocol.
	if ipv4.Protocol != layers.IPProtocolUDP {
		return nil, fmt.Errorf("IPv4 packet does not contain UDP")
	}

	// Extract the complete UDP datagram.
	udpData := ipData[headerSize:]

	// Validate the UDP length field.
	udpLength := int(binary.BigEndian.Uint16(udpData[4:6]))
	if udpLength != len(udpData) || udpLength < udpHeaderSize {
		return nil, fmt.Errorf("invalid UDP length")
	}

	// Verify the UDP checksum when one is present.
	// IPv4 permits a zero UDP checksum.
	if binary.BigEndian.Uint16(udpData[6:8]) != 0 {
		if !validUDPChecksum(ipData[12:20], udpData) {
			return nil, fmt.Errorf("invalid UDP checksum")
		}
	}

	// Decode the UDP header using gopacket.
	var udp layers.UDP
	if err := udp.DecodeFromBytes(udpData, gopacket.NilDecodeFeedback); err != nil {
		return nil, fmt.Errorf("decode UDP: %w", err)
	}

	// Convert the IPv4 addresses into Go netip addresses.
	sourceIP := netip.AddrFrom4([4]byte(ipv4.SrcIP.To4()))
	destinationIP := netip.AddrFrom4([4]byte(ipv4.DstIP.To4()))

	// Return the validated packet with independently owned payload data.
	return &UDPPacket{
		SourceIP:        sourceIP,
		DestinationIP:   destinationIP,
		SourcePort:      uint16(udp.SrcPort),
		DestinationPort: uint16(udp.DstPort),
		Payload:         append([]byte(nil), udp.Payload...),
	}, nil
}

// validChecksum verifies a standard Internet checksum.
// A valid checksummed buffer produces an all-ones sum.
func validChecksum(data []byte) bool {
	return checksumSum(data) == 0xffff
}

// checksumSum calculates the folded one's-complement sum
// of the supplied bytes.
func checksumSum(data []byte) uint16 {
	var sum uint32

	// Add each 16-bit word to the accumulator.
	for len(data) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(data[:2]))
		data = data[2:]
	}

	// Pad a trailing odd byte with zero.
	if len(data) == 1 {
		sum += uint32(data[0]) << 8
	}

	// Fold carries back into the lower 16 bits.
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}

	return uint16(sum)
}

// validUDPChecksum verifies a UDP checksum using the IPv4
// pseudo-header and the complete UDP datagram.
func validUDPChecksum(addresses []byte, udpData []byte) bool {
	// Require the source and destination IPv4 addresses.
	if len(addresses) != 8 {
		return false
	}

	// Build the IPv4 UDP pseudo-header.
	var pseudoHeader [12]byte

	copy(pseudoHeader[:8], addresses)
	pseudoHeader[9] = byte(layers.IPProtocolUDP)
	binary.BigEndian.PutUint16(pseudoHeader[10:12], uint16(len(udpData)))

	// Combine the pseudo-header and UDP datagram sums.
	sum := uint32(checksumSum(pseudoHeader[:])) +
		uint32(checksumSum(udpData))

	// Fold the final carry.
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}

	return uint16(sum) == 0xffff
}
