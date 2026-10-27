package pcapnet

import (
	"bytes"
	"encoding/binary"
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// makeTestUDPFrame creates a valid Ethernet/IPv4/UDP frame
// containing the supplied application payload.
func makeTestUDPFrame(t *testing.T, payload []byte) []byte {
	t.Helper()

	// Configure the Ethernet header.
	ethernet := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0, 1, 2, 3, 4, 5},
		DstMAC:       net.HardwareAddr{6, 7, 8, 9, 10, 11},
		EthernetType: layers.EthernetTypeIPv4,
	}

	// Configure the IPv4 header.
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    net.ParseIP("192.0.2.1").To4(),
		DstIP:    net.ParseIP("192.0.2.2").To4(),
	}

	// Configure the UDP header.
	udp := &layers.UDP{
		SrcPort: 40000,
		DstPort: 6767,
	}

	// Configure the UDP checksum pseudo-header.
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}

	// Allocate a serialization buffer.
	buf := gopacket.NewSerializeBuffer()

	// Serialize the Ethernet, IPv4, UDP, and payload layers.
	err := gopacket.SerializeLayers(
		buf,
		gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		},
		ethernet,
		ip,
		udp,
		gopacket.Payload(payload),
	)
	if err != nil {
		t.Fatal(err)
	}

	// Return a copy of the serialized frame.
	return append([]byte(nil), buf.Bytes()...)
}

// TestParseUDPPacket verifies that a valid packet is
// decoded with the expected addresses, ports, and payload.
func TestParseUDPPacket(t *testing.T) {
	// Generate a valid UDP frame.
	message := []byte("pcapnet test")
	frame := makeTestUDPFrame(t, message)

	// Parse the generated Ethernet frame.
	packet, err := ParseUDPPacket(frame)
	if err != nil {
		t.Fatal(err)
	}

	// Verify the source IPv4 address.
	if packet.SourceIP != netip.MustParseAddr("192.0.2.1") {
		t.Errorf("unexpected source IP: %s", packet.SourceIP)
	}

	// Verify the destination IPv4 address.
	if packet.DestinationIP != netip.MustParseAddr("192.0.2.2") {
		t.Errorf("unexpected destination IP: %s", packet.DestinationIP)
	}

	// Verify the UDP port numbers.
	if packet.SourcePort != 40000 || packet.DestinationPort != 6767 {
		t.Errorf(
			"unexpected UDP ports: %d -> %d",
			packet.SourcePort,
			packet.DestinationPort,
		)
	}

	// Verify the application payload.
	if !bytes.Equal(packet.Payload, message) {
		t.Errorf("payload = %q, want %q", packet.Payload, message)
	}
}

// TestParseUDPPacketMalformed verifies that malformed
// packets are rejected before their payloads are accepted.
func TestParseUDPPacketMalformed(t *testing.T) {
	// Create a valid frame as the test baseline.
	valid := makeTestUDPFrame(t, []byte("hello"))

	// Define the malformed packet scenarios.
	tests := []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{
			name: "empty frame",
			mutate: func(_ []byte) []byte {
				return nil
			},
		},
		{
			name: "truncated Ethernet",
			mutate: func(frame []byte) []byte {
				return frame[:10]
			},
		},
		{
			name: "unsupported EtherType",
			mutate: func(frame []byte) []byte {
				binary.BigEndian.PutUint16(frame[12:14], 0x86dd)
				return frame
			},
		},
		{
			name: "truncated IPv4",
			mutate: func(frame []byte) []byte {
				return frame[:ethernetHeaderSize+10]
			},
		},
		{
			name: "invalid IPv4 checksum",
			mutate: func(frame []byte) []byte {
				frame[ethernetHeaderSize+8] ^= 0x01
				return frame
			},
		},
		{
			name: "invalid UDP checksum",
			mutate: func(frame []byte) []byte {
				// Locate the beginning of the IPv4 datagram.
				ipOffset := ethernetHeaderSize

				// Read the IPv4 header length and total datagram length.
				ipHeaderSize := int(frame[ipOffset]&0x0f) * 4
				ipLength := int(binary.BigEndian.Uint16(frame[ipOffset+2 : ipOffset+4]))

				// Locate the final byte of the actual UDP payload.
				payloadEnd := ipOffset + ipLength

				// Corrupt the UDP payload without updating its checksum.
				if ipLength <= ipHeaderSize+udpHeaderSize {
					panic("test packet has no UDP payload")
				}
				frame[payloadEnd-1] ^= 0x01

				return frame
			},
		},
		{
			name: "truncated UDP payload",
			mutate: func(frame []byte) []byte {
				// Locate the beginning of the IPv4 datagram.
				ipOffset := ethernetHeaderSize

				// Read the IPv4 total length.
				ipLength := int(binary.BigEndian.Uint16(
					frame[ipOffset+2 : ipOffset+4],
				))

				// Truncate the frame inside the declared IPv4 datagram,
				// rather than removing Ethernet padding.
				return frame[:ipOffset+ipLength-1]
			},
		},
		{
			name: "invalid UDP length",
			mutate: func(frame []byte) []byte {
				udpOffset := ethernetHeaderSize + ipv4MinimumHeaderSize
				binary.BigEndian.PutUint16(frame[udpOffset+4:], 7)
				return frame
			},
		},
	}

	// Execute each malformed packet scenario.
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Copy the valid frame before modifying it.
			frame := append([]byte(nil), valid...)
			frame = tt.mutate(frame)

			// Attempt to parse the malformed packet.
			packet, err := ParseUDPPacket(frame)

			// Ensure that validation rejects the packet.
			if err == nil {
				t.Fatalf("expected error, got packet %+v", packet)
			}
		})
	}
}

// TestParseUDPPacketPayloadOwnership verifies that the
// returned payload does not reference the original frame.
func TestParseUDPPacketPayloadOwnership(t *testing.T) {
	// Generate and parse a valid frame.
	frame := makeTestUDPFrame(t, []byte("original"))

	packet, err := ParseUDPPacket(frame)
	if err != nil {
		t.Fatal(err)
	}

	// Overwrite the original frame after parsing.
	for i := range frame {
		frame[i] = 0
	}

	// Verify that the decoded payload remains unchanged.
	if string(packet.Payload) != "original" {
		t.Fatalf("payload was modified: %q", packet.Payload)
	}
}

// TestParseUDPPacketNonUDP verifies that packets containing
// other transport protocols are rejected.
func TestParseUDPPacketNonUDP(t *testing.T) {
	// Generate a valid UDP packet.
	frame := makeTestUDPFrame(t, []byte("hello"))

	// Change the IPv4 protocol number to TCP.
	ipOffset := ethernetHeaderSize
	frame[ipOffset+9] = byte(layers.IPProtocolTCP)

	// Recalculate the IPv4 checksum.
	recalculateTestIPv4Checksum(frame)

	// Verify that the parser rejects the protocol.
	_, err := ParseUDPPacket(frame)
	if err == nil || !strings.Contains(err.Error(), "does not contain UDP") {
		t.Fatalf("expected unsupported protocol error, got %v", err)
	}
}

// TestParseUDPPacketFragment verifies that an IPv4 fragment
// is rejected rather than treated as a complete UDP packet.
func TestParseUDPPacketFragment(t *testing.T) {
	// Generate a valid UDP packet.
	frame := makeTestUDPFrame(t, []byte("hello"))

	// Set the IPv4 More Fragments flag.
	ipOffset := ethernetHeaderSize
	frame[ipOffset+6] = 0x20

	// Recalculate the IPv4 checksum.
	recalculateTestIPv4Checksum(frame)

	// Verify that fragment validation rejects the packet.
	_, err := ParseUDPPacket(frame)
	if err == nil || !strings.Contains(err.Error(), "fragmented") {
		t.Fatalf("expected fragmentation error, got %v", err)
	}
}

// TestParseUDPPacketPadding verifies that Ethernet padding
// is not interpreted as part of the UDP payload.
func TestParseUDPPacketPadding(t *testing.T) {
	// Create a valid Ethernet frame containing a short UDP payload.
	frame := makeTestUDPFrame(t, []byte("hello"))

	// Locate the end of the declared IPv4 datagram.
	ipOffset := ethernetHeaderSize
	ipLength := int(binary.BigEndian.Uint16(
		frame[ipOffset+2 : ipOffset+4],
	))

	// Verify that the frame contains Ethernet padding.
	if len(frame) <= ipOffset+ipLength {
		t.Fatal("expected Ethernet padding")
	}

	// Modify the padding without changing the IPv4 datagram.
	frame[len(frame)-1] ^= 0xff

	// Parse the Ethernet frame.
	packet, err := ParseUDPPacket(frame)
	if err != nil {
		t.Fatalf("expected valid packet: %v", err)
	}

	// Verify that the UDP payload excludes Ethernet padding.
	if string(packet.Payload) != "hello" {
		t.Fatalf("unexpected payload: %q", packet.Payload)
	}
}

// recalculateTestIPv4Checksum updates the IPv4 checksum
// after a test intentionally modifies an IPv4 header field.
func recalculateTestIPv4Checksum(frame []byte) {
	// Locate the IPv4 header.
	ip := frame[ethernetHeaderSize:]
	headerSize := int(ip[0]&0x0f) * 4
	header := ip[:headerSize]

	// Clear the existing checksum.
	header[10] = 0
	header[11] = 0

	// Calculate and store the replacement checksum.
	checksum := ^checksumSum(header)
	binary.BigEndian.PutUint16(header[10:12], checksum)
}
