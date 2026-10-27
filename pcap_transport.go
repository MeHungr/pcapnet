package pcapnet

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// PCAPTransport carries complete inner IPv4 packets over a fixed IPv4/UDP peer.
// Construct it with NewPCAPTransport; its zero value is closed. The transport
// owns its capture handle and optional UDP socket reservation until Close.
// It provides encapsulation and tuple filtering, without peer authentication.
type PCAPTransport struct {
	resources *pcapResources // Physical endpoint acquired during setup
	done      chan struct{}  // Closed before waiting for active packet operations
	sendGate  chan struct{}  // Serializes sends while permitting cancellation
	recvGate  chan struct{}  // Serializes receives independently of sends
	once      sync.Once      // Runs transport shutdown exactly once
	closeErr  error          // Stable resource cleanup result
}

// NewPCAPTransport prepares capture, injection, and an optional UDP reservation.
// ctx controls setup only; the caller owns the resulting transport until Close
// or a successful transfer of ownership to a virtual stack.
//
// Requires an Ethernet capture device and platform capture/injection privileges.
// The configured MTU must fit the selected interface after IPv4/UDP overhead.
func NewPCAPTransport(ctx context.Context, cfg PCAPConfig) (*PCAPTransport, error) {
	return newPCAPTransport(ctx, cfg, livePCAPSetupOps())
}

// newPCAPTransport permits deterministic setup tests without opening live PCAP.
func newPCAPTransport(ctx context.Context, cfg PCAPConfig, ops pcapSetupOps) (*PCAPTransport, error) {
	resources, err := preparePCAP(ctx, cfg, ops)
	if err != nil {
		return nil, err
	}
	p := &PCAPTransport{
		resources: resources,
		done:      make(chan struct{}),
		sendGate:  make(chan struct{}, 1),
		recvGate:  make(chan struct{}, 1),
	}
	p.sendGate <- struct{}{}
	p.recvGate <- struct{}{}
	return p, nil
}

// operationErr rejects canceled operations and closed or uninitialized transports.
func (p *PCAPTransport) operationErr(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("packet context cannot be nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if p == nil || p.resources == nil {
		return ErrClosed
	}
	select {
	case <-p.done:
		return ErrClosed
	default:
		return nil
	}
}

// acquire waits for a direction's packet operation slot without ignoring either
// caller cancellation or shutdown. A successful acquisition must be released.
func (p *PCAPTransport) acquire(ctx context.Context, gate chan struct{}) error {
	if err := p.operationErr(ctx); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-p.done:
		return ErrClosed
	case <-gate:
		// Cancellation may have raced with acquiring the available slot.
		if err := p.operationErr(ctx); err != nil {
			gate <- struct{}{}
			return err
		}
		return nil
	}
}

// Send encapsulates one complete IPv4 packet and injects the Ethernet frame.
// The caller may reuse packet after Send returns. Sends are serialized, while
// capture can proceed concurrently. Cancellation is checked before injection;
// an injection already executing in the native driver cannot be interrupted.
func (p *PCAPTransport) Send(ctx context.Context, packet []byte) error {
	if err := p.operationErr(ctx); err != nil {
		return err
	}
	if err := p.acquire(ctx, p.sendGate); err != nil {
		return err
	}
	defer func() { p.sendGate <- struct{}{} }()

	if err := validateInnerIPv4(packet, p.resources.config.MTU); err != nil {
		return fmt.Errorf("invalid outbound inner packet: %w", err)
	}
	frame, err := p.serializePacket(packet)
	if err != nil {
		return err
	}
	if err := p.operationErr(ctx); err != nil {
		return err
	}
	if err := p.resources.handle.WritePacketData(frame); err != nil {
		return fmt.Errorf("inject tunnel frame: %w", err)
	}
	return nil
}

// serializePacket builds Ethernet/IPv4/UDP around an unchanged inner packet.
// Outer fragmentation is disabled; the interface MTU was checked during setup.
func (p *PCAPTransport) serializePacket(packet []byte) ([]byte, error) {
	r := p.resources
	ethernet := &layers.Ethernet{
		SrcMAC: r.srcMAC, DstMAC: r.dstMAC, EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version: 4, IHL: 5, TTL: 64, Flags: layers.IPv4DontFragment,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    r.local.Addr().AsSlice(), DstIP: r.config.Peer.Addr().AsSlice(),
	}
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(r.local.Port()), DstPort: layers.UDPPort(r.config.Peer.Port()),
	}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		return nil, fmt.Errorf("configure tunnel UDP checksum: %w", err)
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf,
		gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		ethernet, ip, udp, gopacket.Payload(packet)); err != nil {
		return nil, fmt.Errorf("serialize tunnel frame: %w", err)
	}

	// gopacket leaves a computed zero checksum as zero. UDP represents that
	// checksum as 0xffff on the wire; zero means checksumming was disabled.
	frame := buf.Bytes()
	checksumOffset := ethernetHeaderSize + outerIPv4HeaderSize + 6
	if binary.BigEndian.Uint16(frame[checksumOffset:checksumOffset+2]) == 0 {
		binary.BigEndian.PutUint16(frame[checksumOffset:checksumOffset+2], 0xffff)
	}
	return frame, nil
}

// Receive returns one independently owned inner IPv4 packet. Truncated,
// malformed, fragmented outer, unrelated, and oversized packets are dropped.
// Receive retries capture timeouts and checks cancellation between driver calls.
func (p *PCAPTransport) Receive(ctx context.Context) ([]byte, error) {
	if err := p.operationErr(ctx); err != nil {
		return nil, err
	}
	if err := p.acquire(ctx, p.recvGate); err != nil {
		return nil, err
	}
	defer func() { p.recvGate <- struct{}{} }()

	for {
		if err := p.operationErr(ctx); err != nil {
			return nil, err
		}
		data, info, err := p.resources.handle.ReadPacketData()
		// Prefer cancellation or closure if either happened during capture.
		if stateErr := p.operationErr(ctx); stateErr != nil {
			return nil, stateErr
		}
		if errors.Is(err, pcap.NextErrorTimeoutExpired) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("capture tunnel frame: %w", err)
		}
		if info.CaptureLength < info.Length || info.CaptureLength != len(data) {
			continue
		}
		packet, err := ParseUDPPacket(data)
		if err != nil {
			continue
		}
		r := p.resources
		if packet.SourceIP != r.config.Peer.Addr() || packet.SourcePort != r.config.Peer.Port() ||
			packet.DestinationIP != r.local.Addr() || packet.DestinationPort != r.local.Port() {
			continue
		}
		if err := validateInnerIPv4(packet.Payload, r.config.MTU); err != nil {
			continue
		}
		return packet.Payload, nil
	}
}

// validateInnerIPv4 verifies packet boundaries before encapsulation or delivery.
// Inner protocol checksums and reassembly remain the receiving IP stack's job.
func validateInnerIPv4(packet []byte, mtu uint32) error {
	if len(packet) < ipv4MinimumHeaderSize || uint64(len(packet)) > uint64(mtu) {
		return fmt.Errorf("inner packet size must be between %d and %d", ipv4MinimumHeaderSize, mtu)
	}
	headerSize := int(packet[0]&0x0f) * 4
	if packet[0]>>4 != 4 || headerSize < ipv4MinimumHeaderSize || headerSize > len(packet) {
		return fmt.Errorf("invalid inner IPv4 header")
	}
	if int(binary.BigEndian.Uint16(packet[2:4])) != len(packet) {
		return fmt.Errorf("inner IPv4 total length does not match packet size")
	}
	return nil
}

// Close signals shutdown, waits for active native I/O to finish, then releases
// the capture handle and port. Queued operations wake immediately. Active
// receives observe shutdown after the current bounded capture read completes.
// A stalled native driver can delay Close; no handle is freed while in use.
// Close is safe to call repeatedly and concurrently, including on a zero value.
func (p *PCAPTransport) Close() error {
	if p == nil {
		return nil
	}
	p.once.Do(func() {
		if p.resources == nil {
			return
		}
		close(p.done)
		<-p.sendGate
		<-p.recvGate
		p.closeErr = p.resources.Close()
	})
	return p.closeErr
}

// Verify that the live tunnel satisfies the stack's packet transport contract.
var _ PacketTransport = (*PCAPTransport)(nil)
