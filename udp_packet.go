package pcapnet

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// ErrDatagramTooLarge indicates a payload that would require IP fragmentation.
// The endpoint remains usable after rejecting an oversized application write.
var ErrDatagramTooLarge = errors.New("pcapnet: UDP datagram exceeds MTU")

// resolveMAC resolves a route's gateway or a directly connected peer. Cache
// entries expire after 30 seconds and are bounded to avoid unbounded growth.
// The caller holds sendGate, except during unpublished constructor setup.
func (c *UDPConn) resolveMAC(ctx context.Context, device *pcap.Interface, peer netip.Addr, gateway net.IP) (net.HardwareAddr, error) {
	next := peer
	if gateway != nil && !gateway.IsUnspecified() {
		var ok bool
		next, ok = netip.AddrFromSlice(gateway.To4())
		if !ok || !validUDPHost(next) {
			return nil, fmt.Errorf("route gateway is not a usable IPv4 address")
		}
	}
	if entry, ok := c.macs[next]; ok && time.Now().Before(entry.expires) {
		return entry.address, nil
	}
	arpCtx, cancel := context.WithTimeout(ctx, arpTimeout)
	defer cancel()
	mac, err := c.ops.resolveARP(arpCtx, device, c.resources.srcMAC, c.config.LocalIP.AsSlice(), next.AsSlice())
	if err != nil {
		return nil, fmt.Errorf("resolve UDP next hop: %w", err)
	}
	if len(mac) != 6 || mac[0]&1 != 0 || mac.String() == "00:00:00:00:00:00" {
		return nil, fmt.Errorf("next-hop MAC must be unicast Ethernet")
	}
	mac = append(net.HardwareAddr(nil), mac...)
	if len(c.macs) >= 64 {
		clear(c.macs)
	}
	c.macs[next] = udpMAC{address: mac, expires: time.Now().Add(30 * time.Second)}
	return mac, nil
}

// udpFrame serializes a direct Ethernet/IPv4/UDP datagram with no inner packet.
func udpFrame(local, remote netip.AddrPort, src, dst net.HardwareAddr, payload []byte) ([]byte, error) {
	ethernet := &layers.Ethernet{SrcMAC: src, DstMAC: dst, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Flags: layers.IPv4DontFragment, Protocol: layers.IPProtocolUDP, SrcIP: local.Addr().AsSlice(), DstIP: remote.Addr().AsSlice()}
	udp := &layers.UDP{SrcPort: layers.UDPPort(local.Port()), DstPort: layers.UDPPort(remote.Port())}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		return nil, err
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ethernet, ip, udp, gopacket.Payload(payload)); err != nil {
		return nil, err
	}
	frame := buf.Bytes()
	checksum := ethernetHeaderSize + outerIPv4HeaderSize + 6
	if binary.BigEndian.Uint16(frame[checksum:checksum+2]) == 0 {
		binary.BigEndian.PutUint16(frame[checksum:checksum+2], 0xffff)
	}
	return frame, nil
}

// writeTo resolves listener destinations on the owning interface and injects
// one whole datagram. Application and route errors do not close the endpoint;
// native injection failures do, because the capture/injection link is unusable.
func (c *UDPConn) writeTo(payload []byte, peer netip.AddrPort) (int, error) {
	return c.writeToContext(context.Background(), payload, peer)
}

// writeToContext combines a tunnel operation lifetime with UDP shutdown and deadlines.
func (c *UDPConn) writeToContext(parent context.Context, payload []byte, peer netip.AddrPort) (int, error) {
	ctx, finish, err := c.operation(true)
	if err != nil {
		return 0, c.opError("write", err)
	}
	defer finish()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(parent, cancel)
	defer stop()
	if parent.Err() != nil {
		return 0, parent.Err()
	}
	if !validUDPHost(peer.Addr()) || peer.Port() == 0 {
		return 0, c.opError("write", fmt.Errorf("destination must be a unicast IPv4 endpoint"))
	}
	if len(payload) > c.MaxDatagramSize() {
		return 0, c.opError("write", ErrDatagramTooLarge)
	}
	select {
	case <-ctx.Done():
		return 0, c.opError("write", udpContextError(ctx))
	case <-c.sendGate:
	}
	defer func() { c.sendGate <- struct{}{} }()
	if ctx.Err() != nil {
		return 0, c.opError("write", udpContextError(ctx))
	}
	mac := c.resources.dstMAC
	if !c.peer.IsValid() {
		iface, gateway, source, err := c.ops.lookupRoute(peer.Addr().AsSlice())
		if err != nil {
			return 0, c.opError("write", fmt.Errorf("lookup UDP destination route: %w", err))
		}
		if iface == nil || iface.MTU < 28 || !source.Equal(net.IP(c.config.LocalIP.AsSlice())) || !bytes.Equal(iface.HardwareAddr, c.resources.srcMAC) {
			return 0, c.opError("write", fmt.Errorf("destination route does not match local UDP endpoint"))
		}
		if len(payload) > iface.MTU-28-len(c.config.MagicHeader) {
			return 0, c.opError("write", ErrDatagramTooLarge)
		}
		mac, err = c.resolveMAC(ctx, &pcap.Interface{Name: c.config.DeviceName}, peer.Addr(), gateway)
		if err != nil {
			if ctx.Err() != nil {
				err = udpContextError(ctx)
			}
			return 0, c.opError("write", err)
		}
	}
	// Build framing in a fresh buffer so even a caller's spare slice capacity
	// remains untouched. Counts and MTU limits refer to the application body.
	wirePayload := payload
	if len(c.config.MagicHeader) != 0 {
		wirePayload = make([]byte, len(c.config.MagicHeader)+len(payload))
		copy(wirePayload, c.config.MagicHeader)
		copy(wirePayload[len(c.config.MagicHeader):], payload)
	}
	frame, err := udpFrame(c.resources.local, peer, c.resources.srcMAC, mac, wirePayload)
	if err != nil {
		return 0, c.opError("write", err)
	}
	if ctx.Err() != nil {
		return 0, c.opError("write", udpContextError(ctx))
	}
	if err := c.resources.handle.WritePacketData(frame); err != nil {
		if ctx.Err() != nil {
			return 0, c.opError("write", udpContextError(ctx))
		}
		c.failed(fmt.Errorf("inject UDP: %w", err))
		return 0, c.opError("write", err)
	}
	return len(payload), nil
}
