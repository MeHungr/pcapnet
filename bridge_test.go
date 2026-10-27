package pcapnet

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// countedTransport records ownership-related Close calls while delegating I/O.
type countedTransport struct {
	PacketTransport
	closes atomic.Int32
}

func (c *countedTransport) Close() error {
	c.closes.Add(1)
	return c.PacketTransport.Close()
}

// TestNewVirtualStackWithTransportOwnership verifies failed construction keeps
// a usable caller-owned transport and successful construction closes it once.
func TestNewVirtualStackWithTransportOwnership(t *testing.T) {
	local, peer := NewMemoryPair(4)
	defer peer.Close()
	transport := &countedTransport{PacketTransport: local}
	if v, err := NewVirtualStackWithTransport(Config{}, transport); err == nil || v != nil {
		t.Fatal("invalid configuration accepted")
	}
	if transport.closes.Load() != 0 {
		t.Fatal("failed constructor closed caller-owned transport")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := transport.Send(ctx, []byte("still owned")); err != nil {
		t.Fatal(err)
	}
	if data, err := peer.Receive(ctx); err != nil || string(data) != "still owned" {
		t.Fatalf("transport unusable after failure: %q, %v", data, err)
	}
	v, err := NewVirtualStackWithTransport(newTestConfig(), transport)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	if v.bridge == nil {
		t.Fatal("stack has no packet bridge")
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); v.Close() }()
	}
	wg.Wait()
	if transport.closes.Load() != 1 {
		t.Fatalf("transport closed %d times", transport.closes.Load())
	}
	if _, err := peer.Receive(ctx); !errors.Is(err, ErrClosed) {
		t.Fatalf("stack did not close its owned memory transport: %v", err)
	}
}

// TestNewVirtualStackWithTransportValidation rejects nil transports, mismatched
// PCAP MTUs, and closed PCAP instances before taking transport ownership.
func TestNewVirtualStackWithTransportValidation(t *testing.T) {
	var memory *MemoryTransport
	var capture *PCAPTransport
	for _, transport := range []PacketTransport{nil, memory, capture} {
		if v, err := NewVirtualStackWithTransport(newTestConfig(), transport); err == nil || v != nil {
			t.Fatalf("nil transport %T accepted", transport)
		}
	}
	f := newSetupFixture(t)
	p, err := newPCAPTransport(context.Background(), f.cfg, f.ops)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	cfg := newTestConfig()
	cfg.MTU = 1400
	if v, err := NewVirtualStackWithTransport(cfg, p); err == nil || v != nil {
		t.Fatal("mismatched PCAP and stack MTUs accepted")
	}
	if f.capture.closes != 0 || f.port.closes != 0 {
		t.Fatal("MTU rejection closed caller resources")
	}
	if err := p.Send(context.Background(), testInnerIPv4(t, 24)); err != nil {
		t.Fatalf("MTU rejection invalidated transport: %v", err)
	}
	_ = p.Close()
	if v, err := NewVirtualStackWithTransport(newTestConfig(), p); !errors.Is(err, ErrClosed) || v != nil {
		t.Fatalf("closed PCAP transport accepted: %v", err)
	}
}

// bridgeDispatcher observes ingress at the actual channel injection boundary.
// Packet data is copied because the bridge releases its packet reference.
type bridgeDispatcher struct {
	delivered     chan []byte
	wrongProtocol atomic.Bool
}

func (d *bridgeDispatcher) DeliverNetworkPacket(protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	if protocol != ipv4.ProtocolNumber {
		d.wrongProtocol.Store(true)
	}
	view := pkt.ToView()
	data := append([]byte(nil), view.AsSlice()...)
	view.Release()
	d.delivered <- data
}

func (*bridgeDispatcher) DeliverLinkPacket(tcpip.NetworkProtocolNumber, *stack.PacketBuffer) {}

// reverseTestInner changes a valid test packet into the peer-to-local direction.
func reverseTestInner(data []byte) []byte {
	result := append([]byte(nil), data...)
	copy(result[12:16], data[16:20])
	copy(result[16:20], data[12:16])
	result[10], result[11] = 0, 0
	binary.BigEndian.PutUint16(result[10:12], ^checksumSum(result[:20]))
	return result
}

// queueBridgePacket writes one outbound packet with the same endpoint API used
// by gVisor. The link holds its own packet reference after WritePackets returns.
func queueBridgePacket(t *testing.T, link *channel.Endpoint, data []byte) {
	t.Helper()
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(data)})
	defer pkt.DecRef()
	var list stack.PacketBufferList
	list.PushBack(pkt)
	if n, err := link.WritePackets(list); err != nil || n != 1 {
		t.Fatalf("enqueue packet: n = %d, error = %v", n, err)
	}
}

// TestPacketBridgeDirections verifies actual ingress and egress workers reject
// malformed packets, MTU violations, and incorrect virtual address pairs.
func TestPacketBridgeDirections(t *testing.T) {
	cfg := newTestConfig()
	link := channel.New(16, cfg.MTU, "")
	defer link.Close()
	dispatcher := &bridgeDispatcher{delivered: make(chan []byte, 16)}
	link.Attach(dispatcher)
	local, peer := NewMemoryPair(16)
	defer peer.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	bridge := startPacketBridge(ctx, link, cfg, local, nil)
	defer bridge.Close()
	outbound := testInnerIPv4(t, 24)
	inbound := reverseTestInner(outbound)

	// Deliver invalid traffic followed by one valid packet. FIFO processing
	// makes any acceptance of invalid traffic observable as the first result.
	for _, direction := range []struct {
		valid   []byte
		deliver func([]byte)
	}{
		{valid: outbound, deliver: func(data []byte) { queueBridgePacket(t, link, data) }},
		{valid: inbound, deliver: func(data []byte) {
			if err := peer.Send(ctx, data); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		wrongSource := append([]byte(nil), direction.valid...)
		wrongSource[12] ^= 1
		wrongDestination := append([]byte(nil), direction.valid...)
		wrongDestination[16] ^= 1
		wrongLength := append([]byte(nil), direction.valid...)
		wrongLength[3]--
		oversized := testInnerIPv4(t, int(cfg.MTU)+1)
		for _, data := range [][]byte{nil, direction.valid[:19], wrongLength, wrongSource, wrongDestination, oversized, direction.valid} {
			direction.deliver(data)
		}
	}
	got, err := peer.Receive(ctx)
	if err != nil || !bytes.Equal(got, outbound) {
		t.Fatalf("bridge egress = %x, %v; want %x", got, err, outbound)
	}
	select {
	case got := <-dispatcher.delivered:
		if !bytes.Equal(got, inbound) {
			t.Fatalf("bridge ingress = %x, want %x", got, inbound)
		}
	case <-ctx.Done():
		t.Fatal("bridge did not inject valid inbound packet")
	}
	if dispatcher.wrongProtocol.Load() {
		t.Error("bridge injected with the wrong network protocol")
	}
	if err := bridge.Close(); err != nil {
		t.Fatal(err)
	}
	if err := bridge.failure(); err != nil {
		t.Fatalf("normal shutdown recorded a failure: %v", err)
	}
}

// TestVirtualStackWithPCAPDefaults verifies normalized default MTUs agree and
// successful attachment owns a PCAP transport even when reservation is disabled.
func TestVirtualStackWithPCAPDefaults(t *testing.T) {
	f := newSetupFixture(t)
	f.cfg.ReserveUDPPort = false
	p, err := newPCAPTransport(context.Background(), f.cfg, f.ops)
	if err != nil {
		t.Fatal(err)
	}
	cfg := newTestConfig()
	cfg.MTU = 0
	v, err := NewVirtualStackWithTransport(cfg, p)
	if err != nil {
		_ = p.Close()
		t.Fatal(err)
	}
	defer v.Close()
	if v.config.MTU != DefaultMTU || v.bridge.config.MTU != DefaultMTU {
		t.Fatal("bridge did not use normalized stack configuration")
	}
	v.Close()
	if f.capture.closes != 1 || f.port.closes != 0 {
		t.Fatalf("close counts capture/port = %d/%d", f.capture.closes, f.port.closes)
	}
}
