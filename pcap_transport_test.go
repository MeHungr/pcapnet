package pcapnet

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// packetCapture implements deterministic packet I/O separately from setup fakes.
// Callbacks can block at a known point to exercise cancellation and Close races.
type packetCapture struct {
	fakeCapture
	read   func() ([]byte, gopacket.CaptureInfo, error)
	write  func([]byte) error
	closed atomic.Int32
}

func (c *packetCapture) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	return c.read()
}
func (c *packetCapture) WritePacketData(data []byte) error { return c.write(data) }
func (c *packetCapture) Close()                            { c.closed.Add(1) }

// newPacketTransport constructs the actual transport through its injected setup
// path, so packet tests also exercise transfer of acquired endpoint ownership.
func newPacketTransport(t *testing.T, c *packetCapture, mtu uint32) *PCAPTransport {
	t.Helper()
	f := newSetupFixture(t)
	f.cfg.MTU = mtu
	// Accommodate the largest legal IPv4/UDP datagram in boundary tests.
	f.iface.MTU = 65535
	f.ops.openCapture = func(string, int32, bool, time.Duration) (captureHandle, error) { return c, nil }
	p, err := newPCAPTransport(context.Background(), f.cfg, f.ops)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := p.Close(); err != nil {
			t.Errorf("close transport: %v", err)
		}
	})
	return p
}

// testInnerIPv4 creates an independently checksummed IPv4 packet of exact size.
// The transport must preserve all inner bytes, including the protocol payload.
func testInnerIPv4(t *testing.T, size int) []byte {
	t.Helper()
	ip := &layers.IPv4{
		Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP,
		SrcIP: net.ParseIP("10.200.0.1").To4(), DstIP: net.ParseIP("10.200.0.2").To4(),
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf,
		gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		ip, gopacket.Payload(make([]byte, size-ipv4MinimumHeaderSize))); err != nil {
		t.Fatal(err)
	}
	return append([]byte(nil), buf.Bytes()...)
}

// TestPCAPTransportSend verifies actual serialized frames, checksums, MTU bounds,
// outer addressing, DF, Ethernet headers, and preservation of inner bytes.
func TestPCAPTransportSend(t *testing.T) {
	for _, size := range []int{20, 21, DefaultMTU, maxUDPInnerMTU} {
		t.Run(stringSize(size), func(t *testing.T) {
			var frame []byte
			c := &packetCapture{fakeCapture: fakeCapture{link: layers.LinkTypeEthernet}}
			// Retain the actual serialization buffer to detect aliasing with
			// the caller's input, rather than masking it with a fake copy.
			c.write = func(data []byte) error { frame = data; return nil }
			p := newPacketTransport(t, c, uint32(sizeOrMinimumMTU(size)))
			inner := testInnerIPv4(t, size)
			want := append([]byte(nil), inner...)
			if err := p.Send(context.Background(), inner); err != nil {
				t.Fatal(err)
			}
			inner[0] ^= 1
			packet, err := ParseUDPPacket(frame)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(packet.Payload, want) {
				t.Error("serialized inner packet changed")
			}
			if packet.SourceIP != p.resources.local.Addr() || packet.SourcePort != p.resources.local.Port() ||
				packet.DestinationIP != p.resources.config.Peer.Addr() || packet.DestinationPort != p.resources.config.Peer.Port() {
				t.Error("incorrect outer UDP tuple")
			}
			if !bytes.Equal(frame[:6], p.resources.dstMAC) || !bytes.Equal(frame[6:12], p.resources.srcMAC) {
				t.Error("incorrect Ethernet addresses")
			}
			ip := frame[ethernetHeaderSize:]
			if ip[0] != 0x45 || ip[8] != 64 || binary.BigEndian.Uint16(ip[6:8]) != 0x4000 {
				t.Error("incorrect IPv4 header or fragmentation policy")
			}
			if int(binary.BigEndian.Uint16(ip[2:4])) != size+outerIPv4HeaderSize+outerUDPHeaderSize {
				t.Error("incorrect outer IPv4 length")
			}
			if binary.BigEndian.Uint16(ip[26:28]) == 0 {
				t.Error("UDP checksum was disabled")
			}
		})
	}
}

// stringSize provides readable subtest names without rune conversions.
func stringSize(size int) string {
	return fmt.Sprintf("size_%d", size)
}

// sizeOrMinimumMTU permits tiny legal IPv4 packets within a valid link MTU.
func sizeOrMinimumMTU(size int) int {
	if size < MinIPv4MTU {
		return MinIPv4MTU
	}
	return size
}

// TestPCAPTransportZeroUDPChecksum exercises UDP's computed-zero special case.
// The checksum word becomes 0xffff rather than disabling checksumming with zero.
func TestPCAPTransportZeroUDPChecksum(t *testing.T) {
	var frame []byte
	c := &packetCapture{fakeCapture: fakeCapture{link: layers.LinkTypeEthernet}}
	c.write = func(data []byte) error { frame = data; return nil }
	p := newPacketTransport(t, c, DefaultMTU)
	inner := testInnerIPv4(t, 22)
	if err := p.Send(context.Background(), inner); err != nil {
		t.Fatal(err)
	}
	// Adding the current checksum to an initially zero payload word makes
	// the one's-complement sum all ones and the computed checksum zero.
	checksumOffset := ethernetHeaderSize + outerIPv4HeaderSize + 6
	binary.BigEndian.PutUint16(inner[20:22], binary.BigEndian.Uint16(frame[checksumOffset:checksumOffset+2]))
	if err := p.Send(context.Background(), inner); err != nil {
		t.Fatal(err)
	}
	if got := binary.BigEndian.Uint16(frame[checksumOffset : checksumOffset+2]); got != 0xffff {
		t.Fatalf("zero checksum encoded as %#x", got)
	}
	if _, err := ParseUDPPacket(frame); err != nil {
		t.Fatalf("special checksum is invalid: %v", err)
	}
}

// TestPCAPTransportSendRejects verifies malformed packets and MTU overruns never
// reach injection, while a native write failure preserves its original cause.
func TestPCAPTransportSendRejects(t *testing.T) {
	failure := errors.New("native injection failed")
	writes := 0
	c := &packetCapture{fakeCapture: fakeCapture{link: layers.LinkTypeEthernet}}
	c.write = func([]byte) error { writes++; return failure }
	p := newPacketTransport(t, c, DefaultMTU)
	valid := testInnerIPv4(t, 24)
	for _, mutate := range []func([]byte) []byte{
		func([]byte) []byte { return nil },
		func(p []byte) []byte { return p[:19] },
		func(p []byte) []byte { p[0] = 0x65; return p },
		func(p []byte) []byte { p[0] = 0x44; return p },
		func(p []byte) []byte { p[0] = 0x4f; return p },
		func(p []byte) []byte { p[3]--; return p },
		func(p []byte) []byte { p[3]++; return p },
		func([]byte) []byte { return testInnerIPv4(t, DefaultMTU+1) },
	} {
		if err := p.Send(context.Background(), mutate(append([]byte(nil), valid...))); err == nil {
			t.Fatal("invalid inner packet accepted")
		}
	}
	if writes != 0 {
		t.Fatal("invalid packets reached injection")
	}
	if err := p.Send(context.Background(), valid); !errors.Is(err, failure) {
		t.Fatalf("write cause lost: %v", err)
	}
}

// captureResult provides one captured frame or native result to a fake reader.
type captureResult struct {
	data []byte
	info gopacket.CaptureInfo
	err  error
}

func capturedFrame(data []byte) captureResult {
	return captureResult{data: data, info: gopacket.CaptureInfo{CaptureLength: len(data), Length: len(data)}}
}

// TestPCAPTransportReceive checks the public receive path independently of BPF:
// bad traffic is skipped and a complete validated inner packet is returned.
func TestPCAPTransportReceive(t *testing.T) {
	inner := testInnerIPv4(t, 24)
	valid := makeTestUDPFrame(t, inner)
	truncated := capturedFrame(valid)
	truncated.info.Length++
	wrongCaptureSize := capturedFrame(valid)
	wrongCaptureSize.info.CaptureLength--
	results := []captureResult{
		{err: pcap.NextErrorTimeoutExpired}, truncated, wrongCaptureSize,
		capturedFrame([]byte("malformed Ethernet")),
	}
	// Alter each tuple component, repairing the IP checksum and using the
	// IPv4-permitted zero UDP checksum so rejection requires tuple checking.
	for _, offset := range []int{12, 16, 20, 22} {
		wrong := append([]byte(nil), valid...)
		ip := wrong[ethernetHeaderSize:]
		ip[offset] ^= 1
		ip[10], ip[11], ip[26], ip[27] = 0, 0, 0, 0
		binary.BigEndian.PutUint16(ip[10:12], ^checksumSum(ip[:20]))
		if _, err := ParseUDPPacket(wrong); err != nil {
			t.Fatalf("tuple fixture is malformed: %v", err)
		}
		results = append(results, capturedFrame(wrong))
	}
	badChecksum := append([]byte(nil), valid...)
	badChecksum[len(badChecksum)-1] ^= 1
	results = append(results, capturedFrame(badChecksum))
	fragment := append([]byte(nil), valid...)
	ip := fragment[ethernetHeaderSize:]
	ip[6] = 0x20
	ip[10], ip[11] = 0, 0
	binary.BigEndian.PutUint16(ip[10:12], ^checksumSum(ip[:20]))
	results = append(results, capturedFrame(fragment))
	for _, payload := range [][]byte{nil, inner[:19], testInnerIPv4(t, DefaultMTU+1)} {
		results = append(results, capturedFrame(makeTestUDPFrame(t, payload)))
	}
	results = append(results, capturedFrame(valid))
	index := 0
	failure := errors.New("capture failed")
	c := &packetCapture{fakeCapture: fakeCapture{link: layers.LinkTypeEthernet}}
	c.read = func() ([]byte, gopacket.CaptureInfo, error) {
		if index >= len(results) {
			return nil, gopacket.CaptureInfo{}, failure
		}
		r := results[index]
		index++
		return r.data, r.info, r.err
	}
	p := newPacketTransport(t, c, DefaultMTU)
	got, err := p.Receive(context.Background())
	if err != nil || !bytes.Equal(got, inner) {
		t.Fatalf("Receive() = %x, %v; want %x", got, err, inner)
	}
	if index != len(results) {
		t.Fatalf("invalid frame was accepted at index %d", index)
	}
	// Returned bytes must survive changes to the original capture buffer.
	valid[len(valid)-1] ^= 1
	if !bytes.Equal(got, inner) {
		t.Error("receive payload aliases capture buffer")
	}
	if _, err := p.Receive(context.Background()); !errors.Is(err, failure) {
		t.Fatalf("capture cause lost: %v", err)
	}
}

// TestPCAPTransportReceiveVLAN checks that transport delivery preserves inner
// bytes through the same supported VLAN formats as the capture filter.
func TestPCAPTransportReceiveVLAN(t *testing.T) {
	for _, tags := range []int{1, 2} {
		t.Run(stringSize(tags), func(t *testing.T) {
			inner := testInnerIPv4(t, 24)
			frame := makeTestUDPFrame(t, inner)
			for i := 0; i < tags; i++ {
				frame = append(append(append([]byte(nil), frame[:12]...), 0x81, 0, 0, 1), frame[12:]...)
			}
			if tags == 2 {
				frame[12], frame[13] = 0x88, 0xa8
			}
			c := &packetCapture{fakeCapture: fakeCapture{link: layers.LinkTypeEthernet}}
			c.read = func() ([]byte, gopacket.CaptureInfo, error) {
				r := capturedFrame(frame)
				return r.data, r.info, nil
			}
			p := newPacketTransport(t, c, DefaultMTU)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			got, err := p.Receive(ctx)
			if err != nil || !bytes.Equal(got, inner) {
				t.Fatalf("Receive() = %x, %v", got, err)
			}
		})
	}
}

// awaitSignal bounds synchronization failures without depending on sleeps.
func awaitSignal(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for packet operation")
	}
}

// awaitError bounds completion of an operation that should have been unblocked.
func awaitError(t *testing.T, ch <-chan error) error {
	t.Helper()
	select {
	case err := <-ch:
		return err
	case <-time.After(3 * time.Second):
		t.Fatal("packet operation did not finish")
		return nil
	}
}

// TestPCAPTransportCloseDuringIO verifies simultaneous capture/injection, queued
// operation wakeup, and that no handle is released during active native I/O.
func TestPCAPTransportCloseDuringIO(t *testing.T) {
	readStarted, writeStarted := make(chan struct{}), make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	c := &packetCapture{fakeCapture: fakeCapture{link: layers.LinkTypeEthernet}}
	c.read = func() ([]byte, gopacket.CaptureInfo, error) {
		close(readStarted)
		<-release
		return nil, gopacket.CaptureInfo{}, pcap.NextErrorTimeoutExpired
	}
	c.write = func([]byte) error { close(writeStarted); <-release; return nil }
	p := newPacketTransport(t, c, DefaultMTU)
	inner := testInnerIPv4(t, 24)
	readDone, writeDone, closeDone := make(chan error, 1), make(chan error, 1), make(chan error, 1)
	go func() { _, err := p.Receive(context.Background()); readDone <- err }()
	go func() { writeDone <- p.Send(context.Background(), inner) }()
	awaitSignal(t, readStarted)
	awaitSignal(t, writeStarted)
	go func() { closeDone <- p.Close() }()
	awaitSignal(t, p.done)
	// Concurrent Close callers must all await the same resource release.
	otherClosers := make(chan error, 4)
	for i := 0; i < cap(otherClosers); i++ {
		go func() { otherClosers <- p.Close() }()
	}
	if c.closed.Load() != 0 {
		t.Fatal("capture handle closed while native I/O was active")
	}
	if err := p.Send(context.Background(), inner); !errors.Is(err, ErrClosed) {
		t.Fatalf("queued send did not observe closure: %v", err)
	}
	if _, err := p.Receive(context.Background()); !errors.Is(err, ErrClosed) {
		t.Fatalf("queued receive did not observe closure: %v", err)
	}
	releaseOnce.Do(func() { close(release) })
	if err := awaitError(t, writeDone); err != nil {
		t.Fatalf("completed injection failed: %v", err)
	}
	if err := awaitError(t, readDone); !errors.Is(err, ErrClosed) {
		t.Fatalf("receive error = %v", err)
	}
	if err := awaitError(t, closeDone); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < cap(otherClosers); i++ {
		if err := awaitError(t, otherClosers); err != nil {
			t.Fatal(err)
		}
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if c.closed.Load() != 1 {
		t.Fatal("capture handle was not closed exactly once")
	}
}

// TestPCAPTransportReceiveCancellation verifies that an active receive checks
// cancellation after its current native call, without shutting down transport.
func TestPCAPTransportReceiveCancellation(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	c := &packetCapture{fakeCapture: fakeCapture{link: layers.LinkTypeEthernet}}
	c.read = func() ([]byte, gopacket.CaptureInfo, error) {
		close(started)
		<-release
		return nil, gopacket.CaptureInfo{}, pcap.NextErrorTimeoutExpired
	}
	c.write = func([]byte) error { return nil }
	p := newPacketTransport(t, c, DefaultMTU)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := p.Receive(ctx); done <- err }()
	awaitSignal(t, started)
	cancel()
	releaseOnce.Do(func() { close(release) })
	if err := awaitError(t, done); !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v", err)
	}
	if err := p.Send(context.Background(), testInnerIPv4(t, 24)); err != nil {
		t.Fatalf("canceled receive closed transport: %v", err)
	}
}

// TestPCAPTransportContexts verifies operation rejection and that a canceled
// setup context does not cancel the successfully created transport's lifetime.
func TestPCAPTransportContexts(t *testing.T) {
	f := newSetupFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	p, err := newPCAPTransport(ctx, f.cfg, f.ops)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	cancel()
	inner := testInnerIPv4(t, 24)
	if err := p.Send(context.Background(), inner); err != nil {
		t.Fatal(err)
	}
	if err := p.Send(ctx, inner); !errors.Is(err, context.Canceled) {
		t.Fatalf("send error = %v", err)
	}
	if _, err := p.Receive(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("receive error = %v", err)
	}
	if err := p.Send(nil, inner); err == nil {
		t.Fatal("nil send context accepted")
	}
	if _, err := p.Receive(nil); err == nil {
		t.Fatal("nil receive context accepted")
	}
	if _, err := NewPCAPTransport(ctx, f.cfg); !errors.Is(err, context.Canceled) {
		t.Fatalf("constructor error = %v", err)
	}
	if _, err := NewPCAPTransport(nil, f.cfg); err == nil {
		t.Fatal("nil setup context accepted")
	}
	if _, err := NewPCAPTransport(context.Background(), PCAPConfig{}); err == nil {
		t.Fatal("invalid constructor config accepted")
	}
	for _, closed := range []*PCAPTransport{nil, {}, p} {
		if err := closed.Close(); err != nil {
			t.Fatal(err)
		}
		if err := closed.Send(context.Background(), inner); !errors.Is(err, ErrClosed) {
			t.Fatalf("closed send error = %v", err)
		}
		if _, err := closed.Receive(context.Background()); !errors.Is(err, ErrClosed) {
			t.Fatalf("closed receive error = %v", err)
		}
	}
}

// TestPCAPTransportQueuedCancellation checks that callers waiting behind another
// operation can cancel without waiting for the occupied native operation slot.
func TestPCAPTransportQueuedCancellation(t *testing.T) {
	c := &packetCapture{fakeCapture: fakeCapture{link: layers.LinkTypeEthernet}}
	p := newPacketTransport(t, c, DefaultMTU)
	for _, gate := range []chan struct{}{p.sendGate, p.recvGate} {
		<-gate
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- p.acquire(ctx, gate) }()
		cancel()
		err := awaitError(t, done)
		// Restore the slot even when an assertion fails so cleanup can finish.
		gate <- struct{}{}
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("gate wait error = %v", err)
		}
	}
}
