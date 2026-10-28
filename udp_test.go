package pcapnet

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// udpEvent can establish a capture-processing barrier without timing sleeps.
type udpEvent struct {
	frame   captureResult
	barrier chan struct{}
}
type udpFixture struct {
	setup   *setupFixture
	ops     udpSetupOps
	config  UDPConfig
	capture *packetCapture
	events  chan udpEvent
	writes  chan []byte
}

// newUDPFixture models a real packet device while keeping all route, ARP, bind,
// and capture operations deterministic and free of native network privileges.
func newUDPFixture(t *testing.T) *udpFixture {
	t.Helper()
	setup := newSetupFixture(t)
	f := &udpFixture{setup: setup, config: UDPConfig{DeviceName: "eth0", LocalIP: netip.MustParseAddr("192.0.2.2"), LocalPort: 6767}, events: make(chan udpEvent, 512), writes: make(chan []byte, 512)}
	f.capture = &packetCapture{fakeCapture: fakeCapture{link: layers.LinkTypeEthernet}}
	f.capture.read = func() ([]byte, gopacket.CaptureInfo, error) {
		timer := time.NewTimer(5 * time.Millisecond)
		defer timer.Stop()
		select {
		case event := <-f.events:
			if event.barrier != nil {
				close(event.barrier)
				return nil, gopacket.CaptureInfo{}, pcap.NextErrorTimeoutExpired
			}
			return event.frame.data, event.frame.info, event.frame.err
		case <-timer.C:
			return nil, gopacket.CaptureInfo{}, pcap.NextErrorTimeoutExpired
		}
	}
	f.capture.write = func(data []byte) error { f.writes <- append([]byte(nil), data...); return nil }
	f.ops = udpSetupOps{pcapSetupOps: setup.ops, interfaceForIP: func(netip.Addr) (*net.Interface, error) { return setup.iface, nil }}
	f.ops.openCapture = func(string, int32, bool, time.Duration) (captureHandle, error) { return f.capture, nil }
	return f
}

func (f *udpFixture) open(t *testing.T, connected bool) *UDPConn {
	t.Helper()
	peer := netip.AddrPort{}
	if connected {
		peer = netip.MustParseAddrPort("192.0.2.1:40000")
	}
	c, err := newUDPConn(context.Background(), f.config, peer, f.ops)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { done := make(chan error, 1); go func() { done <- c.Close() }(); _ = awaitError(t, done) })
	return c
}
func (f *udpFixture) feed(data []byte) { f.events <- udpEvent{frame: capturedFrame(data)} }
func (f *udpFixture) barrier(t *testing.T) {
	done := make(chan struct{})
	f.events <- udpEvent{barrier: done}
	awaitSignal(t, done)
}

// TestDirectUDPDatagrams verifies the connected and unconnected interfaces,
// independent byte ownership, empty datagrams, MTU-sized payloads, and truncation.
func TestDirectUDPDatagrams(t *testing.T) {
	f := newUDPFixture(t)
	c := f.open(t, true)
	if c.LocalAddr().String() != "192.0.2.2:6767" || c.RemoteAddr().String() != "192.0.2.1:40000" {
		t.Fatal("incorrect endpoint addresses")
	}
	for _, size := range []int{0, 1, 1472} {
		payload := bytes.Repeat([]byte{7}, size)
		if n, err := c.Write(payload); err != nil || n != size {
			t.Fatalf("write %d: %d, %v", size, n, err)
		}
		frame := <-f.writes
		packet, err := ParseUDPPacket(frame)
		if err != nil || !bytes.Equal(packet.Payload, payload) {
			t.Fatalf("wire datagram: %+v, %v", packet, err)
		}
		if packet.SourcePort != 6767 || packet.DestinationPort != 40000 || packet.SourceIP != f.config.LocalIP {
			t.Fatal("wrong wire tuple")
		}
		if binary.BigEndian.Uint16(frame[20:22]) != 0x4000 {
			t.Fatal("outer IPv4 did not set Don't Fragment")
		}
	}
	if n, err := c.Write(make([]byte, 1473)); n != 0 || !errors.Is(err, ErrDatagramTooLarge) {
		t.Fatalf("oversized datagram: %d, %v", n, err)
	}
	f.feed(makeTestUDPFrame(t, []byte("long datagram")))
	f.feed(makeTestUDPFrame(t, nil))
	f.feed(makeTestUDPFrame(t, []byte("next")))
	buffer := make([]byte, 4)
	if n, err := c.Read(buffer); n != 4 || err != nil || string(buffer) != "long" {
		t.Fatalf("truncated read: %d %q %v", n, buffer, err)
	}
	if n, err := c.Read(buffer); n != 0 || err != nil {
		t.Fatalf("empty datagram lost: %d %v", n, err)
	}
	if n, err := c.Read(buffer); n != 4 || err != nil || string(buffer) != "next" {
		t.Fatalf("datagram boundary lost: %d %q %v", n, buffer, err)
	}
	if _, err := c.WriteTo(nil, &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 40000}); err == nil {
		t.Fatal("connected WriteTo accepted")
	}
}

// TestDirectUDPListener accepts multiple peers and preserves source addressing.
// Replies resolve a route/ARP independently, with cached next-hop MAC reuse.
func TestDirectUDPListener(t *testing.T) {
	f := newUDPFixture(t)
	var arpCalls atomic.Int32
	original := f.ops.resolveARP
	f.ops.resolveARP = func(ctx context.Context, d *pcap.Interface, m net.HardwareAddr, s, n net.IP) (net.HardwareAddr, error) {
		arpCalls.Add(1)
		return original(ctx, d, m, s, n)
	}
	c := f.open(t, false)
	if c.RemoteAddr() != nil {
		t.Fatal("listener has a connected peer")
	}
	for _, port := range []uint16{40000, 40001} {
		frame, err := udpFrame(netip.AddrPortFrom(netip.MustParseAddr("192.0.2.1"), port), c.resources.local, f.setup.mac, f.setup.iface.HardwareAddr, []byte(fmt.Sprint(port)))
		if err != nil {
			t.Fatal(err)
		}
		f.feed(frame)
		buffer := make([]byte, 32)
		n, addr, err := c.ReadFrom(buffer)
		if err != nil || addr.String() != fmt.Sprintf("192.0.2.1:%d", port) {
			t.Fatalf("sender address: %v %v", addr, err)
		}
		if _, err := c.WriteTo(buffer[:n], addr); err != nil {
			t.Fatal(err)
		}
		packet, err := ParseUDPPacket(<-f.writes)
		if err != nil || packet.DestinationPort != port || !bytes.Equal(packet.Payload, buffer[:n]) {
			t.Fatalf("reply: %+v %v", packet, err)
		}
	}
	if arpCalls.Load() != 1 {
		t.Fatalf("ARP cache was not reused: %d", arpCalls.Load())
	}
	if _, err := c.Write(nil); err == nil {
		t.Fatal("unconnected Write accepted")
	}
	for _, address := range []net.Addr{nil, (*net.UDPAddr)(nil), &net.TCPAddr{}, &net.UDPAddr{IP: net.ParseIP("::1"), Port: 5}, &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 70000}, &net.UDPAddr{IP: net.ParseIP("224.0.0.1"), Port: 5}} {
		if _, err := c.WriteTo(nil, address); err == nil {
			t.Fatalf("invalid destination accepted: %v", address)
		}
	}
}

// TestDirectUDPFiltering exercises parsing and tuple checks without relying on
// BPF, and verifies queue overflow drops whole new datagrams without blocking.
func TestDirectUDPFiltering(t *testing.T) {
	f := newUDPFixture(t)
	c := f.open(t, true)
	valid := makeTestUDPFrame(t, []byte("valid"))
	f.feed([]byte("bad frame"))
	bad := append([]byte(nil), valid...)
	bad[ethernetHeaderSize+outerIPv4HeaderSize+udpHeaderSize] ^= 1
	f.feed(bad)
	for _, remote := range []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:40001"), netip.MustParseAddrPort("192.0.2.3:40000")} {
		frame, _ := udpFrame(remote, c.resources.local, f.setup.mac, f.setup.iface.HardwareAddr, []byte("wrong peer"))
		f.feed(frame)
	}
	wrongLocal := netip.MustParseAddrPort("192.0.2.2:6768")
	frame, _ := udpFrame(c.peer, wrongLocal, f.setup.mac, f.setup.iface.HardwareAddr, []byte("wrong local"))
	f.feed(frame)
	f.feed(makeTestUDPFrame(t, make([]byte, 1473)))
	truncated := capturedFrame(valid)
	truncated.info.Length++
	f.events <- udpEvent{frame: truncated}
	f.barrier(t)
	if len(c.inbox) != 0 {
		t.Fatal("invalid traffic entered receive queue")
	}
	for i := 0; i < 257; i++ {
		f.feed(valid)
	}
	f.barrier(t)
	if len(c.inbox) != 256 {
		t.Fatalf("bounded queue length = %d", len(c.inbox))
	}
}

// TestDirectUDPDeadlines verifies deadline changes affect pending operations,
// expired deadlines report net.Error timeouts, and clearing permits new I/O.
func TestDirectUDPDeadlines(t *testing.T) {
	f := newUDPFixture(t)
	c := f.open(t, true)
	result := make(chan error, 1)
	go func() { _, err := c.Read(make([]byte, 8)); result <- err }()
	if err := c.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	err := awaitError(t, result)
	var timeout net.Error
	if !errors.Is(err, os.ErrDeadlineExceeded) || !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Fatalf("read deadline: %v", err)
	}
	_ = c.SetReadDeadline(time.Time{})
	f.feed(makeTestUDPFrame(t, []byte("ok")))
	if n, err := c.Read(make([]byte, 8)); n != 2 || err != nil {
		t.Fatalf("cleared read deadline: %d %v", n, err)
	}
	// Hold injection's gate to ensure the pending write has no native call.
	<-c.sendGate
	go func() { _, err := c.Write([]byte("blocked")); result <- err }()
	_ = c.SetWriteDeadline(time.Now().Add(-time.Second))
	err = awaitError(t, result)
	c.sendGate <- struct{}{}
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("write deadline: %v", err)
	}
	_ = c.SetDeadline(time.Time{})
	if _, err := c.Write(nil); err != nil {
		t.Fatalf("cleared write deadline: %v", err)
	}
	_ = c.SetReadDeadline(time.Now().Add(-time.Second))
	f.feed(makeTestUDPFrame(t, []byte("queued")))
	f.barrier(t)
	if _, err := c.Read(make([]byte, 32)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("queued data bypassed deadline: %v", err)
	}
}

// TestDirectUDPFailures verifies native failures close the endpoint and wake its
// callers, while a normal Close is idempotent and deadline setters reject closure.
func TestDirectUDPFailures(t *testing.T) {
	for _, writeFailure := range []bool{false, true} {
		t.Run(fmt.Sprint(writeFailure), func(t *testing.T) {
			f := newUDPFixture(t)
			cause := errors.New("native UDP failure")
			if writeFailure {
				f.capture.write = func([]byte) error { return cause }
			}
			c := f.open(t, true)
			result := make(chan error, 1)
			go func() { _, err := c.Read(make([]byte, 8)); result <- err }()
			if writeFailure {
				if _, err := c.Write(nil); !errors.Is(err, cause) {
					t.Fatalf("write cause lost: %v", err)
				}
			} else {
				f.events <- udpEvent{frame: captureResult{err: cause}}
			}
			if err := awaitError(t, result); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("reader not closed: %v", err)
			}
			done := make(chan error, 1)
			go func() { done <- c.Close() }()
			if err := awaitError(t, done); !errors.Is(err, cause) {
				t.Fatalf("terminal cause lost: %v", err)
			}
			if !errors.Is(c.Err(), cause) || f.capture.closed.Load() != 1 {
				t.Fatal("native failure cleanup incorrect")
			}
		})
	}
	f := newUDPFixture(t)
	c := f.open(t, false)
	result := make(chan error, 1)
	go func() { _, _, err := c.ReadFrom(nil); result <- err }()
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if err := awaitError(t, result); !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
	if err := c.SetDeadline(time.Time{}); !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
	if c.Err() != nil || c.Close() != nil || f.capture.closed.Load() != 1 {
		t.Fatal("normal closure failed")
	}
}

// TestDirectUDPSetup rejects invalid configuration before capture and preserves
// caller resources on failure, including optional UDP reservation rollback.
func TestDirectUDPSetup(t *testing.T) {
	if _, err := DialUDP(context.Background(), UDPConfig{}, netip.AddrPort{}); err == nil {
		t.Fatal("missing dial peer accepted")
	}
	for _, test := range []struct {
		name      string
		change    func(*udpFixture)
		connected bool
	}{
		{"no listener IP", func(f *udpFixture) { f.config.LocalIP = netip.Addr{} }, false},
		{"missing listener port", func(f *udpFixture) { f.config.LocalPort = 0 }, false},
		{"wrong source", func(f *udpFixture) { f.config.LocalIP = netip.MustParseAddr("192.0.2.3") }, true},
		{"MTU too large", func(f *udpFixture) { f.config.MTU = 1501 }, true},
		{"wrong capture type", func(f *udpFixture) { f.capture.link = layers.LinkTypeRaw }, true},
		{"filter failure", func(f *udpFixture) { f.capture.filterErr = errors.New("filter failure") }, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newUDPFixture(t)
			test.change(f)
			peer := netip.AddrPort{}
			if test.connected {
				peer = netip.MustParseAddrPort("192.0.2.1:40000")
			}
			if c, err := newUDPConn(context.Background(), f.config, peer, f.ops); err == nil {
				_ = c.Close()
				t.Fatal("invalid setup accepted")
			}
		})
	}
	f := newUDPFixture(t)
	f.config.LocalIP = netip.Addr{}
	f.config.ReserveUDPPort = true
	c := f.open(t, true)
	if c.LocalAddr().String() != "192.0.2.2:6767" {
		t.Fatal("dial did not use route source")
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if f.setup.port.closes != 1 {
		t.Fatal("reservation was not released")
	}
}

// TestDirectUDPChecksumZero verifies gopacket's computed-zero checksum is encoded
// as 0xffff so direct UDP never accidentally disables its checksum.
func TestDirectUDPChecksumZero(t *testing.T) {
	f := newUDPFixture(t)
	c := f.open(t, true)
	payload := make([]byte, 2)
	if _, err := c.Write(payload); err != nil {
		t.Fatal(err)
	}
	first := <-f.writes
	offset := ethernetHeaderSize + outerIPv4HeaderSize + 6
	binary.BigEndian.PutUint16(payload, binary.BigEndian.Uint16(first[offset:offset+2]))
	if _, err := c.Write(payload); err != nil {
		t.Fatal(err)
	}
	frame := <-f.writes
	if binary.BigEndian.Uint16(frame[offset:offset+2]) != 0xffff {
		t.Fatal("computed zero checksum was not encoded as all ones")
	}
	if _, err := ParseUDPPacket(frame); err != nil {
		t.Fatal(err)
	}
}

// TestDirectUDPListenFilter checks real libpcap matching for multiple source
// endpoints, wrong destinations, and supported VLAN offsets.
func TestDirectUDPListenFilter(t *testing.T) {
	local := netip.MustParseAddrPort("192.0.2.2:6767")
	filter, err := pcap.NewBPF(layers.LinkTypeEthernet, captureSnaplen, udpListenFilter(local))
	if err != nil {
		t.Fatal(err)
	}
	for _, source := range []string{"192.0.2.1:40000", "192.0.2.3:50000"} {
		for _, tags := range []int{0, 1, 2} {
			frame, err := udpFrame(netip.MustParseAddrPort(source), local, net.HardwareAddr{2, 1, 2, 3, 4, 5}, net.HardwareAddr{2, 6, 7, 8, 9, 10}, nil)
			if err != nil {
				t.Fatal(err)
			}
			for i := 0; i < tags; i++ {
				frame = append(append(append([]byte(nil), frame[:12]...), 0x81, 0, 0, 1), frame[12:]...)
			}
			if tags == 2 {
				frame[12], frame[13] = 0x88, 0xa8
			}
			info := gopacket.CaptureInfo{CaptureLength: len(frame), Length: len(frame)}
			if !filter.Matches(info, frame) {
				t.Fatalf("source %s with %d tags rejected", source, tags)
			}
			frame[ethernetHeaderSize+tags*4+23] ^= 1
			if filter.Matches(info, frame) {
				t.Fatal("wrong local port accepted")
			}
		}
	}
}

// TestDirectUDPDeadlineTimer verifies an actual future deadline expires without
// another deadline setter or datagram waking the operation.
func TestDirectUDPDeadlineTimer(t *testing.T) {
	f := newUDPFixture(t)
	c := f.open(t, true)
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
	result := make(chan error, 1)
	go func() { _, err := c.Read(nil); result <- err }()
	if err := awaitError(t, result); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal(err)
	}
}

// TestDirectUDPIncomingMTUOptions verifies the physical MTU includes IPv4
// options, rather than checking only application payload plus minimum headers.
func TestDirectUDPIncomingMTUOptions(t *testing.T) {
	f := newUDPFixture(t)
	f.config.MTU = 48
	c := f.open(t, true)
	payload := bytes.Repeat([]byte{1}, 20)
	plain := makeTestUDPFrame(t, payload)
	offset := ethernetHeaderSize + outerIPv4HeaderSize
	options := append(append(append([]byte(nil), plain[:offset]...), 1, 1, 1, 1), plain[offset:]...)
	ip := options[ethernetHeaderSize:]
	ip[0] = 0x46
	binary.BigEndian.PutUint16(ip[2:4], 52)
	ip[10], ip[11] = 0, 0
	binary.BigEndian.PutUint16(ip[10:12], ^checksumSum(ip[:24]))
	if _, err := ParseUDPPacket(options); err != nil {
		t.Fatalf("invalid IP options fixture: %v", err)
	}
	f.feed(options)
	f.feed(plain)
	f.barrier(t)
	if len(c.inbox) != 1 {
		t.Fatalf("incoming physical MTU was not enforced: queued %d datagrams", len(c.inbox))
	}
}

// TestDirectUDPWriteRouteErrors keeps route/ARP failures local to the write and
// verifies an in-progress ARP operation observes a changed write deadline.
func TestDirectUDPWriteRouteErrors(t *testing.T) {
	f := newUDPFixture(t)
	f.ops.resolveARP = func(ctx context.Context, _ *pcap.Interface, _ net.HardwareAddr, _ net.IP, _ net.IP) (net.HardwareAddr, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	c := f.open(t, false)
	_ = c.SetWriteDeadline(time.Now().Add(10 * time.Millisecond))
	result := make(chan error, 1)
	go func() {
		_, err := c.WriteTo(nil, &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 40000})
		result <- err
	}()
	if err := awaitError(t, result); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("ARP deadline: %v", err)
	}
	if c.Err() != nil {
		t.Fatal("application write deadline closed endpoint")
	}
}

// TestDirectUDPSetupRollback preserves both setup and reservation cleanup errors.
func TestDirectUDPSetupRollback(t *testing.T) {
	f := newUDPFixture(t)
	f.config.ReserveUDPPort = true
	cause, cleanup := errors.New("filter failure"), errors.New("reservation cleanup failure")
	f.capture.filterErr = cause
	f.setup.port.err = cleanup
	c, err := newUDPConn(context.Background(), f.config, netip.MustParseAddrPort("192.0.2.1:40000"), f.ops)
	if c != nil || !errors.Is(err, cause) || !errors.Is(err, cleanup) {
		t.Fatalf("setup causes lost: %v", err)
	}
	if f.capture.closed.Load() != 1 || f.setup.port.closes != 1 {
		t.Fatal("setup resources leaked")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := newUDPConn(ctx, f.config, netip.AddrPort{}, f.ops); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

// TestDirectUDPConcurrentClose races pending reads and closers against the same
// endpoint; native resources must close once and callers must all be released.
func TestDirectUDPConcurrentClose(t *testing.T) {
	f := newUDPFixture(t)
	c := f.open(t, true)
	results := make(chan error, 24)
	for i := 0; i < 16; i++ {
		go func() {
			_, err := c.Read(nil)
			if !errors.Is(err, net.ErrClosed) {
				results <- fmt.Errorf("read error: %v", err)
				return
			}
			results <- nil
		}()
	}
	for i := 0; i < 8; i++ {
		go func() { results <- c.Close() }()
	}
	for i := 0; i < 24; i++ {
		if err := awaitError(t, results); err != nil {
			t.Fatal(err)
		}
	}
	if f.capture.closed.Load() != 1 {
		t.Fatal("concurrent closure repeated native cleanup")
	}
}
