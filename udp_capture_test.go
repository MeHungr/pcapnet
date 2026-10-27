package pcapnet

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func TestUDPCaptureMagicAndPorts(t *testing.T) {
	f := newUDPFixture(t)
	magic := []byte("0123456789abcdef\x00\xff") // Full match extends beyond the BPF prefilter.
	cfg := UDPCaptureConfig{LocalIP: f.config.LocalIP, MagicHeader: bytes.Clone(magic)}
	c, err := newUDPCapture(context.Background(), cfg, f.ops)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	cfg.MagicHeader[0] = 'X' // The capture owns an independent configuration copy.
	filter, err := pcap.NewBPF(layers.LinkTypeEthernet, captureSnaplen, udpMagicFilter(cfg.LocalIP, magic))
	if err != nil {
		t.Fatal(err)
	}
	frame := func(port uint16, payload []byte) []byte {
		data, err := udpFrame(netip.MustParseAddrPort("192.0.2.1:1234"), netip.AddrPortFrom(cfg.LocalIP, port), net.HardwareAddr{2, 0, 0, 0, 0, 1}, net.HardwareAddr{2, 0, 0, 0, 0, 2}, payload)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	for _, port := range []uint16{0, 1, 45001, 65535} {
		data := frame(port, append(bytes.Clone(magic), 'a'))
		if !filter.Matches(capturedFrame(data).info, data) {
			t.Fatalf("BPF rejected port %d", port)
		}
		f.feed(data)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		packet, err := c.Receive(ctx)
		cancel()
		if err != nil || packet.DestinationPort != port || packet.SourcePort != 1234 || !bytes.Equal(packet.Payload, append(bytes.Clone(magic), 'a')) {
			t.Fatalf("receive: %+v, %v", packet, err)
		}
	}
	for _, payload := range [][]byte{magic[:17], append([]byte("x"), magic...), append(bytes.Clone(magic[:17]), 0)} {
		f.feed(frame(9999, payload))
	}
	f.barrier(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := c.Receive(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("nonmatching payload: %v", err)
	}
	if len(f.writes) != 0 || f.setup.port.closes != 0 {
		t.Fatal("capture sent traffic or reserved a port")
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Receive(context.Background()); !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
	if f.capture.closed.Load() != 1 || len(c.inbox) != 0 {
		t.Fatal("capture resources not released exactly once")
	}
}

func TestUDPCaptureFailureCleanup(t *testing.T) {
	t.Run("filter", func(t *testing.T) {
		f := newUDPFixture(t)
		f.capture.filterErr = io.ErrUnexpectedEOF
		_, err := newUDPCapture(context.Background(), UDPCaptureConfig{LocalIP: f.config.LocalIP, MagicHeader: []byte{0xff}}, f.ops)
		if !errors.Is(err, io.ErrUnexpectedEOF) || f.capture.closed.Load() != 1 {
			t.Fatalf("rollback: %v, %d", err, f.capture.closed.Load())
		}
	})
	t.Run("read", func(t *testing.T) {
		f := newUDPFixture(t)
		c, err := newUDPCapture(context.Background(), UDPCaptureConfig{LocalIP: f.config.LocalIP, MagicHeader: []byte("PCAT")}, f.ops)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		f.events <- udpEvent{frame: captureResult{err: io.ErrUnexpectedEOF}}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if _, err := c.Receive(ctx); !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatal(err)
		}
		c.Close()
		if f.capture.closed.Load() != 1 {
			t.Fatal("terminal error leaked handle")
		}
	})
	t.Run("empty magic", func(t *testing.T) {
		f := newUDPFixture(t)
		if _, err := newUDPCapture(context.Background(), UDPCaptureConfig{LocalIP: f.config.LocalIP}, f.ops); err == nil {
			t.Fatal("empty magic accepted")
		}
	})
}

// TestUDPCaptureBPF verifies native prefix offsets for untagged and VLAN frames,
// including binary headers and rejection before userspace processing.
func TestUDPCaptureBPF(t *testing.T) {
	local := netip.MustParseAddrPort("192.0.2.2:65535")
	magic := []byte{0, 0xff, 0x80}
	filter, err := pcap.NewBPF(layers.LinkTypeEthernet, captureSnaplen, udpMagicFilter(local.Addr(), magic))
	if err != nil {
		t.Fatal(err)
	}
	for tags := 0; tags <= 2; tags++ {
		data, err := udpFrame(netip.MustParseAddrPort("192.0.2.1:1"), local, net.HardwareAddr{2, 0, 0, 0, 0, 1}, net.HardwareAddr{2, 0, 0, 0, 0, 2}, magic)
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < tags; i++ {
			data = append(append(append([]byte(nil), data[:12]...), 0x81, 0, 0, 1), data[12:]...)
		}
		info := capturedFrame(data).info
		if !filter.Matches(info, data) {
			t.Fatalf("rejected %d tags", tags)
		}
		data[14+4*tags+28] ^= 1
		if filter.Matches(info, data) {
			t.Fatalf("accepted wrong prefix with %d tags", tags)
		}
	}
}

// TestUDPCaptureCancellation checks that Close wakes a blocked receiver and
// setup cancellation prevents acquisition of native capture resources.
func TestUDPCaptureCancellation(t *testing.T) {
	f := newUDPFixture(t)
	// These optional operations must never be used by read-only capture.
	f.ops.reservePort = nil
	f.ops.lookupRoute = nil
	f.ops.resolveARP = nil
	cfg := UDPCaptureConfig{LocalIP: f.config.LocalIP, MagicHeader: []byte("PCAT")}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := newUDPCapture(ctx, cfg, f.ops); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	c, err := newUDPCapture(context.Background(), cfg, f.ops)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	done := make(chan error, 1)
	go func() { _, err := c.Receive(context.Background()); done <- err }()
	c.Close()
	if err := awaitError(t, done); !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
}
