package pcapnet

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func openCaptureServer(t *testing.T, f *udpFixture, magic []byte) *UDPCaptureServer {
	t.Helper()
	// A capture server never reserves a host port.
	f.ops.reservePort = nil
	server, err := newUDPCaptureServer(context.Background(), UDPCaptureConfig{LocalIP: f.config.LocalIP, MagicHeader: magic}, f.ops)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close() })
	return server
}

// TestUDPCaptureServerReplies checks full-prefix filtering, body ownership, and
// reversed wire tuples without allocating a capture handle per destination port.
func TestUDPCaptureServerReplies(t *testing.T) {
	f := newUDPFixture(t)
	magic := []byte("0123456789abcdef\x00\xff")
	server := openCaptureServer(t, f, bytes.Clone(magic))
	frame := func(port uint16, header, body []byte) []byte {
		wire, err := udpFrame(netip.MustParseAddrPort("192.0.2.1:45000"), netip.AddrPortFrom(f.config.LocalIP, port), net.HardwareAddr{2, 0, 0, 0, 0, 1}, net.HardwareAddr{2, 0, 0, 0, 0, 2}, append(bytes.Clone(header), body...))
		if err != nil {
			t.Fatal(err)
		}
		return wire
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	// Wrong and incomplete prefixes, port zero, and mismatches after the BPF's
	// initial 16 bytes must not reach applications, even if native filtering errs.
	for _, wire := range [][]byte{frame(1, magic[:17], nil), frame(2, append(bytes.Clone(magic[:17]), 0), nil), frame(0, magic, nil)} {
		f.feed(wire)
	}
	for _, port := range []uint16{1, 45001, 65535} {
		for _, size := range []int{0, 1, server.MaxDatagramSize()} {
			body := bytes.Repeat([]byte{0x7f}, size)
			f.feed(frame(port, magic, body))
			request, err := server.Receive(ctx)
			if err != nil || request.DestinationPort != port || !bytes.Equal(request.Payload, body) {
				t.Fatalf("receive: %+v, %v", request, err)
			}
			if err := server.Reply(ctx, request, request.Payload); err != nil {
				t.Fatal(err)
			}
			reply, err := ParseUDPPacket(<-f.writes)
			if err != nil || reply.SourceIP != f.config.LocalIP || reply.SourcePort != port || reply.DestinationIP != request.SourceIP || reply.DestinationPort != request.SourcePort || !bytes.Equal(reply.Payload, append(bytes.Clone(magic), body...)) {
				t.Fatalf("reply: %+v, %v", reply, err)
			}
		}
	}
	request := &UDPPacket{SourceIP: netip.MustParseAddr("192.0.2.1"), SourcePort: 45000, DestinationIP: f.config.LocalIP, DestinationPort: 12345}
	if err := server.Reply(ctx, request, make([]byte, server.MaxDatagramSize()+1)); !errors.Is(err, ErrDatagramTooLarge) {
		t.Fatal(err)
	}
	for _, invalid := range []*UDPPacket{nil, {}, {SourcePort: 1, DestinationIP: netip.MustParseAddr("192.0.2.99"), DestinationPort: 1}, {SourcePort: 1, DestinationIP: f.config.LocalIP}} {
		if err := server.Reply(ctx, invalid, nil); err == nil {
			t.Fatal("invalid reply tuple accepted")
		}
	}
	if len(f.writes) != 0 || server.Err() != nil {
		t.Fatal("invalid requests injected traffic or closed server")
	}
}

// TestUDPCaptureServerConcurrentReplies guards against changing shared source
// ports while another goroutine serializes or injects its response.
func TestUDPCaptureServerConcurrentReplies(t *testing.T) {
	f := newUDPFixture(t)
	server := openCaptureServer(t, f, []byte("M"))
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var workers sync.WaitGroup
	failures := make(chan error, 16)
	for i := uint16(1); i <= 16; i++ {
		workers.Go(func() {
			request := &UDPPacket{SourceIP: netip.MustParseAddr("192.0.2.1"), SourcePort: 45000, DestinationIP: f.config.LocalIP, DestinationPort: i}
			body := binary.BigEndian.AppendUint16(nil, i)
			failures <- server.Reply(ctx, request, body)
		})
	}
	workers.Wait()
	for i := 0; i < 16; i++ {
		if err := <-failures; err != nil {
			t.Fatal(err)
		}
		packet, err := ParseUDPPacket(<-f.writes)
		if err != nil || len(packet.Payload) != 3 || packet.Payload[0] != 'M' || binary.BigEndian.Uint16(packet.Payload[1:]) != packet.SourcePort {
			t.Fatalf("crossed reply ports: %+v %v", packet, err)
		}
	}
}

func TestUDPCaptureServerLifecycle(t *testing.T) {
	t.Run("close", func(t *testing.T) {
		f := newUDPFixture(t)
		server := openCaptureServer(t, f, []byte("M"))
		done := make(chan error, 1)
		go func() { _, err := server.Receive(context.Background()); done <- err }()
		server.Close()
		if err := awaitError(t, done); !errors.Is(err, net.ErrClosed) {
			t.Fatal(err)
		}
		if server.Close() != nil || f.capture.closed.Load() != 1 {
			t.Fatal("capture handle not released exactly once")
		}
	})
	t.Run("terminal failure", func(t *testing.T) {
		f := newUDPFixture(t)
		server := openCaptureServer(t, f, []byte("M"))
		f.events <- udpEvent{frame: captureResult{err: io.ErrUnexpectedEOF}}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if _, err := server.Receive(ctx); !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatal(err)
		}
		if err := server.Close(); !errors.Is(err, io.ErrUnexpectedEOF) || f.capture.closed.Load() != 1 {
			t.Fatalf("cleanup: %v", err)
		}
	})
	t.Run("empty prefix", func(t *testing.T) {
		f := newUDPFixture(t)
		if _, err := newUDPCaptureServer(context.Background(), UDPCaptureConfig{LocalIP: f.config.LocalIP}, f.ops); err == nil {
			t.Fatal("empty header accepted")
		}
	})
	t.Run("canceled operations", func(t *testing.T) {
		f := newUDPFixture(t)
		server := openCaptureServer(t, f, []byte("M"))
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := server.Receive(ctx); !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
		if err := server.Reply(ctx, nil, nil); !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	})
}

// TestUDPCaptureServerEthernetEcho verifies replies accepted by DialUDP across
// several destination ports using real serialization and compiled native BPF.
func TestUDPCaptureServerEthernetEcho(t *testing.T) {
	for _, port := range []uint16{1, 45001, 65535} {
		t.Run(fmt.Sprint(port), func(t *testing.T) {
			leftMAC, rightMAC := net.HardwareAddr{2, 0, 0, 0, 0, 1}, net.HardwareAddr{2, 0, 0, 0, 0, 2}
			left := &ethernetCapture{inbound: make(chan []byte, 16), local: leftMAC, remote: rightMAC, done: make(chan struct{})}
			right := &ethernetCapture{inbound: make(chan []byte, 16), local: rightMAC, remote: leftMAC, done: make(chan struct{})}
			left.peer, right.peer = right, left
			local, remote := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")
			lc := PCAPConfig{DeviceName: "left", LocalPort: 45000, Peer: netip.AddrPortFrom(remote, port)}
			rc := PCAPConfig{DeviceName: "right", LocalPort: port, Peer: netip.AddrPortFrom(local, 45000)}
			leftOps := udpSetupOps{pcapSetupOps: ethernetSetup(t, lc, local, left, &fakeReservation{})}
			rightOps := udpSetupOps{pcapSetupOps: ethernetSetup(t, rc, remote, right, &fakeReservation{}), interfaceForIP: func(netip.Addr) (*net.Interface, error) {
				return &net.Interface{Name: "right", HardwareAddr: rightMAC, MTU: 1500}, nil
			}}
			magic := []byte{0, 0xff, 'M'}
			server, err := newUDPCaptureServer(context.Background(), UDPCaptureConfig{LocalIP: remote, MagicHeader: magic}, rightOps)
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			client, err := newUDPConn(ctx, UDPConfig{LocalPort: 45000, MagicHeader: magic}, lc.Peer, leftOps)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			client.SetDeadline(time.Now().Add(3 * time.Second))
			if _, err := client.Write([]byte("hello")); err != nil {
				t.Fatal(err)
			}
			request, err := server.Receive(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if err := server.Reply(ctx, request, request.Payload); err != nil {
				t.Fatal(err)
			}
			reply := make([]byte, 32)
			n, err := client.Read(reply)
			if err != nil || string(reply[:n]) != "hello" {
				t.Fatalf("echo: %q %v", reply[:n], err)
			}
		})
	}
}
