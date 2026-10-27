package pcapnet

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

// TestUDPMagicFraming exercises wire framing in both connection modes. The
// header never appears in application byte counts and caller buffers stay owned
// by the caller, including spare capacity that append could otherwise overwrite.
func TestUDPMagicFraming(t *testing.T) {
	for _, connected := range []bool{true, false} {
		name := "listener"
		if connected {
			name = "connected"
		}
		t.Run(name, func(t *testing.T) {
			f := newUDPFixture(t)
			header := []byte("0123456789abcdef\x00\xff")
			f.config.MagicHeader = bytes.Clone(header)
			c := f.open(t, connected)
			f.config.MagicHeader[0] ^= 1
			if got := c.MaxDatagramSize(); got != 1472-len(header) {
				t.Fatalf("capacity: %d", got)
			}
			endpoint, err := NewPlainUDPEndpoint(c)
			if err != nil {
				t.Fatal(err)
			}
			if endpoint.MaxDatagramSize() != c.MaxDatagramSize() {
				t.Fatal("adapter ignored framing overhead")
			}
			for _, size := range []int{0, 1, c.MaxDatagramSize()} {
				storage := bytes.Repeat([]byte{0x55}, size+len(header)+1)
				original := bytes.Clone(storage)
				body := storage[:size]
				var n int
				var err error
				if connected {
					n, err = c.Write(body)
				} else {
					n, err = c.WriteTo(body, net.UDPAddrFromAddrPort(netip.MustParseAddrPort("192.0.2.1:40000")))
				}
				if n != size || err != nil {
					t.Fatalf("write %d: %d, %v", size, n, err)
				}
				if !bytes.Equal(storage, original) {
					t.Fatal("write modified caller buffer")
				}
				packet, err := ParseUDPPacket(<-f.writes)
				want := append(bytes.Clone(header), body...)
				if err != nil || !bytes.Equal(packet.Payload, want) {
					t.Fatalf("wire payload: %+v, %v", packet, err)
				}
				f.feed(makeTestUDPFrame(t, want))
				_ = c.SetReadDeadline(time.Now().Add(time.Second))
				buffer := make([]byte, size)
				n, addr, err := c.ReadFrom(buffer)
				if err != nil || n != size || !bytes.Equal(buffer, body) || addr.String() != "192.0.2.1:40000" {
					t.Fatalf("read %d: %d, %v, %v", size, n, addr, err)
				}
			}
			oversized := make([]byte, c.MaxDatagramSize()+1)
			if connected {
				_, err = c.Write(oversized)
			} else {
				_, err = c.WriteTo(oversized, net.UDPAddrFromAddrPort(netip.MustParseAddrPort("192.0.2.1:40000")))
			}
			if !errors.Is(err, ErrDatagramTooLarge) || c.Err() != nil || len(f.writes) != 0 {
				t.Fatalf("oversized write: %v", err)
			}
			// Wrong/short/interior prefixes are ignored, including a mismatch beyond
			// the first 16 bytes. A subsequent correct datagram remains readable.
			for _, body := range [][]byte{header[:17], append([]byte("x"), header...), append(bytes.Clone(header[:17]), 0)} {
				f.feed(makeTestUDPFrame(t, body))
			}
			f.feed(makeTestUDPFrame(t, append(bytes.Clone(header), []byte("abc")...)))
			buffer := make([]byte, 2)
			if n, err := c.Read(buffer); n != 2 || err != nil || string(buffer) != "ab" {
				t.Fatalf("filtered/truncated read: %d %q %v", n, buffer, err)
			}
			f.feed(makeTestUDPFrame(t, header))
			if n, err := c.Read(buffer); n != 0 || err != nil {
				t.Fatalf("header-only read: %d %v", n, err)
			}
		})
	}
}

// TestUDPMagicHeaderMTU rejects impossible framing before opening resources,
// while allowing a header-only datagram when the header exactly fills the MTU.
func TestUDPMagicHeaderMTU(t *testing.T) {
	f := newUDPFixture(t)
	f.config.MTU = 32
	f.config.MagicHeader = make([]byte, 5)
	if _, err := newUDPConn(context.Background(), f.config, netip.AddrPort{}, f.ops); err == nil {
		t.Fatal("oversized magic accepted")
	}
	if f.capture.closed.Load() != 0 {
		t.Fatal("acquired capture before validating header")
	}
	f.config.MagicHeader = make([]byte, 4)
	c := f.open(t, true)
	if c.MaxDatagramSize() != 0 {
		t.Fatal("header-only capacity")
	}
	if n, err := c.Write(nil); n != 0 || err != nil {
		t.Fatalf("header-only write: %d %v", n, err)
	}
	if packet, err := ParseUDPPacket(<-f.writes); err != nil || len(packet.Payload) != 4 {
		t.Fatalf("header-only frame: %+v %v", packet, err)
	}
}
