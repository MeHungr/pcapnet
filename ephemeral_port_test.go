package pcapnet

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
)

type addressedReservation struct {
	fakeReservation
	address *net.UDPAddr
}

func (r *addressedReservation) LocalAddr() net.Addr { return r.address }

func TestDialUDPEphemeral(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "lifetime", true: "rollback"}[fail], func(t *testing.T) {
			f := newUDPFixture(t)
			f.config.LocalPort = 0
			f.config.ReserveUDPPort = true
			r := &addressedReservation{address: net.UDPAddrFromAddrPort(netip.MustParseAddrPort("192.0.2.2:54321"))}
			calls := 0
			f.ops.reservePort = func(_ context.Context, local netip.AddrPort) (io.Closer, error) {
				calls++
				if local.String() != "192.0.2.2:0" {
					t.Fatalf("reservation requested %s", local)
				}
				return r, nil
			}
			failure := errors.New("capture setup failed")
			if fail {
				f.capture.filterErr = failure
			}
			c, err := newUDPConn(context.Background(), f.config, netip.MustParseAddrPort("192.0.2.1:40000"), f.ops)
			if calls != 1 {
				t.Fatalf("reservation calls %d", calls)
			}
			if fail {
				if !errors.Is(err, failure) || r.closes != 1 {
					t.Fatalf("rollback: %v, closes %d", err, r.closes)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			if c.LocalAddr().String() != "192.0.2.2:54321" || c.config.LocalPort != 54321 || r.closes != 0 {
				t.Fatal("allocated address or ownership mismatch")
			}
			if !strings.Contains(f.capture.filter, "54321") {
				t.Fatalf("filter: %s", f.capture.filter)
			}
			if _, err := c.Write([]byte("test")); err != nil {
				t.Fatal(err)
			}
			packet, err := ParseUDPPacket(<-f.writes)
			if err != nil || packet.SourcePort != 54321 {
				t.Fatalf("wire source: %+v, %v", packet, err)
			}
			if err := c.Close(); err != nil {
				t.Fatal(err)
			}
			if r.closes != 1 {
				t.Fatalf("reservation closes %d", r.closes)
			}
		})
	}
}

func TestDialUDPEphemeralReservationFailure(t *testing.T) {
	for _, malformed := range []bool{false, true} {
		f := newUDPFixture(t)
		f.config.LocalPort = 0
		f.config.ReserveUDPPort = true
		failure := errors.New("bind failed")
		r := &addressedReservation{address: net.UDPAddrFromAddrPort(netip.MustParseAddrPort("192.0.2.2:0"))}
		f.ops.reservePort = func(context.Context, netip.AddrPort) (io.Closer, error) {
			if malformed {
				return r, nil
			}
			return nil, failure
		}
		c, err := newUDPConn(context.Background(), f.config, netip.MustParseAddrPort("192.0.2.1:40000"), f.ops)
		if c != nil || err == nil {
			t.Fatal("invalid reservation accepted")
		}
		if malformed && r.closes != 1 {
			t.Fatal("invalid reservation leaked")
		}
		if !malformed && !errors.Is(err, failure) {
			t.Fatal(err)
		}
	}
}

func TestDialUDPDynamicWithoutReservation(t *testing.T) {
	f := newUDPFixture(t)
	f.config.LocalPort = 0
	f.config.ReserveUDPPort = false
	f.ops.reservePort = func(context.Context, netip.AddrPort) (io.Closer, error) {
		t.Fatal("unreserved dynamic port opened a reservation socket")
		return nil, nil
	}
	c := f.open(t, true)
	address := c.LocalAddr().(*net.UDPAddr).AddrPort()
	if address.Port() < 49152 || address.Addr() != f.config.LocalIP || c.resources.port != nil {
		t.Fatalf("unexpected dynamic endpoint: %s", address)
	}
	if !strings.Contains(f.capture.filter, fmt.Sprint(address.Port())) {
		t.Fatal("capture filter uses wrong port")
	}
	if _, err := c.Write([]byte("test")); err != nil {
		t.Fatal(err)
	}
	packet, err := ParseUDPPacket(<-f.writes)
	if err != nil || packet.SourcePort != address.Port() {
		t.Fatalf("wire source: %+v, %v", packet, err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
}
