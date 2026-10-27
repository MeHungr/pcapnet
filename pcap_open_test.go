package pcapnet

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/google/gopacket/pcap"
)

// TestCaptureOpenTypedNilRollback reproduces the native open failure that used
// to panic during cleanup. A typed nil is deliberately returned through the
// captureHandle interface, rather than the untyped nil used by older fakes.
func TestCaptureOpenTypedNilRollback(t *testing.T) {
	cause := errors.New("capture permission denied")
	cleanup := errors.New("reservation cleanup failed")
	failOpen := func(string, int32, bool, time.Duration) (captureHandle, error) {
		var handle *pcap.Handle
		return handle, cause
	}
	for _, mode := range []string{"tcp", "udp-dial", "udp-listen"} {
		for _, reserve := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/reserve_%t", mode, reserve), func(t *testing.T) {
				var err error
				var port *fakeReservation
				if mode == "tcp" {
					f := newSetupFixture(t)
					f.cfg.ReserveUDPPort = reserve
					f.ops.openCapture = failOpen
					port = f.port
					port.err = cleanup
					owned, openErr := preparePCAP(context.Background(), f.cfg, f.ops)
					err = openErr
					if owned != nil {
						t.Fatal("failed setup returned resources")
					}
				} else {
					f := newUDPFixture(t)
					f.config.ReserveUDPPort = reserve
					f.ops.openCapture = failOpen
					port = f.setup.port
					port.err = cleanup
					peer := netip.AddrPort{}
					if mode == "udp-dial" {
						peer = netip.MustParseAddrPort("192.0.2.1:40000")
					}
					conn, openErr := newUDPConn(context.Background(), f.config, peer, f.ops)
					err = openErr
					if conn != nil {
						t.Fatal("failed setup returned a connection")
					}
				}
				if !errors.Is(err, cause) {
					t.Fatalf("capture cause lost: %v", err)
				}
				wantCloses := 0
				if reserve {
					wantCloses = 1
				}
				if port.closes != wantCloses {
					t.Fatalf("reservation close count = %d, want %d", port.closes, wantCloses)
				}
				if errors.Is(err, cleanup) != reserve {
					t.Fatalf("incorrect cleanup cause: %v", err)
				}
			})
		}
	}
}

// TestLiveCaptureOpenerFailureReturnsNil checks the production adapter, using a
// deliberately nonexistent device so no working capture interface is opened.
// The underlying error may be device-not-found or insufficient privileges.
func TestLiveCaptureOpenerFailureReturnsNil(t *testing.T) {
	ops := livePCAPSetupOps()
	handle, err := ops.openCapture("pcapnet-regression-device-that-does-not-exist", captureSnaplen, false, captureTimeout)
	if err == nil {
		if handle != nil {
			handle.Close()
		}
		t.Fatal("nonexistent capture device unexpectedly opened")
	}
	if handle != nil {
		t.Fatalf("failed capture open returned a non-nil interface: %T", handle)
	}
}
