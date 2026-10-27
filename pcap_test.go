package pcapnet

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// fakeCapture records setup and release without opening a physical interface.
type fakeCapture struct {
	link      layers.LinkType
	filter    string
	filterErr error
	closes    int
}

func (f *fakeCapture) LinkType() layers.LinkType { return f.link }
func (f *fakeCapture) SetBPFFilter(filter string) error {
	f.filter = filter
	return f.filterErr
}
func (f *fakeCapture) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	return nil, gopacket.CaptureInfo{}, io.EOF
}
func (f *fakeCapture) WritePacketData([]byte) error { return nil }
func (f *fakeCapture) Close()                       { f.closes++ }

// fakeReservation records release and can simulate socket cleanup failures.
type fakeReservation struct {
	closes int
	err    error
}

func (f *fakeReservation) Close() error {
	f.closes++
	return f.err
}

// setupFixture supplies a route, device, capture handle, and port reservation.
// Its callbacks verify arguments so setup tests exercise resource wiring too.
type setupFixture struct {
	cfg     PCAPConfig
	ops     pcapSetupOps
	iface   *net.Interface
	source  net.IP
	mac     net.HardwareAddr
	capture *fakeCapture
	port    *fakeReservation
	nextHop net.IP
}

func newSetupFixture(t *testing.T) *setupFixture {
	t.Helper()
	f := &setupFixture{
		cfg:     PCAPConfig{DeviceName: "eth0", LocalPort: 6767, Peer: netip.MustParseAddrPort("192.0.2.1:40000"), ReserveUDPPort: true},
		iface:   &net.Interface{Name: "eth0", MTU: 1500, HardwareAddr: net.HardwareAddr{2, 1, 2, 3, 4, 5}},
		source:  net.ParseIP("192.0.2.2").To4(),
		mac:     net.HardwareAddr{2, 6, 7, 8, 9, 10},
		capture: &fakeCapture{link: layers.LinkTypeEthernet},
		port:    &fakeReservation{},
	}
	f.ops = pcapSetupOps{
		lookupRoute: func(peer net.IP) (*net.Interface, net.IP, net.IP, error) {
			if !peer.Equal(net.ParseIP("192.0.2.1")) {
				t.Errorf("unexpected route destination: %s", peer)
			}
			return f.iface, nil, f.source, nil
		},
		findDevices: func() ([]pcap.Interface, error) { return []pcap.Interface{{Name: "eth0"}}, nil },
		reservePort: func(_ context.Context, local netip.AddrPort) (io.Closer, error) {
			if local != netip.MustParseAddrPort("192.0.2.2:6767") {
				t.Errorf("unexpected reservation: %s", local)
			}
			return f.port, nil
		},
		openCapture: func(name string, snaplen int32, promisc bool, timeout time.Duration) (captureHandle, error) {
			if name != "eth0" || snaplen != captureSnaplen || promisc || timeout != captureTimeout {
				t.Errorf("unexpected capture arguments: %s %d %t %s", name, snaplen, promisc, timeout)
			}
			return f.capture, nil
		},
		resolveARP: func(ctx context.Context, device *pcap.Interface, mac net.HardwareAddr, source, nextHop net.IP) (net.HardwareAddr, error) {
			if device.Name != "eth0" || !source.Equal(f.source) || mac.String() != f.iface.HardwareAddr.String() {
				t.Error("ARP did not use selected device and route source")
			}
			if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > arpTimeout {
				t.Error("ARP resolution has no bounded deadline")
			}
			f.nextHop = append(net.IP(nil), nextHop...)
			return f.mac, nil
		},
	}
	return f
}

// TestPreparePCAP verifies direct and gateway routes, independent address
// ownership, and concurrent idempotent resource release.
func TestPreparePCAP(t *testing.T) {
	for _, routed := range []bool{false, true} {
		name := "direct"
		if routed {
			name = "gateway"
		}
		t.Run(name, func(t *testing.T) {
			f := newSetupFixture(t)
			wantHop := net.ParseIP("192.0.2.1")
			if routed {
				wantHop = net.ParseIP("192.0.2.254")
				f.ops.lookupRoute = func(net.IP) (*net.Interface, net.IP, net.IP, error) {
					return f.iface, wantHop, f.source, nil
				}
			}
			p, err := preparePCAP(context.Background(), f.cfg, f.ops)
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			if !f.nextHop.Equal(wantHop) {
				t.Errorf("ARP next hop = %s, want %s", f.nextHop, wantHop)
			}
			if p.config.MTU != DefaultMTU {
				t.Errorf("MTU = %d", p.config.MTU)
			}
			if f.capture.filter == "" {
				t.Error("capture filter was not installed")
			}

			// Caller-owned route and ARP buffers must not change stored headers.
			f.iface.HardwareAddr[0] = 4
			f.mac[0] = 4
			if p.srcMAC[0] != 2 || p.dstMAC[0] != 2 {
				t.Error("MAC addresses were not copied")
			}
			var wg sync.WaitGroup
			for i := 0; i < 8; i++ {
				wg.Add(1)
				go func() { defer wg.Done(); _ = p.Close() }()
			}
			wg.Wait()
			if f.capture.closes != 1 || f.port.closes != 1 {
				t.Error("resources were not closed exactly once")
			}
		})
	}
}

// TestPreparePCAPFailures checks that each setup failure closes all resources
// acquired so far and preserves the original error for errors.Is callers.
func TestPreparePCAPFailures(t *testing.T) {
	failure := errors.New("injected setup failure")
	tests := []struct {
		name                      string
		change                    func(*setupFixture)
		portCloses, captureCloses int
		wantCause                 bool
	}{
		{name: "invalid config", change: func(f *setupFixture) { f.cfg.LocalPort = 0 }},
		{name: "route error", change: func(f *setupFixture) {
			f.ops.lookupRoute = func(net.IP) (*net.Interface, net.IP, net.IP, error) { return nil, nil, nil, failure }
		}, wantCause: true},
		{name: "missing route interface", change: func(f *setupFixture) { f.iface = nil }},
		{name: "invalid source", change: func(f *setupFixture) { f.source = nil }},
		{name: "non Ethernet route", change: func(f *setupFixture) { f.iface.HardwareAddr = nil }},
		{name: "invalid route MTU", change: func(f *setupFixture) { f.iface.MTU = 0 }},
		{name: "inner MTU exceeds route", change: func(f *setupFixture) { f.cfg.MTU = 1473 }},
		{name: "device enumeration", change: func(f *setupFixture) { f.ops.findDevices = func() ([]pcap.Interface, error) { return nil, failure } }, wantCause: true},
		{name: "missing device", change: func(f *setupFixture) { f.cfg.DeviceName = "other" }},
		{name: "wrong route device", change: func(f *setupFixture) { f.iface.Name = "other" }},
		{name: "port collision", change: func(f *setupFixture) {
			f.ops.reservePort = func(context.Context, netip.AddrPort) (io.Closer, error) { return nil, failure }
		}, wantCause: true},
		{name: "capture open", change: func(f *setupFixture) {
			f.ops.openCapture = func(string, int32, bool, time.Duration) (captureHandle, error) { return nil, failure }
		}, portCloses: 1, wantCause: true},
		{name: "non Ethernet capture", change: func(f *setupFixture) { f.capture.link = layers.LinkTypeRaw }, portCloses: 1, captureCloses: 1},
		{name: "filter failure", change: func(f *setupFixture) { f.capture.filterErr = failure }, portCloses: 1, captureCloses: 1, wantCause: true},
		{name: "IPv6 gateway", change: func(f *setupFixture) {
			f.ops.lookupRoute = func(net.IP) (*net.Interface, net.IP, net.IP, error) {
				return f.iface, net.ParseIP("2001:db8::1"), f.source, nil
			}
		}, portCloses: 1, captureCloses: 1},
		{name: "ARP failure", change: func(f *setupFixture) {
			f.ops.resolveARP = func(context.Context, *pcap.Interface, net.HardwareAddr, net.IP, net.IP) (net.HardwareAddr, error) {
				return nil, failure
			}
		}, portCloses: 1, captureCloses: 1, wantCause: true},
		{name: "invalid ARP MAC", change: func(f *setupFixture) { f.mac = nil }, portCloses: 1, captureCloses: 1},
		{name: "multicast ARP MAC", change: func(f *setupFixture) { f.mac[0] = 1 }, portCloses: 1, captureCloses: 1},
		{name: "zero ARP MAC", change: func(f *setupFixture) { f.mac = make(net.HardwareAddr, 6) }, portCloses: 1, captureCloses: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newSetupFixture(t)
			tt.change(f)
			p, err := preparePCAP(context.Background(), f.cfg, f.ops)
			if err == nil || p != nil {
				t.Fatalf("preparePCAP() = %v, %v; want failure", p, err)
			}
			if tt.wantCause && !errors.Is(err, failure) {
				t.Errorf("original cause lost: %v", err)
			}
			if f.port.closes != tt.portCloses || f.capture.closes != tt.captureCloses {
				t.Errorf("close counts port/capture = %d/%d, want %d/%d", f.port.closes, f.capture.closes, tt.portCloses, tt.captureCloses)
			}
		})
	}
}

// TestPreparePCAPCancellation verifies rejection before resource acquisition,
// rollback after cancellation during ARP, and preservation of cleanup errors.
func TestPreparePCAPCancellation(t *testing.T) {
	f := newSetupFixture(t)
	if _, err := preparePCAP(nil, f.cfg, f.ops); err == nil {
		t.Fatal("nil context accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := preparePCAP(ctx, f.cfg, f.ops); !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v", err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	cleanupErr := errors.New("reservation close failed")
	f.port.err = cleanupErr
	f.ops.resolveARP = func(context.Context, *pcap.Interface, net.HardwareAddr, net.IP, net.IP) (net.HardwareAddr, error) {
		cancel()
		return f.mac, nil
	}
	if _, err := preparePCAP(ctx, f.cfg, f.ops); !errors.Is(err, context.Canceled) || !errors.Is(err, cleanupErr) {
		t.Fatalf("cancellation or cleanup error lost: %v", err)
	}
	if f.port.closes != 1 || f.capture.closes != 1 {
		t.Fatal("canceled setup leaked resources")
	}
}

// TestMatchCaptureDevice checks Npcap-style names matched by the route source.
func TestMatchCaptureDevice(t *testing.T) {
	iface := &net.Interface{Name: "Ethernet"}
	source := net.ParseIP("192.0.2.2")
	device := pcap.Interface{Name: "capture-path", Addresses: []pcap.InterfaceAddress{{IP: source}}}
	if _, err := matchCaptureDevice(device.Name, []pcap.Interface{device}, iface, source); err != nil {
		t.Fatal(err)
	}
	device.Addresses = nil
	if _, err := matchCaptureDevice(device.Name, []pcap.Interface{device}, iface, source); err == nil {
		t.Fatal("unrelated device accepted")
	}
}

// TestTunnelBPFFilter compiles the actual filter through libpcap and checks
// inbound tuple matching for untagged, 802.1Q, and 802.1ad/Q-in-Q captures.
func TestTunnelBPFFilter(t *testing.T) {
	filter, err := pcap.NewBPF(layers.LinkTypeEthernet, captureSnaplen, tunnelBPFFilter(
		netip.MustParseAddrPort("192.0.2.2:6767"), netip.MustParseAddrPort("192.0.2.1:40000")))
	if err != nil {
		t.Fatal(err)
	}
	frame := makeTestUDPFrame(t, []byte("filter test"))
	for _, tags := range []int{0, 1, 2} {
		tagged := append([]byte(nil), frame...)
		for i := 0; i < tags; i++ {
			// Insert VLAN TCI followed by the original EtherType and payload.
			tagged = append(append(append([]byte(nil), tagged[:12]...), 0x81, 0, 0, 1), tagged[12:]...)
		}
		if tags == 2 {
			tagged[12], tagged[13] = 0x88, 0xa8
		}
		ci := gopacket.CaptureInfo{CaptureLength: len(tagged), Length: len(tagged)}
		if !filter.Matches(ci, tagged) {
			t.Errorf("valid frame with %d tags rejected", tags)
		}
		// Every component of the tuple must match, even behind VLAN tags.
		// Checksums need not be repaired because BPF only examines headers.
		ipStart := ethernetHeaderSize + 4*tags
		for _, offset := range []int{12, 16, 20, 22} {
			wrong := append([]byte(nil), tagged...)
			wrong[ipStart+offset] ^= 1
			if filter.Matches(ci, wrong) {
				t.Errorf("wrong tuple at offset %d with %d tags accepted", offset, tags)
			}
		}
	}
}

// TestReserveUDPPort uses a loopback socket, without sending any packets, to
// verify that the reservation prevents collisions and releases the endpoint.
func TestReserveUDPPort(t *testing.T) {
	ctx := context.Background()
	port, err := reserveUDPPort(ctx, netip.MustParseAddrPort("127.0.0.1:0"))
	if err != nil {
		// Restricted build environments may forbid even loopback sockets.
		// Keep all other bind failures visible rather than skipping real bugs.
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
			t.Skipf("environment prohibits UDP sockets: %v", err)
		}
		t.Fatal(err)
	}
	defer port.Close()
	local := port.(net.PacketConn).LocalAddr().(*net.UDPAddr).AddrPort()
	if local.Port() == 0 {
		t.Fatal("host did not allocate a UDP port")
	}
	other, err := reserveUDPPort(ctx, local)
	if err == nil {
		_ = other.Close()
		t.Fatal("reservation allowed a competing bind")
	}
	if err := port.Close(); err != nil {
		t.Fatal(err)
	}
	other, err = reserveUDPPort(ctx, local)
	if err != nil {
		t.Fatalf("released endpoint could not be reserved again: %v", err)
	}
	_ = other.Close()
}

// TestPCAPResourcesCloseError verifies that repeated closure returns the same
// error while releasing both the capture handle and port only once.
func TestPCAPResourcesCloseError(t *testing.T) {
	failure := errors.New("close reservation failed")
	f := newSetupFixture(t)
	f.port.err = failure
	p, err := preparePCAP(context.Background(), f.cfg, f.ops)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := p.Close(); !errors.Is(err, failure) {
			t.Fatalf("Close() = %v, want %v", err, failure)
		}
	}
	if f.port.closes != 1 || f.capture.closes != 1 {
		t.Fatal("resources were not released exactly once")
	}
}

// TestPreparePCAPWithoutReservation verifies the default avoids host sockets
// entirely, including when later capture setup fails and cleanup runs.
func TestPreparePCAPWithoutReservation(t *testing.T) {
	for _, failCapture := range []bool{false, true} {
		name := "success"
		if failCapture {
			name = "capture failure"
		}
		t.Run(name, func(t *testing.T) {
			f := newSetupFixture(t)
			f.cfg.ReserveUDPPort = false
			f.ops.reservePort = func(context.Context, netip.AddrPort) (io.Closer, error) {
				t.Fatal("unrequested UDP reservation attempted")
				return nil, nil
			}
			if failCapture {
				f.capture.filterErr = errors.New("filter failed")
			}
			p, err := preparePCAP(context.Background(), f.cfg, f.ops)
			if failCapture {
				if err == nil || p != nil {
					t.Fatal("capture failure was ignored")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if p.port != nil {
					t.Error("unexpected socket reservation")
				}
				if err := p.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if f.capture.closes != 1 || f.port.closes != 0 {
				t.Errorf("close counts capture/port = %d/%d", f.capture.closes, f.port.closes)
			}
		})
	}
}
