package pcapnet

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/google/gopacket/pcap"
)

// TestAutomaticCaptureDeviceSelection checks name priority, address fallback,
// ambiguity, and explicit overrides independently of native route/capture APIs.
func TestAutomaticCaptureDeviceSelection(t *testing.T) {
	source := net.ParseIP("192.0.2.2")
	addressDevice := func(name string) pcap.Interface {
		return pcap.Interface{Name: name, Addresses: []pcap.InterfaceAddress{{IP: source}, {IP: source}}}
	}
	tests := []struct {
		name, explicit, want string
		devices              []pcap.Interface
		wantErr              bool
	}{
		{name: "interface name", devices: []pcap.Interface{{Name: "other"}, {Name: "eth0"}}, want: "eth0"},
		{name: "address fallback", devices: []pcap.Interface{addressDevice("capture-path")}, want: "capture-path"},
		{name: "name before addresses", devices: []pcap.Interface{addressDevice("capture-a"), addressDevice("capture-b"), {Name: "eth0"}}, want: "eth0"},
		{name: "ambiguous addresses", devices: []pcap.Interface{addressDevice("capture-a"), addressDevice("capture-b")}, wantErr: true},
		{name: "ambiguous names", devices: []pcap.Interface{{Name: "eth0"}, {Name: "eth0"}}, wantErr: true},
		{name: "empty list", wantErr: true},
		{name: "unrelated address", devices: []pcap.Interface{{Name: "other", Addresses: []pcap.InterfaceAddress{{IP: net.ParseIP("192.0.2.3")}}}}, wantErr: true},
		{name: "unnamed device", devices: []pcap.Interface{addressDevice("")}, wantErr: true},
		{name: "explicit resolves ambiguity", explicit: "capture-b", devices: []pcap.Interface{addressDevice("capture-a"), addressDevice("capture-b")}, want: "capture-b"},
		{name: "explicit override before name", explicit: "capture-path", devices: []pcap.Interface{{Name: "eth0"}, addressDevice("capture-path")}, want: "capture-path"},
		{name: "explicit unknown does not fall back", explicit: "missing", devices: []pcap.Interface{{Name: "eth0"}}, wantErr: true},
		{name: "explicit mismatch does not fall back", explicit: "other", devices: []pcap.Interface{{Name: "other"}, {Name: "eth0"}}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			device, err := matchCaptureDevice(tt.explicit, tt.devices, &net.Interface{Name: "eth0"}, source)
			if (err != nil) != tt.wantErr {
				t.Fatalf("selection error = %v, wantErr %t", err, tt.wantErr)
			}
			if !tt.wantErr && (device == nil || device.Name != tt.want) {
				t.Fatalf("device = %v, want %s", device, tt.want)
			}
		})
	}
}

// TestPCAPAutomaticDeviceSetup checks the actual tunnel setup uses and retains
// the selected capture name for opening PCAP and resolving ARP.
func TestPCAPAutomaticDeviceSetup(t *testing.T) {
	for _, addressMatch := range []bool{false, true} {
		t.Run(fmt.Sprint(addressMatch), func(t *testing.T) {
			f := newSetupFixture(t)
			f.cfg.DeviceName = ""
			want := "eth0"
			if addressMatch {
				want = "capture-path"
			}
			f.ops.findDevices = func() ([]pcap.Interface, error) {
				return []pcap.Interface{{Name: want, Addresses: []pcap.InterfaceAddress{{IP: f.source}}}}, nil
			}
			f.ops.openCapture = func(name string, _ int32, _ bool, _ time.Duration) (captureHandle, error) {
				if name != want {
					t.Errorf("opened %q, want %q", name, want)
				}
				return f.capture, nil
			}
			f.ops.resolveARP = func(_ context.Context, device *pcap.Interface, _ net.HardwareAddr, _ net.IP, _ net.IP) (net.HardwareAddr, error) {
				if device.Name != want {
					t.Errorf("ARP device = %q, want %q", device.Name, want)
				}
				return f.mac, nil
			}
			owned, err := preparePCAP(context.Background(), f.cfg, f.ops)
			if err != nil {
				t.Fatal(err)
			}
			defer owned.Close()
			if owned.config.DeviceName != want {
				t.Fatal("resolved capture name was not retained")
			}
		})
	}
}

// TestUDPAutomaticDeviceSetup covers dial route selection and listener address
// ownership. A listener's later WriteTo must use the resolved name for ARP.
func TestUDPAutomaticDeviceSetup(t *testing.T) {
	for _, connected := range []bool{false, true} {
		for _, addressMatch := range []bool{false, true} {
			t.Run(fmt.Sprintf("dial_%t_address_%t", connected, addressMatch), func(t *testing.T) {
				f := newUDPFixture(t)
				f.config.DeviceName = ""
				want := "eth0"
				if addressMatch {
					want = "capture-path"
				}
				f.ops.findDevices = func() ([]pcap.Interface, error) {
					return []pcap.Interface{{Name: want, Addresses: []pcap.InterfaceAddress{{IP: f.setup.source}}}}, nil
				}
				f.ops.interfaceForIP = func(ip netip.Addr) (*net.Interface, error) {
					if ip != f.config.LocalIP {
						t.Errorf("interface lookup IP = %s", ip)
					}
					return f.setup.iface, nil
				}
				f.ops.openCapture = func(name string, _ int32, _ bool, _ time.Duration) (captureHandle, error) {
					if name != want {
						t.Errorf("opened %q, want %q", name, want)
					}
					return f.capture, nil
				}
				arpCalled := false
				f.ops.resolveARP = func(_ context.Context, device *pcap.Interface, _ net.HardwareAddr, _ net.IP, _ net.IP) (net.HardwareAddr, error) {
					arpCalled = true
					if device.Name != want {
						t.Errorf("ARP device = %q, want %q", device.Name, want)
					}
					return f.setup.mac, nil
				}
				if connected {
					f.config.LocalIP = netip.Addr{}
				}
				c := f.open(t, connected)
				if c.config.DeviceName != want {
					t.Fatal("resolved capture name was not retained")
				}
				if !connected {
					if _, err := c.WriteTo(nil, &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 40000}); err != nil {
						t.Fatal(err)
					}
				}
				if !arpCalled {
					t.Fatal("ARP was not exercised")
				}
			})
		}
	}
}

// TestAutomaticDeviceSelectionFailure checks failed discovery never opens PCAP
// or reserves a host UDP socket, for both protocols and both UDP endpoint modes.
func TestAutomaticDeviceSelectionFailure(t *testing.T) {
	for _, ambiguous := range []bool{false, true} {
		t.Run(fmt.Sprint(ambiguous), func(t *testing.T) {
			devices := []pcap.Interface{}
			if ambiguous {
				for _, name := range []string{"one", "two"} {
					devices = append(devices, pcap.Interface{Name: name, Addresses: []pcap.InterfaceAddress{{IP: net.ParseIP("192.0.2.2")}}})
				}
			}
			f := newSetupFixture(t)
			f.cfg.DeviceName = ""
			f.ops.findDevices = func() ([]pcap.Interface, error) { return devices, nil }
			f.ops.openCapture = func(string, int32, bool, time.Duration) (captureHandle, error) {
				t.Error("capture opened after failed selection")
				return f.capture, nil
			}
			if owned, err := preparePCAP(context.Background(), f.cfg, f.ops); err == nil {
				_ = owned.Close()
				t.Fatal("invalid selection accepted")
			}
			if f.port.closes != 0 {
				t.Fatal("reservation acquired before device selection")
			}
			for _, connected := range []bool{false, true} {
				u := newUDPFixture(t)
				u.config.DeviceName = ""
				u.config.ReserveUDPPort = true
				u.ops.findDevices = f.ops.findDevices
				u.ops.openCapture = f.ops.openCapture
				peer := netip.AddrPort{}
				if connected {
					peer = netip.MustParseAddrPort("192.0.2.1:40000")
				}
				if c, err := newUDPConn(context.Background(), u.config, peer, u.ops); err == nil {
					_ = c.Close()
					t.Fatal("invalid UDP selection accepted")
				}
				if u.setup.port.closes != 0 {
					t.Fatal("UDP reservation acquired before device selection")
				}
			}
		})
	}
}
