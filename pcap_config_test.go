package pcapnet

import (
	"net/netip"
	"testing"
)

// TestPCAPConfigNormalize checks tunnel settings without opening a device.
// Each case starts from a valid configuration so failures identify one rule.
func TestPCAPConfigNormalize(t *testing.T) {
	tests := []struct {
		name    string
		change  func(*PCAPConfig)
		wantMTU uint32
		wantErr bool
	}{
		{name: "valid configuration", wantMTU: 1400},
		{name: "UDP reservation enabled", change: func(c *PCAPConfig) { c.ReserveUDPPort = true }, wantMTU: 1400},
		{name: "default MTU", change: func(c *PCAPConfig) { c.MTU = 0 }, wantMTU: DefaultMTU},
		{name: "minimum MTU", change: func(c *PCAPConfig) { c.MTU = MinIPv4MTU }, wantMTU: MinIPv4MTU},
		{name: "maximum MTU", change: func(c *PCAPConfig) { c.MTU = maxUDPInnerMTU }, wantMTU: maxUDPInnerMTU},
		{name: "automatic device", change: func(c *PCAPConfig) { c.DeviceName = "" }, wantMTU: 1400},
		{name: "blank device", change: func(c *PCAPConfig) { c.DeviceName = " \t" }, wantErr: true},
		{name: "zero local port", change: func(c *PCAPConfig) { c.LocalPort = 0 }, wantErr: true},
		{name: "missing peer", change: func(c *PCAPConfig) { c.Peer = netip.AddrPort{} }, wantErr: true},
		{name: "MTU too small", change: func(c *PCAPConfig) { c.MTU = MinIPv4MTU - 1 }, wantErr: true},
		{name: "MTU too large", change: func(c *PCAPConfig) { c.MTU = maxUDPInnerMTU + 1 }, wantErr: true},
		{name: "zero peer port", change: func(c *PCAPConfig) { c.Peer = netip.MustParseAddrPort("192.0.2.2:0") }, wantErr: true},
		{name: "IPv6 peer", change: func(c *PCAPConfig) { c.Peer = netip.MustParseAddrPort("[2001:db8::2]:9000") }, wantErr: true},
		{name: "mapped IPv6 peer", change: func(c *PCAPConfig) { c.Peer = netip.MustParseAddrPort("[::ffff:192.0.2.2]:9000") }, wantErr: true},
		{name: "unspecified peer", change: func(c *PCAPConfig) { c.Peer = netip.MustParseAddrPort("0.0.0.0:9000") }, wantErr: true},
		{name: "multicast peer", change: func(c *PCAPConfig) { c.Peer = netip.MustParseAddrPort("224.0.0.1:9000") }, wantErr: true},
		{name: "loopback peer", change: func(c *PCAPConfig) { c.Peer = netip.MustParseAddrPort("127.0.0.1:9000") }, wantErr: true},
		{name: "broadcast peer", change: func(c *PCAPConfig) { c.Peer = netip.MustParseAddrPort("255.255.255.255:9000") }, wantErr: true},
		{name: "maximum ports", change: func(c *PCAPConfig) {
			c.LocalPort = 65535
			c.Peer = netip.MustParseAddrPort("192.0.2.2:65535")
		}, wantMTU: 1400},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := PCAPConfig{
				DeviceName: "eth0",
				LocalPort:  8000,
				Peer:       netip.MustParseAddrPort("192.0.2.2:9000"),
				MTU:        1400,
			}
			if tt.change != nil {
				tt.change(&cfg)
			}

			got, err := cfg.normalize()
			if (err != nil) != tt.wantErr {
				t.Fatalf("normalize() error = %v, wantErr = %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}

			// Only the default MTU may change during normalization.
			want := cfg
			want.MTU = tt.wantMTU
			if got != want {
				t.Errorf("normalize() = %+v, want %+v", got, want)
			}
			if again, err := got.normalize(); err != nil || again != got {
				t.Errorf("normalization is not idempotent: %+v, %v", again, err)
			}
		})
	}
}
