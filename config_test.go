package pcapnet

import (
	"net/netip"
	"testing"
)

// TestConfigNormalize tests that a config is properly created and normalized
func TestConfigNormalize(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantMTU uint32
		wantErr bool
	}{
		{
			name: "valid configuration",
			config: Config{
				VirtualIP:  netip.MustParseAddr("10.200.0.1"),
				PeerSubnet: netip.MustParsePrefix("10.200.0.2/32"),
				MTU:        1400,
			},
			wantMTU: 1400,
		},
		{
			name: "default MTU",
			config: Config{
				VirtualIP:  netip.MustParseAddr("10.200.0.1"),
				PeerSubnet: netip.MustParsePrefix("10.200.0.2/32"),
			},
			wantMTU: DefaultMTU,
		},
		{
			name: "missing virtual IP",
			config: Config{
				PeerSubnet: netip.MustParsePrefix("10.200.0.2/32"),
			},
			wantErr: true,
		},
		{
			name: "IPv6 rejected",
			config: Config{
				VirtualIP:  netip.MustParseAddr("2001:db8::1"),
				PeerSubnet: netip.MustParsePrefix("10.200.0.2/32"),
			},
			wantErr: true,
		},
		{
			name: "loopback rejected",
			config: Config{
				VirtualIP:  netip.MustParseAddr("127.0.0.1"),
				PeerSubnet: netip.MustParsePrefix("10.200.0.2/32"),
			},
			wantErr: true,
		},
		{
			name: "duplicate virtual IP",
			config: Config{
				VirtualIP:  netip.MustParseAddr("10.200.0.1"),
				PeerSubnet: netip.MustParsePrefix("10.200.0.1/32"),
			},
			wantErr: true,
		},
		{
			name: "MTU too small",
			config: Config{
				VirtualIP:  netip.MustParseAddr("10.200.0.1"),
				PeerSubnet: netip.MustParsePrefix("10.200.0.2/32"),
				MTU:        500,
			},
			wantErr: true,
		},
		{
			name: "MTU too large",
			config: Config{
				VirtualIP:  netip.MustParseAddr("10.200.0.1"),
				PeerSubnet: netip.MustParsePrefix("10.200.0.2/32"),
				MTU:        70000,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.config.normalize()

			if (err != nil) != tt.wantErr {
				t.Fatalf(
					"normalize() error = %v, wantErr = %v",
					err,
					tt.wantErr,
				)
			}

			if tt.wantErr {
				return
			}

			if got.MTU != tt.wantMTU {
				t.Errorf(
					"MTU = %d, want %d",
					got.MTU,
					tt.wantMTU,
				)
			}

			if got.VirtualIP != tt.config.VirtualIP {
				t.Errorf("virtual IP unexpectedly changed")
			}

			if got.PeerSubnet != tt.config.PeerSubnet {
				t.Errorf("peer virtual IP unexpectedly changed")
			}
		})
	}
}
