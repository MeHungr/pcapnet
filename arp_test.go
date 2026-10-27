package pcapnet

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/google/gopacket/pcap"
)

// TestResolveARPValidation verifies that invalid setup is rejected before
// capture is opened. The deliberately nonexistent device requires no privileges.
func TestResolveARPValidation(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	validMAC := net.HardwareAddr{2, 1, 2, 3, 4, 5}
	validIP := net.ParseIP("192.0.2.1")
	tests := []struct {
		name            string
		ctx             context.Context
		device          *pcap.Interface
		mac             net.HardwareAddr
		source, nextHop net.IP
		wantCanceled    bool
	}{
		{name: "nil context", device: &pcap.Interface{Name: "nonexistent"}, mac: validMAC, source: validIP, nextHop: validIP},
		{name: "canceled context", ctx: canceled, device: &pcap.Interface{Name: "nonexistent"}, mac: validMAC, source: validIP, nextHop: validIP, wantCanceled: true},
		{name: "nil device", ctx: context.Background(), mac: validMAC, source: validIP, nextHop: validIP},
		{name: "empty device", ctx: context.Background(), device: &pcap.Interface{}, mac: validMAC, source: validIP, nextHop: validIP},
		{name: "invalid source", ctx: context.Background(), device: &pcap.Interface{Name: "nonexistent"}, mac: validMAC, nextHop: validIP},
		{name: "IPv6 next hop", ctx: context.Background(), device: &pcap.Interface{Name: "nonexistent"}, mac: validMAC, source: validIP, nextHop: net.ParseIP("2001:db8::1")},
		{name: "invalid MAC", ctx: context.Background(), device: &pcap.Interface{Name: "nonexistent"}, source: validIP, nextHop: validIP},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mac, err := resolveARP(tt.ctx, tt.device, tt.mac, tt.source, tt.nextHop)
			if err == nil || mac != nil {
				t.Fatalf("resolveARP() = %v, %v, want failure", mac, err)
			}
			if tt.wantCanceled && !errors.Is(err, context.Canceled) {
				t.Fatalf("cancellation cause lost: %v", err)
			}
		})
	}
}
