package pcapnet

import (
	"net"
	"testing"
)

// TestLookupRouteRejectsNonIPv4 verifies input validation before invoking the
// platform route implementation; it requires no network or capture privileges.
func TestLookupRouteRejectsNonIPv4(t *testing.T) {
	for _, destination := range []net.IP{nil, net.ParseIP("2001:db8::1")} {
		iface, gateway, source, err := lookupRoute(destination)
		if err == nil || iface != nil || gateway != nil || source != nil {
			t.Fatalf("lookupRoute(%s) = %v, %v, %v, %v; want IPv4 validation failure", destination, iface, gateway, source, err)
		}
	}
}
