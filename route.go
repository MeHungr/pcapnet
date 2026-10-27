package pcapnet

import (
	"fmt"
	"net"

	"github.com/libp2p/go-netroute"
)

// lookupRoute determines how the OS would route a packet to dstIP
//
// gateway == nil means the destination is directly reachable on the selected interface
func lookupRoute(
	dstIP net.IP,
) (
	device *net.Interface,
	gateway net.IP,
	srcIP net.IP,
	err error,
) {
	// Ensure dstIP is IPv4
	if dstIP.To4() == nil {
		err = fmt.Errorf("lookupRoute requires IPv4")
		return
	}

	// Create a new router object to determine route
	router, e := netroute.New()
	if e != nil {
		err = fmt.Errorf("create router: %w", e)
		return
	}

	// Determine route to dstIP
	device, gateway, srcIP, e = router.Route(dstIP)
	if e != nil {
		err = fmt.Errorf("route to %s: %w", dstIP, e)
		return
	}

	// Ensure an interface was  found
	if device == nil {
		err = fmt.Errorf("no interface found for %s", dstIP)
		return
	}

	// Ensure that a source address was found
	if srcIP == nil || srcIP.To4() == nil {
		err = fmt.Errorf("no IPv4 source address for %s", dstIP)
		return
	}

	// Return all named variables
	return
}
