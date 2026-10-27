package pcapnet_test

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	"github.com/MeHungr/doodlebob/pkg/pcapnet"
)

// ExampleNewVirtualStackWithTransport illustrates ownership and separate physical
// and virtual settings. It requires a configured Ethernet peer and capture
// privileges, so it is compiled but has no Output directive and is not executed.
func ExampleNewVirtualStackWithTransport() {
	ctx := context.Background()
	physical := pcapnet.PCAPConfig{
		DeviceName: "eth0", LocalPort: 45000,
		Peer: netip.MustParseAddrPort("192.0.2.2:45001"),
		MTU:  1200, ReserveUDPPort: false,
	}
	virtual := pcapnet.Config{
		VirtualIP:     netip.MustParseAddr("10.200.0.1"),
		PeerVirtualIP: netip.MustParseAddr("10.200.0.2"), MTU: 1200,
	}
	transport, err := pcapnet.NewPCAPTransport(ctx, physical)
	if err != nil {
		fmt.Println(err)
		return
	}
	v, err := pcapnet.NewVirtualStackWithTransport(virtual, transport)
	if err != nil {
		// Failed attachment leaves transport ownership with this caller.
		fmt.Println(errors.Join(err, transport.Close()))
		return
	}
	// Successful attachment transfers ownership. Stack closure also stops the
	// packet workers and releases the capture handle and optional reservation.
	v.Close()
	if err := v.Err(); err != nil {
		fmt.Println(err)
	}
}
