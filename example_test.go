package pcapnet_test

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	"github.com/MeHungr/pcapnet"
)

// ExampleNewVirtualStackWithTransport illustrates ownership and separate physical
// and virtual settings. It requires a configured Ethernet peer and capture
// privileges, so it is compiled but has no Output directive and is not executed.
func ExampleNewVirtualStackWithTransport() {
	ctx := context.Background()
	physical := pcapnet.PCAPConfig{
		LocalPort: 45000, // Select the capture device from the peer route.
		Peer:      netip.MustParseAddrPort("192.0.2.2:45001"),
		MTU:       1200, ReserveUDPPort: false,
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

// ExampleDialUDP shows direct application datagrams to a physical UDP peer.
// It requires live capture privileges and is compiled without being executed.
func ExampleDialUDP() {
	conn, err := pcapnet.DialUDP(context.Background(), pcapnet.UDPConfig{
		LocalPort: 45000, // Select the capture device from the peer route.
	}, netip.MustParseAddrPort("192.0.2.2:45001"))
	if err != nil {
		fmt.Println(err)
		return
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("hello")); err != nil {
		fmt.Println(err)
	}
}

// ExampleListenUDP shows replying to a datagram's physical sender. UDP listeners
// do not accept stream connections and need no virtual address configuration.
func ExampleListenUDP() {
	listener, err := pcapnet.ListenUDP(context.Background(), pcapnet.UDPConfig{
		LocalIP: netip.MustParseAddr("192.0.2.2"), LocalPort: 45001,
	})
	if err != nil {
		fmt.Println(err)
		return
	}
	defer listener.Close()
	buffer := make([]byte, 1472)
	n, sender, err := listener.ReadFrom(buffer)
	if err != nil {
		fmt.Println(err)
		return
	}
	if _, err := listener.WriteTo(buffer[:n], sender); err != nil {
		fmt.Println(err)
	}
}
