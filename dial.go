package pcapnet

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
)

// Dial establishes a TCP connection to the configured virtual peer.
//
// The returned connection implements net.Conn and is automatically
// closed when the VirtualStack is closed.
//
// The context controls dialing, not the established connection's lifetime.
func (v *VirtualStack) Dial(
	ctx context.Context,
	targetIP string,
	targetPort int,
) (net.Conn, error) {
	// Verify that the virtual stack is initialized.
	if v == nil || v.Stack == nil {
		return nil, fmt.Errorf("virtual stack is not initialized")
	}

	// Reject nil contexts.
	if ctx == nil {
		return nil, fmt.Errorf("dial context cannot be nil")
	}

	// Check whether the caller has already canceled dialing.
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// Parse the destination IPv4 address.
	ip, err := netip.ParseAddr(targetIP)
	if err != nil {
		return nil, fmt.Errorf("invalid target IP: %w", err)
	}

	// Ensure the destination matches the configured peer.
	if ip != v.config.PeerVirtualIP {
		return nil, fmt.Errorf(
			"target %s does not match configured peer %s",
			ip,
			v.config.PeerVirtualIP,
		)
	}

	// Validate the destination TCP port.
	if targetPort < 1 || targetPort > 65535 {
		return nil, fmt.Errorf("target port must be between 1 and 65535")
	}

	// Register the dial as an active operation.
	finish, err := v.beginDial()
	if err != nil {
		return nil, err
	}
	defer finish()

	// Create a context specifically for this dial operation.
	dialCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Cancel dialing when the virtual stack begins shutting down.
	stop := context.AfterFunc(v.closeCtx, cancel)
	defer stop()

	// Construct the remote gVisor TCP endpoint.
	remoteAddr := tcpip.FullAddress{
		NIC:  virtualNICID,              // Virtual NIC
		Addr: tcpip.AddrFrom4(ip.As4()), // Destination IPv4
		Port: uint16(targetPort),        // Destination TCP port
	}

	// Establish the connection through the gVisor TCP/IP stack.
	conn, err := gonet.DialContextTCP(
		dialCtx,             // Dial context
		v.Stack,             // Virtual TCP/IP stack
		remoteAddr,          // Remote endpoint
		ipv4.ProtocolNumber, // IPv4 protocol
	)
	if err != nil {
		return nil, fmt.Errorf("gVisor TCP dial failed: %w", err)
	}

	// Register the established connection with the VirtualStack.
	managed, err := v.registerConn(conn)
	if err != nil {
		// Release connections established during shutdown.
		_ = conn.Close()
		return nil, err
	}

	return managed, nil
}
