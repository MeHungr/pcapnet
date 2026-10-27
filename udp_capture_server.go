package pcapnet

import (
	"context"
	"fmt"
	"net/netip"
)

// UDPCaptureServer receives magic-prefixed datagrams on all nonzero UDP ports
// at one local IPv4 address and can reply from the port each client contacted.
// It owns one capture/injection handle and a bounded 256-datagram receive queue.
// No host sockets or port reservations are created. Host UDP delivery and ICMP
// responses are unaffected. Header matching is framing, not authentication.
//
// Receive removes the header, like UDPConn; Reply prepends it. CaptureUDP remains
// a separate read-only observer returning complete payloads, including headers.
// Close releases the handle, stops capture, and wakes blocked operations.
type UDPCaptureServer struct{ conn *UDPConn }

// ListenUDPCapture creates a replying server on the interface owning LocalIP.
// MagicHeader must be nonempty and fit within the physical UDP payload MTU.
// ctx controls setup only; Receive and Reply have per-operation contexts.
// Reply uses the interface MTU, ordinary route lookup, and next-hop ARP, just
// like ListenUDP. There is no handshake, session allocation, or gVisor stack.
func ListenUDPCapture(ctx context.Context, cfg UDPCaptureConfig) (*UDPCaptureServer, error) {
	return newUDPCaptureServer(ctx, cfg, liveUDPSetupOps())
}

func newUDPCaptureServer(ctx context.Context, cfg UDPCaptureConfig, ops udpSetupOps) (*UDPCaptureServer, error) {
	if len(cfg.MagicHeader) == 0 {
		return nil, fmt.Errorf("UDP capture server requires a nonempty magic header")
	}
	conn, err := newUDPConnMode(ctx, UDPConfig{DeviceName: cfg.DeviceName, LocalIP: cfg.LocalIP, MagicHeader: cfg.MagicHeader}, netip.AddrPort{}, ops, true)
	if err != nil {
		return nil, err
	}
	return &UDPCaptureServer{conn: conn}, nil
}

// Receive returns a matching datagram with the magic header removed and both
// source and destination addresses preserved. Returned bytes belong to the caller.
// Cancellation affects only this operation. Concurrent receivers share the queue.
func (s *UDPCaptureServer) Receive(parent context.Context) (*UDPPacket, error) {
	if parent == nil {
		return nil, fmt.Errorf("UDP capture receive context cannot be nil")
	}
	if err := parent.Err(); err != nil {
		return nil, err
	}
	ctx, finish, err := s.conn.operation(false)
	if err != nil {
		return nil, err
	}
	defer finish()
	select {
	case <-parent.Done():
		return nil, parent.Err()
	case <-ctx.Done():
		return nil, s.receiveError()
	case packet := <-s.conn.inbox:
		if err := parent.Err(); err != nil {
			return nil, err
		}
		if ctx.Err() != nil {
			return nil, s.receiveError()
		}
		return packet, nil
	}
}

func (s *UDPCaptureServer) receiveError() error {
	if err := s.Err(); err != nil {
		return err
	}
	return udpContextError(s.conn.ctx)
}

// Reply sends body with the configured magic header to request's source address,
// using request's destination port as its source port. body excludes the header;
// passing request.Payload echoes the application body without duplicating framing.
// The request must address this server's LocalIP with nonzero UDP ports. This
// method validates addresses, not packet provenance; callers must preserve the
// received tuple. Concurrent replies do not change one another's source port.
func (s *UDPCaptureServer) Reply(ctx context.Context, request *UDPPacket, body []byte) error {
	if ctx == nil {
		return fmt.Errorf("UDP capture reply context cannot be nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if request == nil || request.DestinationIP != s.conn.config.LocalIP || request.DestinationPort == 0 || request.SourcePort == 0 {
		return fmt.Errorf("reply requires a request to this local IPv4 address with nonzero ports")
	}
	peer := netip.AddrPortFrom(request.SourceIP, request.SourcePort)
	_, err := s.conn.writeFromContext(ctx, body, request.DestinationPort, peer)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

// MaxDatagramSize reports the maximum reply body after IP/UDP and magic framing.
func (s *UDPCaptureServer) MaxDatagramSize() int { return s.conn.MaxDatagramSize() }

// Err reports terminal capture/injection failures and resource cleanup errors.
func (s *UDPCaptureServer) Err() error { return s.conn.Err() }

// Close is idempotent, wakes operations, joins workers, and releases resources.
func (s *UDPCaptureServer) Close() error { return s.conn.Close() }
