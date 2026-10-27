package pcapnet

import (
	"context"
	"errors"
)

// ErrClosed indicates that a transport has been closed.
var ErrClosed = errors.New("pcapnet: transport closed")

// PacketTransport defines a bidirectional packet transport.
//
// Each Send transmits one complete packet.
// Each Receive returns one complete packet.
//
// Send must finish using the caller's packet before returning or retain its
// own copy. Receive returns an independently owned packet that remains valid
// after subsequent operations. Send and Receive must support concurrent use
// in opposite directions and honor context cancellation.
// Close releases resources and unblocks pending operations.
// Close must be safe to call repeatedly and concurrently with Send and Receive.
//
// A newly created transport belongs to its caller. A successful attachment to
// a VirtualStack transfers ownership to the stack, which closes the transport
// during shutdown. A failed attachment leaves ownership with the caller.
// An attached transport must not be shared with another stack or closed by the
// caller while the stack is using it.
type PacketTransport interface {
	Send(ctx context.Context, packet []byte) error
	Receive(ctx context.Context) ([]byte, error)
	Close() error
}
