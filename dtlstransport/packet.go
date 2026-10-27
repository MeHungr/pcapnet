package dtlstransport

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"time"

	"github.com/MeHungr/pcapnet"
	"github.com/MeHungr/pcapnet/internal/deadline"
)

// A public random routing ID separates concurrent initial handshakes before DTLS
// can authenticate anything. It is not the authenticated peer identity and never
// authorizes allocation. Changing it on an encrypted record cannot bypass DTLS
// authentication. The physical address remains fixed for a connection's lifetime.
const (
	muxHeaderSize = 24
	muxMagic      = "PCDT"
	muxVersion    = 1
)

type routeID [16]byte
type routeKey struct {
	peer pcapnet.Peer
	id   routeID
}

func randomID() (routeID, error) {
	var id routeID
	_, err := rand.Read(id[:])
	return id, err
}
func frame(id routeID, record []byte) []byte {
	b := make([]byte, muxHeaderSize+len(record))
	copy(b, muxMagic)
	b[4] = muxVersion
	copy(b[8:24], id[:])
	copy(b[24:], record)
	return b
}
func unframe(b []byte) (routeID, []byte, bool) {
	var id routeID
	if len(b) < muxHeaderSize+13 || string(b[:4]) != muxMagic || b[4] != muxVersion || b[5] != 0 || b[6] != 0 || b[7] != 0 {
		return id, nil, false
	}
	copy(id[:], b[8:24])
	return id, b[24:], true
}
func initialHello(b []byte) bool {
	// Require an epoch-zero ClientHello before reserving a server handshake slot.
	// Pion performs the actual record, fragment, cookie, and handshake validation.
	return len(b) >= 25 && b[0] == 22 && b[1] == 0xfe && (b[2] == 0xfd || b[2] == 0xff) && b[3] == 0 && b[4] == 0 && b[13] == 1
}

// packetConn is an isolated, bounded queue of encrypted records for one DTLS
// connection. Closing it never closes another connection or the shared endpoint.
type packetConn struct {
	endpoint                    *Endpoint
	key                         routeKey
	incoming                    chan []byte
	ctx                         context.Context
	cancel                      context.CancelFunc
	readDeadline, writeDeadline deadline.Deadline
}

func newPacketConn(e *Endpoint, key routeKey) *packetConn {
	ctx, cancel := context.WithCancel(e.ctx)
	return &packetConn{endpoint: e, key: key, incoming: make(chan []byte, 256), ctx: ctx, cancel: cancel}
}
func (p *packetConn) ReadFrom(b []byte) (int, net.Addr, error) {
	ctx, finish := p.readDeadline.Begin(p.ctx)
	defer finish()
	select {
	case <-ctx.Done():
		return 0, nil, context.Cause(ctx)
	case record := <-p.incoming:
		return copy(b, record), net.UDPAddrFromAddrPort(p.key.peer.AddrPort), nil
	}
}
func (p *packetConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	ctx, finish := p.writeDeadline.Begin(p.ctx)
	defer finish()
	if len(b) > p.endpoint.capacity+recordOverhead {
		return 0, pcapnet.ErrDatagramTooLarge
	}
	err := p.endpoint.raw.SendTo(ctx, frame(p.key.id, b), p.key.peer)
	if ctx.Err() != nil {
		return 0, context.Cause(ctx)
	}
	if err != nil {
		return 0, err
	}
	return len(b), nil
}
func (p *packetConn) Close() error        { p.cancel(); return nil }
func (p *packetConn) LocalAddr() net.Addr { return transportAddress("pcap-dtls") }
func (p *packetConn) SetDeadline(t time.Time) error {
	p.readDeadline.Set(t)
	p.writeDeadline.Set(t)
	return nil
}
func (p *packetConn) SetReadDeadline(t time.Time) error  { p.readDeadline.Set(t); return nil }
func (p *packetConn) SetWriteDeadline(t time.Time) error { p.writeDeadline.Set(t); return nil }

type transportAddress string

func (a transportAddress) Network() string { return "udp" }
func (a transportAddress) String() string  { return string(a) }

var _ net.PacketConn = (*packetConn)(nil)

func invalidContext(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("datagram context is required")
	}
	return ctx.Err()
}
