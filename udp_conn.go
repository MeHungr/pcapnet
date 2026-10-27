package pcapnet

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"time"

	"github.com/MeHungr/pcapnet/internal/deadline"
	"github.com/MeHungr/pcapnet/internal/queue"
)

// failed initiates shutdown outside a capture or application operation, which
// must return before Close can join it. Cancellation from normal close is ignored.
func (c *UDPConn) failed(err error) {
	c.mu.Lock()
	if c.closing {
		c.mu.Unlock()
		return
	}
	c.err = err
	c.closing = true
	c.cancel()
	c.mu.Unlock()
	go c.Close()
}

// Err reports native capture/injection and optional reservation cleanup errors.
func (c *UDPConn) Err() error { c.mu.Lock(); defer c.mu.Unlock(); return c.err }

// Close wakes readers and writers, joins capture and application operations, and
// releases native resources. Native PCAP calls must return before handles close.
func (c *UDPConn) Close() error {
	c.once.Do(func() {
		c.mu.Lock()
		c.closing = true
		c.cancel()
		c.mu.Unlock()
		c.active.Wait()
		c.workers.Wait()
		queue.Drain(c.inbox)
		clear(c.macs)
		err := c.resources.Close()
		c.mu.Lock()
		c.err = errors.Join(c.err, err)
		c.mu.Unlock()
	})
	return c.Err()
}

// LocalAddr returns a fresh UDP address for the physical source endpoint.
func (c *UDPConn) LocalAddr() net.Addr { return net.UDPAddrFromAddrPort(c.resources.local) }

// RemoteAddr returns the dialed physical peer, or nil for a listener.
func (c *UDPConn) RemoteAddr() net.Addr {
	if !c.peer.IsValid() {
		return nil
	}
	return net.UDPAddrFromAddrPort(c.peer)
}

// SetDeadline changes pending and future read/write deadlines. Zero clears them.
func (c *UDPConn) SetDeadline(t time.Time) error { return c.setDeadline(t, true, true) }

// SetReadDeadline updates pending and future reads; zero clears the deadline.
func (c *UDPConn) SetReadDeadline(t time.Time) error { return c.setDeadline(t, true, false) }

// SetWriteDeadline updates pending writes, including route/ARP and injection
// gate waits. An executing native route or injection call cannot be interrupted.
func (c *UDPConn) SetWriteDeadline(t time.Time) error { return c.setDeadline(t, false, true) }
func (c *UDPConn) setDeadline(t time.Time, read, write bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closing {
		return net.ErrClosed
	}
	if read {
		c.readDeadline = t
	}
	if write {
		c.writeDeadline = t
	}
	close(c.changed)
	c.changed = make(chan struct{})
	return nil
}

// operation registers before Close can wait, and watches mutable deadlines so
// changing a deadline also wakes an already blocked transport write or read.
func (c *UDPConn) operation(write bool) (context.Context, func(), error) {
	c.mu.Lock()
	if c.closing {
		c.mu.Unlock()
		return nil, nil, net.ErrClosed
	}
	c.active.Add(1)
	c.mu.Unlock()
	ctx, finish := deadline.Context(c.ctx, func() (time.Time, <-chan struct{}) {
		c.mu.Lock()
		defer c.mu.Unlock()
		at := c.readDeadline
		if write {
			at = c.writeDeadline
		}
		return at, c.changed
	})
	return ctx, func() { finish(); c.active.Done() }, nil
}

func (c *UDPConn) opError(op string, err error) error {
	return &net.OpError{Op: op, Net: "udp", Source: c.LocalAddr(), Addr: c.RemoteAddr(), Err: err}
}
func udpContextError(ctx context.Context) error {
	if errors.Is(context.Cause(ctx), os.ErrDeadlineExceeded) {
		return os.ErrDeadlineExceeded
	}
	return net.ErrClosed
}

// ReadFrom consumes one datagram, truncating and discarding any unread tail.
// A configured MagicHeader has already been matched and removed from the body.
func (c *UDPConn) ReadFrom(b []byte) (int, net.Addr, error) {
	ctx, finish, err := c.operation(false)
	if err != nil {
		return 0, nil, c.opError("read", err)
	}
	defer finish()
	select {
	case <-ctx.Done():
		return 0, nil, c.opError("read", udpContextError(ctx))
	case packet := <-c.inbox:
		if ctx.Err() != nil {
			return 0, nil, c.opError("read", udpContextError(ctx))
		}
		return copy(b, packet.Payload), net.UDPAddrFromAddrPort(netip.AddrPortFrom(packet.SourceIP, packet.SourcePort)), nil
	}
}

// Read receives one datagram and discards the sender address.
func (c *UDPConn) Read(b []byte) (int, error) { n, _, err := c.ReadFrom(b); return n, err }

// Write sends one datagram to the dialed peer. Listeners must use WriteTo.
// MagicHeader is prepended when configured; the returned count excludes it.
func (c *UDPConn) Write(b []byte) (int, error) {
	if !c.peer.IsValid() {
		return 0, c.opError("write", fmt.Errorf("UDP endpoint is not connected"))
	}
	return c.writeTo(b, c.peer)
}

// WriteTo sends one datagram from a listener to a unicast IPv4 *net.UDPAddr.
// Connected endpoints use Write and reject WriteTo, matching net.UDPConn.
// MagicHeader is prepended when configured; the returned count excludes it.
func (c *UDPConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if c.peer.IsValid() {
		return 0, c.opError("write", fmt.Errorf("WriteTo on connected UDP endpoint"))
	}
	udp, ok := addr.(*net.UDPAddr)
	if !ok || udp == nil || udp.Zone != "" || udp.Port < 1 || udp.Port > 65535 {
		return 0, c.opError("write", fmt.Errorf("destination must be an IPv4 UDP address"))
	}
	ip, ok := netip.AddrFromSlice(udp.IP.To4())
	if !ok {
		return 0, c.opError("write", fmt.Errorf("destination must be IPv4"))
	}
	return c.writeTo(b, netip.AddrPortFrom(ip, uint16(udp.Port)))
}

var _ net.Conn = (*UDPConn)(nil)
var _ net.PacketConn = (*UDPConn)(nil)

// MaxDatagramSize is the largest application body that fits the configured
// physical IPv4 MTU after UDP and the optional magic header. Writes exceeding
// this limit return ErrDatagramTooLarge without closing the connection.
func (c *UDPConn) MaxDatagramSize() int {
	return int(c.config.MTU) - 28 - len(c.config.MagicHeader)
}
