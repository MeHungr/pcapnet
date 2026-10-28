package pcapnet

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"gvisor.dev/gvisor/pkg/tcpip"
)

// managedConn represents a TCP connection owned by a VirtualStack.
type managedConn struct {
	net.Conn // The underlying gVisor TCP connection

	owner      *VirtualStack // The stack that owns this connection
	generation *allocation   // Immutable allocation binding for accepted PCAT TCP

	closeOnce sync.Once // Ensures the connection closes once
	closeErr  error     // Stable result shared by concurrent Close callers
}

// Peer returns the original allocation's exact peer handle, even after closure.
// A zero peer denotes a connection outside the PCAT server acceptance path.
func (c *managedConn) Peer() Peer {
	if c.generation == nil {
		return Peer{}
	}
	return c.generation.key.endpoint
}

// Close closes the TCP connection and unregisters it from its VirtualStack.
func (c *managedConn) Close() error {
	// Close the underlying connection only once.
	c.closeOnce.Do(func() {
		// Close the gVisor TCP connection.
		c.closeErr = c.Conn.Close()

		// Remove the connection from the owner's registry.
		c.owner.mu.Lock()
		delete(c.owner.conns, c)
		c.owner.mu.Unlock()
	})

	return c.closeErr
}

// managedListener represents a TCP listener owned by a VirtualStack.
type managedListener struct {
	net.Listener // The underlying gVisor TCP listener

	owner *VirtualStack // The stack that owns this listener

	closeOnce sync.Once // Ensures the listener closes once
	closeErr  error     // Stable result shared by concurrent Close callers
}

// Accept waits for a TCP connection and registers it with the VirtualStack.
func (l *managedListener) Accept() (net.Conn, error) {
	// Accept a TCP connection through gVisor.
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	// Register the connection with the owning virtual stack.
	managed, err := l.owner.registerConn(conn)
	if err != nil {
		// Close connections accepted during shutdown.
		_ = conn.Close()
		return nil, err
	}

	return managed, nil
}

// Close closes the TCP listener and unregisters it from its VirtualStack.
func (l *managedListener) Close() error {
	// Close the underlying listener only once.
	l.closeOnce.Do(func() {
		// Close the gVisor listener.
		l.closeErr = l.Listener.Close()

		// Remove the listener from the owner's registry.
		l.owner.mu.Lock()
		delete(l.owner.listeners, l)
		l.owner.mu.Unlock()
	})

	return l.closeErr
}

// registerConn registers a TCP connection with the VirtualStack.
// Connections cannot be registered after shutdown begins.
func (v *VirtualStack) registerConn(conn net.Conn) (net.Conn, error) {
	return v.registerGenerationConn(conn, nil)
}
func (v *VirtualStack) registerGenerationConn(conn net.Conn, generation *allocation) (net.Conn, error) {
	// Acquire the lifecycle lock.
	v.mu.Lock()
	defer v.mu.Unlock()

	// Reject connections during shutdown.
	if v.closing {
		return nil, ErrClosed
	}

	// Wrap the connection to manage its lifetime.
	managed := &managedConn{
		Conn: conn, owner: v, generation: generation,
	}

	// Register the connection.
	v.conns[managed] = struct{}{}

	return managed, nil
}

// beginDial registers a pending TCP dial operation.
// The caller must invoke the returned completion function exactly once.
func (v *VirtualStack) beginDial() (func(), error) {
	// Acquire the lifecycle lock.
	v.mu.Lock()
	defer v.mu.Unlock()

	// Reject new dial operations after shutdown begins.
	if v.closing {
		return nil, ErrClosed
	}

	// Verify that the virtual stack has been initialized.
	if v.Stack == nil || v.closeCtx == nil {
		return nil, fmt.Errorf("virtual stack is not initialized")
	}

	// Register the pending dial operation.
	v.activeDials.Add(1)

	// Return the operation's completion function.
	return v.activeDials.Done, nil
}

// Err returns the first unexpected packet worker failure and any cleanup errors.
// Normal cancellation during Close is not a failure. Err is safe during shutdown;
// call Close before Err when the final cleanup result is needed. A nil stack or
// a stack that has not encountered an error returns nil.
func (v *VirtualStack) Err() error {
	if v == nil {
		return nil
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.err
}

// recordError preserves errors for Err without changing the Close signature.
func (v *VirtualStack) recordError(err error) {
	if err == nil {
		return
	}
	v.mu.Lock()
	v.err = errors.Join(v.err, err)
	v.mu.Unlock()
}

// workerFailed rejects new operations and cancels pending dials immediately.
// Shutdown runs outside the worker: Close joins that worker and must not be
// called synchronously by it. Only the bridge's first failure invokes this hook.
func (v *VirtualStack) workerFailed(err error) {
	v.mu.Lock()
	v.err = errors.Join(v.err, err)
	v.closing = true
	v.cancel()
	v.mu.Unlock()
	go v.Close()
}

// Close releases the VirtualStack's TCP connections, listeners,
// workers, and gVisor networking resources.
//
// Close is safe to call repeatedly and concurrently.
// It waits for pending TCP dials, packet workers, and gVisor cleanup to finish.
// Resource cleanup errors remain available through Err.
func (v *VirtualStack) Close() {
	// Ignore nil virtual stacks.
	if v == nil {
		return
	}

	// Perform shutdown only once.
	v.closeOnce.Do(func() {
		// Acquire the lifecycle lock.
		v.mu.Lock()

		// Prevent new operations from starting.
		v.closing = true

		// Cancel pending dial operations.
		if v.cancel != nil {
			v.cancel()
		}

		// Copy the listeners that need to be closed.
		listeners := make([]*managedListener, 0, len(v.listeners))
		for listener := range v.listeners {
			listeners = append(listeners, listener)
		}

		// Copy the connections that need to be closed.
		conns := make([]*managedConn, 0, len(v.conns))
		for conn := range v.conns {
			conns = append(conns, conn)
		}

		// Release the lock before closing network resources.
		v.mu.Unlock()

		// Stop generation-aware handshakes before destroying the shared stack.
		if v.peerListener != nil {
			_ = v.peerListener.Close()
		}

		// Close all active TCP listeners.
		var cleanupErr error
		for _, listener := range listeners {
			cleanupErr = errors.Join(cleanupErr, listener.Close())
		}

		// Close all active TCP connections.
		for _, conn := range conns {
			cleanupErr = errors.Join(cleanupErr, conn.Close())
		}

		// Wait for pending TCP dials to finish.
		v.activeDials.Wait()

		// Close the owned transport and join its workers before destroying
		// gVisor resources, so ingress cannot inject into a released stack.
		if v.bridge != nil {
			cleanupErr = errors.Join(cleanupErr, v.bridge.Close())
		}

		// Close the gVisor TCP/IP stack.
		if v.Stack != nil {
			v.Stack.Close()
		}

		// Close the in-memory link endpoint.
		if v.Link != nil {
			v.Link.Close()
		}

		// Finish gVisor endpoint, protocol, and NIC cleanup only after packet
		// workers and pending dials can no longer use those resources.
		if v.Stack != nil {
			v.Stack.Wait()
		}
		v.recordError(cleanupErr)
	})
}

// Verify that managed connections implement net.Conn.
var _ net.Conn = (*managedConn)(nil)

// Verify that managed listeners implement net.Listener.
var _ net.Listener = (*managedListener)(nil)

// expireVirtualPeer initiates abort of registered TCP state for an expiring
// assignment. This covers pending accepts and TIME_WAIT, as well as managed
// connections. Stack destruction joins the session expiry worker first.
func (v *VirtualStack) expireVirtualPeer(ip netip.Addr) {
	endpoints := append(v.Stack.RegisteredEndpoints(), v.Stack.CleanupEndpoints()...)
	for _, endpoint := range endpoints {
		if addressed, ok := endpoint.(tcpip.Endpoint); ok {
			remote, err := addressed.GetRemoteAddress()
			if err == nil && remote.Addr == tcpip.AddrFrom4(ip.As4()) {
				endpoint.Abort()
			}
		}
	}
	// managed Close unregisters itself, so release the registry lock first.
	v.mu.Lock()
	var stale []net.Conn
	for conn := range v.conns {
		if addr, ok := conn.RemoteAddr().(*net.TCPAddr); ok && addr.IP.Equal(ip.AsSlice()) {
			stale = append(stale, conn)
		}
	}
	v.mu.Unlock()
	for _, conn := range stale {
		_ = conn.Close()
	}
}
