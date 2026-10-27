package pcapnet

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

// failingTransport wraps a real memory transport with a controlled failure in
// one direction. It also exposes packet and cleanup events for synchronization.
type failingTransport struct {
	PacketTransport
	failCtx    context.Context
	fail       context.CancelFunc
	failSend   bool
	cause      error
	cleanupErr error
	sent       chan struct{}
	sentOnce   sync.Once
	closed     chan struct{}
	closes     atomic.Int32
	zeroWindow chan struct{}
	windowOnce sync.Once
}

func newFailingTransport(t *testing.T, transport PacketTransport, failSend bool) *failingTransport {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return &failingTransport{
		PacketTransport: transport, failCtx: ctx, fail: cancel, failSend: failSend,
		cause: errors.New("controlled packet failure"), sent: make(chan struct{}),
		closed: make(chan struct{}), zeroWindow: make(chan struct{}),
	}
}

func (f *failingTransport) Send(ctx context.Context, data []byte) error {
	f.sentOnce.Do(func() { close(f.sent) })
	if f.failSend {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-f.failCtx.Done():
			return f.cause
		}
	}
	return f.PacketTransport.Send(ctx, data)
}

func (f *failingTransport) Receive(ctx context.Context) ([]byte, error) {
	if f.failSend {
		return f.PacketTransport.Receive(ctx)
	}
	opCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(f.failCtx, cancel)
	defer stop()
	data, err := f.PacketTransport.Receive(opCtx)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if f.failCtx.Err() != nil {
		return nil, f.cause
	}
	// A zero advertised TCP window provides a deterministic signal that the
	// test peer's receive buffer is full; no timing sleeps are needed.
	if len(data) >= 40 && data[9] == byte(tcp.ProtocolNumber) {
		header := int(data[0]&0x0f) * 4
		if header >= 20 && len(data) >= header+20 && binary.BigEndian.Uint16(data[header+14:header+16]) == 0 {
			f.windowOnce.Do(func() { close(f.zeroWindow) })
		}
	}
	return data, err
}

func (f *failingTransport) Close() error {
	f.closes.Add(1)
	err := f.PacketTransport.Close()
	close(f.closed)
	return errors.Join(err, f.cleanupErr)
}

// closeTestStack bounds shutdown assertions so a worker self-join deadlock is
// reported by the test rather than blocking the entire test run indefinitely.
func closeTestStack(t *testing.T, v *VirtualStack) {
	t.Helper()
	done := make(chan struct{})
	go func() { v.Close(); close(done) }()
	awaitSignal(t, done)
}

// TestWorkerFailureUnblocksDialAndAccept verifies send and receive failures
// automatically stop a stack with a pending handshake and blocked listener.
func TestWorkerFailureUnblocksDialAndAccept(t *testing.T) {
	for _, failSend := range []bool{false, true} {
		name := "receive"
		if failSend {
			name = "send"
		}
		t.Run(name, func(t *testing.T) {
			local, peer := NewMemoryPair(8)
			defer peer.Close()
			transport := newFailingTransport(t, local, failSend)
			transport.cleanupErr = errors.New("controlled transport cleanup failure")
			v, err := NewVirtualStackWithTransport(newTestConfig(), transport)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { closeTestStack(t, v) })
			listener, err := v.Listen(6767)
			if err != nil {
				t.Fatal(err)
			}
			acceptDone := make(chan error, 1)
			go func() {
				conn, err := listener.Accept()
				if conn != nil {
					_ = conn.Close()
				}
				acceptDone <- err
			}()
			dialDone := make(chan error, 1)
			go func() {
				conn, err := v.Dial(context.Background(), "10.200.0.2", 6767)
				if conn != nil {
					_ = conn.Close()
				}
				dialDone <- err
			}()
			awaitSignal(t, transport.sent) // The pending dial has emitted its SYN.
			transport.fail()
			awaitSignal(t, transport.closed) // No caller has requested Close yet.
			if err := awaitError(t, dialDone); !errors.Is(err, context.Canceled) {
				t.Fatalf("pending dial did not observe stack cancellation: %v", err)
			}
			if err := awaitError(t, acceptDone); err == nil {
				t.Fatal("blocked Accept succeeded after failure")
			}
			closeTestStack(t, v)
			if err := v.Err(); !errors.Is(err, transport.cause) || !errors.Is(err, transport.cleanupErr) || !strings.Contains(err.Error(), "bridge "+name) {
				t.Fatalf("terminal causes were lost: %v", err)
			}
			if _, err := v.Listen(6768); !errors.Is(err, ErrClosed) {
				t.Fatalf("new listener error = %v", err)
			}
			if _, err := v.Dial(context.Background(), "10.200.0.2", 6768); !errors.Is(err, ErrClosed) {
				t.Fatalf("new dial error = %v", err)
			}
			if transport.closes.Load() != 1 {
				t.Fatalf("transport closed %d times", transport.closes.Load())
			}
		})
	}
}

// TestWorkerFailureUnblocksTCPIO establishes actual gVisor TCP endpoints, fills
// the peer receive window, and verifies stack failure wakes both Read and Write.
func TestWorkerFailureUnblocksTCPIO(t *testing.T) {
	local, remote := NewMemoryPair(256)
	transport := newFailingTransport(t, local, false)
	control, err := NewVirtualStackWithTransport(newTestConfig(), transport)
	if err != nil {
		_ = local.Close()
		_ = remote.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { closeTestStack(t, control) })
	cfg := newTestConfig()
	cfg.VirtualIP, cfg.PeerSubnet = cfg.PeerSubnet.Addr(), netip.PrefixFrom(cfg.VirtualIP, 32)
	target, err := NewVirtualStackWithTransport(cfg, remote)
	if err != nil {
		_ = remote.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { closeTestStack(t, target) })
	// Small fixed buffers create backpressure after a few packets. These are
	// test-only protocol options and do not change production stack defaults.
	for _, v := range []*VirtualStack{control, target} {
		if err := v.Stack.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpip.TCPSendBufferSizeRangeOption{Min: 4096, Default: 4096, Max: 4096}); err != nil {
			t.Fatal(err)
		}
		if err := v.Stack.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpip.TCPReceiveBufferSizeRangeOption{Min: 4096, Default: 4096, Max: 4096}); err != nil {
			t.Fatal(err)
		}
	}
	listener, err := target.Listen(6767)
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan net.Conn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- conn
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := control.Dial(ctx, "10.200.0.2", 6767)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case server := <-accepted:
		defer server.Close()
	case err := <-acceptErr:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal("TCP accept did not complete")
	}
	readDone, writeDone := make(chan error, 1), make(chan error, 1)
	go func() { _, err := conn.Read(make([]byte, 1)); readDone <- err }()
	go func() { _, err := conn.Write(make([]byte, 64*1024)); writeDone <- err }()
	awaitSignal(t, transport.zeroWindow)
	select {
	case err := <-writeDone:
		t.Fatalf("write finished before failure despite backpressure: %v", err)
	default:
	}
	transport.fail()
	awaitSignal(t, transport.closed)
	if err := awaitError(t, readDone); err == nil {
		t.Fatal("read succeeded after stack failure")
	}
	if err := awaitError(t, writeDone); err == nil {
		t.Fatal("blocked write succeeded after stack failure")
	}
	closeTestStack(t, control)
	if !errors.Is(control.Err(), transport.cause) {
		t.Fatalf("terminal cause lost: %v", control.Err())
	}
}

// TestImmediateWorkerFailure covers a transport that fails during construction,
// before its bridge assignment and constructor return can complete.
func TestImmediateWorkerFailure(t *testing.T) {
	local, peer := NewMemoryPair(1)
	defer peer.Close()
	transport := newFailingTransport(t, local, false)
	transport.fail()
	v, err := NewVirtualStackWithTransport(newTestConfig(), transport)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeTestStack(t, v) })
	awaitSignal(t, transport.closed)
	closeTestStack(t, v)
	if !errors.Is(v.Err(), transport.cause) || transport.closes.Load() != 1 {
		t.Fatalf("immediate failure cleanup: %v, close count %d", v.Err(), transport.closes.Load())
	}
}

// TestUnexpectedLinkClosure verifies a worker exiting without cancellation is
// treated as a failed link rather than silently leaving the stack usable.
func TestUnexpectedLinkClosure(t *testing.T) {
	local, peer := NewMemoryPair(1)
	defer peer.Close()
	transport := newFailingTransport(t, local, false)
	v, err := NewVirtualStackWithTransport(newTestConfig(), transport)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeTestStack(t, v) })
	v.Link.Close()
	awaitSignal(t, transport.closed)
	closeTestStack(t, v)
	if !errors.Is(v.Err(), ErrClosed) {
		t.Fatalf("link closure not reported: %v", v.Err())
	}
}

// TestStackErrDuringNormalShutdown exercises Err and Close concurrently and
// distinguishes ordinary cancellation from a real resource cleanup failure.
func TestStackErrDuringNormalShutdown(t *testing.T) {
	var nilStack *VirtualStack
	if err := nilStack.Err(); err != nil {
		t.Fatal(err)
	}
	for _, failCleanup := range []bool{false, true} {
		name := "clean"
		if failCleanup {
			name = "cleanup failure"
		}
		t.Run(name, func(t *testing.T) {
			local, peer := NewMemoryPair(1)
			defer peer.Close()
			transport := newFailingTransport(t, local, false)
			if failCleanup {
				transport.cleanupErr = errors.New("cleanup failed")
			}
			v, err := NewVirtualStackWithTransport(newTestConfig(), transport)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { closeTestStack(t, v) })
			if err := v.Err(); err != nil {
				t.Fatal(err)
			}
			var wg sync.WaitGroup
			for i := 0; i < 8; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					_ = v.Err()
					v.Close()
					_ = v.Err()
				}()
			}
			wg.Wait()
			if failCleanup {
				if !errors.Is(v.Err(), transport.cleanupErr) {
					t.Fatalf("cleanup cause lost: %v", v.Err())
				}
			} else if err := v.Err(); err != nil {
				t.Fatalf("normal cancellation recorded a failure: %v", err)
			}
			if transport.closes.Load() != 1 {
				t.Fatal("concurrent Close released transport more than once")
			}
		})
	}
}

// errorOnCloseConn and errorOnCloseListener release real test endpoints while
// simulating cleanup errors that must survive repeated/concurrent closure.
type errorOnCloseConn struct {
	net.Conn
	cause  error
	closes atomic.Int32
}

func (c *errorOnCloseConn) Close() error {
	c.closes.Add(1)
	return errors.Join(c.Conn.Close(), c.cause)
}

type errorOnCloseListener struct {
	net.Listener
	cause  error
	closes atomic.Int32
}

func (l *errorOnCloseListener) Close() error {
	l.closes.Add(1)
	return errors.Join(l.Listener.Close(), l.cause)
}

// TestStackEndpointCleanupErrors verifies Close keeps its existing signature
// while Err retains connection/listener cleanup errors and wrapper Close calls
// consistently return their original result after stack-owned shutdown.
func TestStackEndpointCleanupErrors(t *testing.T) {
	v, err := NewVirtualStack(newTestConfig())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeTestStack(t, v) })
	local, remote := net.Pipe()
	defer remote.Close()
	badConn := &errorOnCloseConn{Conn: local, cause: errors.New("connection cleanup failed")}
	conn, err := v.registerConn(badConn)
	if err != nil {
		_ = badConn.Close()
		t.Fatal(err)
	}
	listener, err := v.Listen(6767)
	if err != nil {
		t.Fatal(err)
	}
	managed := listener.(*managedListener)
	badListener := &errorOnCloseListener{Listener: managed.Listener, cause: errors.New("listener cleanup failed")}
	managed.Listener = badListener
	closeTestStack(t, v)
	if err := v.Err(); !errors.Is(err, badConn.cause) || !errors.Is(err, badListener.cause) {
		t.Fatalf("endpoint cleanup causes lost: %v", err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := conn.Close(); !errors.Is(err, badConn.cause) {
				t.Errorf("repeated conn Close() = %v", err)
			}
			if err := listener.Close(); !errors.Is(err, badListener.cause) {
				t.Errorf("repeated listener Close() = %v", err)
			}
		}()
	}
	wg.Wait()
	if badConn.closes.Load() != 1 || badListener.closes.Load() != 1 {
		t.Fatal("endpoint cleanup was repeated")
	}
}
