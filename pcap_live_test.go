//go:build pcaplive

package pcapnet

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/google/gopacket"
)

// liveSettings are explicit opt-in settings for a real capture driver. Tests
// never create interfaces, modify routes/firewalls, or choose a device silently.
type liveSettings struct {
	physical PCAPConfig
	virtual  Config
	role     string
}

func readLiveSettings(t *testing.T) liveSettings {
	t.Helper()
	if os.Getenv("PCAPNET_LIVE") != "1" {
		t.Skip("set PCAPNET_LIVE=1 and endpoint settings to exercise live PCAP")
	}
	port, err := strconv.ParseUint(os.Getenv("PCAPNET_LOCAL_PORT"), 10, 16)
	if err != nil {
		t.Fatalf("PCAPNET_LOCAL_PORT: %v", err)
	}
	peer, err := netip.ParseAddrPort(os.Getenv("PCAPNET_PEER"))
	if err != nil {
		t.Fatalf("PCAPNET_PEER: %v", err)
	}
	localIP, err := netip.ParseAddr(os.Getenv("PCAPNET_VIRTUAL_IP"))
	if err != nil {
		t.Fatalf("PCAPNET_VIRTUAL_IP: %v", err)
	}
	peerIP, err := netip.ParseAddr(os.Getenv("PCAPNET_PEER_VIRTUAL_IP"))
	if err != nil {
		t.Fatalf("PCAPNET_PEER_VIRTUAL_IP: %v", err)
	}
	reserve := false
	if setting := os.Getenv("PCAPNET_RESERVE_UDP"); setting != "" {
		reserve, err = strconv.ParseBool(setting)
		if err != nil {
			t.Fatalf("PCAPNET_RESERVE_UDP: %v", err)
		}
	}
	mtu := uint64(DefaultMTU)
	if setting := os.Getenv("PCAPNET_MTU"); setting != "" {
		mtu, err = strconv.ParseUint(setting, 10, 32)
		if err != nil {
			t.Fatalf("PCAPNET_MTU: %v", err)
		}
	}
	physical, err := (PCAPConfig{
		DeviceName: os.Getenv("PCAPNET_DEVICE"), LocalPort: uint16(port), Peer: peer,
		ReserveUDPPort: reserve, MTU: uint32(mtu),
	}).normalize()
	if err != nil {
		t.Fatal(err)
	}
	virtual, err := (Config{VirtualIP: localIP, PeerSubnet: netip.PrefixFrom(peerIP, 32), MTU: uint32(mtu)}).normalize()
	if err != nil {
		t.Fatal(err)
	}
	return liveSettings{physical: physical, virtual: virtual, role: os.Getenv("PCAPNET_ROLE")}
}

// newLiveStack uses the exported setup and attachment APIs against the selected
// real device. Construction errors retain enough context to diagnose setup.
func newLiveStack(t *testing.T, cfg liveSettings) *VirtualStack {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	transport, err := NewPCAPTransport(ctx, cfg.physical)
	if err != nil {
		t.Fatal(err)
	}
	v, err := NewVirtualStackWithTransport(cfg.virtual, transport)
	if err != nil {
		_ = transport.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		closeTestStack(t, v)
		if err := v.Err(); err != nil {
			t.Errorf("live stack failure: %v", err)
		}
	})
	return v
}

// TestLivePCAPTCPEcho runs on two hosts or separate network namespaces, one as
// server and one as client. The server retains the tunnel through the transfer
// deadline so it cannot cancel egress before the client receives the final echo.
func TestLivePCAPTCPEcho(t *testing.T) {
	cfg := readLiveSettings(t)
	if cfg.role != "server" && cfg.role != "client" {
		t.Fatal("PCAPNET_ROLE must be server or client")
	}
	v := newLiveStack(t, cfg)
	const size = 64 * 1024
	if cfg.role == "server" {
		listener, err := v.Listen(6767)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		// Closing the listener on timeout also bounds waiting for a client.
		stop := context.AfterFunc(ctx, func() { _ = listener.Close() })
		defer stop()
		t.Log("live echo server listening on virtual TCP port 6767")
		conn, err := listener.Accept()
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		deadline, _ := ctx.Deadline()
		if err := conn.SetDeadline(deadline); err != nil {
			t.Fatal(err)
		}
		n, err := io.Copy(conn, conn)
		// A client can close its stack before TCP FIN is delivered. The idle
		// deadline then ends the server without making a completed echo fail.
		var timeout net.Error
		if err != nil && !(errors.As(err, &timeout) && timeout.Timeout()) {
			t.Fatal(err)
		}
		if n != size {
			t.Fatalf("echoed %d bytes, want %d", n, size)
		}
		t.Logf("echoed %d bytes through live PCAP", n)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := v.Dial(ctx, cfg.virtual.PeerSubnet.Addr().String(), 6767)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	message := make([]byte, size)
	for i := range message {
		message[i] = byte(i * 31)
	}
	if _, err := conn.Write(message); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, size)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reply, message) {
		t.Fatal("live TCP echo payload mismatch")
	}
	t.Logf("received %d unchanged bytes through live PCAP", len(reply))
}

// liveReadObserver signals after Receive has acquired its operation gate and
// entered capture, so Close is tested against active I/O rather than a queued call.
type liveReadObserver struct {
	captureHandle
	entered chan struct{}
	once    sync.Once
}

func (o *liveReadObserver) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	o.once.Do(func() { close(o.entered) })
	return o.captureHandle.ReadPacketData()
}

// TestLivePCAPReceiveCancellation checks the actual driver's idle-read behavior.
// The outer test timeout is still necessary if native setup or injection stalls.
func TestLivePCAPReceiveCancellation(t *testing.T) {
	cfg := readLiveSettings(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	transport, err := NewPCAPTransport(ctx, cfg.physical)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		done := make(chan error, 1)
		go func() { done <- transport.Close() }()
		if err := awaitError(t, done); err != nil {
			t.Errorf("close live capture: %v", err)
		}
	})
	readCtx, readCancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer readCancel()
	result := make(chan error, 1)
	go func() {
		for {
			if _, err := transport.Receive(readCtx); err != nil {
				result <- err
				return
			}
		}
	}()
	if err := awaitError(t, result); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("live receive did not honor cancellation: %v", err)
	}
	// The first Receive has completed; install the observer before starting
	// another operation. This only observes the real handle, not its behavior.
	observer := &liveReadObserver{captureHandle: transport.resources.handle, entered: make(chan struct{})}
	transport.resources.handle = observer
	go func() { _, err := transport.Receive(context.Background()); result <- err }()
	awaitSignal(t, observer.entered)
	closed := make(chan error, 1)
	go func() { closed <- transport.Close() }()
	if err := awaitError(t, closed); err != nil {
		t.Fatal(err)
	}
	if err := awaitError(t, result); !errors.Is(err, ErrClosed) {
		t.Fatalf("live receive did not unblock during Close: %v", err)
	}
}

// TestLiveDirectUDPEcho tests physical UDP interoperability. PCAPNET_UDP_MODE
// selects pcap (default) or kernel independently on each host, allowing either
// PCAP DialUDP or ListenUDP to exchange with an ordinary host UDP socket.
func TestLiveDirectUDPEcho(t *testing.T) {
	cfg := readLiveSettings(t)
	if cfg.role != "client" && cfg.role != "server" {
		t.Fatal("PCAPNET_ROLE must be client or server")
	}
	mode := os.Getenv("PCAPNET_UDP_MODE")
	if mode == "" {
		mode = "pcap"
	}
	if mode != "pcap" && mode != "kernel" {
		t.Fatal("PCAPNET_UDP_MODE must be pcap or kernel")
	}
	_, _, source, err := lookupRoute(cfg.physical.Peer.Addr().AsSlice())
	if err != nil {
		t.Fatal(err)
	}
	localIP, ok := netip.AddrFromSlice(source.To4())
	if !ok {
		t.Fatal("live UDP route has no IPv4 source")
	}
	udpConfig := UDPConfig{DeviceName: cfg.physical.DeviceName, LocalIP: localIP, LocalPort: cfg.physical.LocalPort, ReserveUDPPort: cfg.physical.ReserveUDPPort}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	payload := bytes.Repeat([]byte("direct UDP"), 100)
	if cfg.role == "server" {
		var listener net.PacketConn
		if mode == "pcap" {
			listener, err = ListenUDP(ctx, udpConfig)
		} else {
			listener, err = net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(localIP, udpConfig.LocalPort)))
		}
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		_ = listener.SetDeadline(time.Now().Add(15 * time.Second))
		t.Logf("direct UDP server ready (%s)", mode)
		buffer := make([]byte, 1500)
		n, addr, err := listener.ReadFrom(buffer)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(buffer[:n], payload) {
			t.Fatal("direct UDP request mismatch")
		}
		if _, err := listener.WriteTo(buffer[:n], addr); err != nil {
			t.Fatal(err)
		}
		return
	}
	var conn net.Conn
	if mode == "pcap" {
		conn, err = DialUDP(ctx, udpConfig, cfg.physical.Peer)
	} else {
		conn, err = net.DialUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(localIP, udpConfig.LocalPort)), net.UDPAddrFromAddrPort(cfg.physical.Peer))
	}
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 1500)
	n, err := conn.Read(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buffer[:n], payload) {
		t.Fatal("direct UDP echo mismatch")
	}
}
