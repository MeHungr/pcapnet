package pcapnet

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// ethernetCapture models a capture device on a two-endpoint Ethernet link.
// Native capture is replaced; serialization, BPF, parsing, and gVisor are real.
type ethernetCapture struct {
	inbound       chan []byte
	peer          *ethernetCapture
	local, remote net.HardwareAddr
	filter        *pcap.BPF
	done          chan struct{}
	once          sync.Once
	frames        atomic.Uint64
	filtered      atomic.Uint64
	maxInner      atomic.Uint32
}

func (c *ethernetCapture) LinkType() layers.LinkType { return layers.LinkTypeEthernet }
func (c *ethernetCapture) SetBPFFilter(expression string) error {
	filter, err := pcap.NewBPF(layers.LinkTypeEthernet, captureSnaplen, expression)
	if err == nil {
		c.filter = filter
	}
	return err
}

// ReadPacketData applies the installed BPF as a live capture driver would.
// Timeouts remain bounded even when the Ethernet link is idle.
func (c *ethernetCapture) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	timer := time.NewTimer(10 * time.Millisecond)
	defer timer.Stop()
	for {
		select {
		case data := <-c.inbound:
			info := gopacket.CaptureInfo{CaptureLength: len(data), Length: len(data)}
			if !c.filter.Matches(info, data) {
				c.filtered.Add(1)
				continue
			}
			return data, info, nil
		case <-timer.C:
			return nil, gopacket.CaptureInfo{}, pcap.NextErrorTimeoutExpired
		case <-c.done:
			return nil, gopacket.CaptureInfo{}, io.EOF
		}
	}
}

// WritePacketData validates the real wire frame and delivers an owned copy to
// the peer. Full queues and an offline peer drop frames, as Ethernet can do.
func (c *ethernetCapture) WritePacketData(frame []byte) error {
	packet, err := ParseUDPPacket(frame)
	if err != nil {
		return fmt.Errorf("invalid injected frame: %w", err)
	}
	if !bytes.Equal(frame[:6], c.remote) || !bytes.Equal(frame[6:12], c.local) {
		return fmt.Errorf("injected frame has incorrect Ethernet addresses")
	}
	if len(frame)-ethernetHeaderSize > 1500 {
		return fmt.Errorf("outer datagram exceeds physical MTU")
	}
	c.frames.Add(1)
	length := uint32(len(packet.Payload))
	for old := c.maxInner.Load(); length > old; old = c.maxInner.Load() {
		if c.maxInner.CompareAndSwap(old, length) {
			break
		}
	}
	select {
	case <-c.peer.done:
		return nil
	default:
	}
	select {
	case c.peer.inbound <- append([]byte(nil), frame...):
	default:
	}
	return nil
}

func (c *ethernetCapture) Close() { c.once.Do(func() { close(c.done) }) }

// ethernetSetup provides deterministic routing/ARP but still constructs the
// production PCAP transport through its normal resource setup sequence.
func ethernetSetup(t *testing.T, cfg PCAPConfig, local netip.Addr, capture *ethernetCapture, port *fakeReservation) pcapSetupOps {
	t.Helper()
	return pcapSetupOps{
		lookupRoute: func(peer net.IP) (*net.Interface, net.IP, net.IP, error) {
			if !peer.Equal(net.IP(cfg.Peer.Addr().AsSlice())) {
				return nil, nil, nil, fmt.Errorf("unexpected route peer")
			}
			return &net.Interface{Name: cfg.DeviceName, MTU: 1500, HardwareAddr: capture.local}, nil, local.AsSlice(), nil
		},
		findDevices: func() ([]pcap.Interface, error) { return []pcap.Interface{{Name: cfg.DeviceName}}, nil },
		reservePort: func(_ context.Context, addr netip.AddrPort) (io.Closer, error) {
			if !cfg.ReserveUDPPort {
				t.Error("unexpected socket reservation")
			}
			if addr != netip.AddrPortFrom(local, cfg.LocalPort) {
				t.Errorf("reservation address = %s", addr)
			}
			return port, nil
		},
		openCapture: func(string, int32, bool, time.Duration) (captureHandle, error) { return capture, nil },
		resolveARP: func(_ context.Context, _ *pcap.Interface, _ net.HardwareAddr, _ net.IP, next net.IP) (net.HardwareAddr, error) {
			if !next.Equal(net.IP(cfg.Peer.Addr().AsSlice())) {
				return nil, fmt.Errorf("unexpected ARP next hop")
			}
			return capture.remote, nil
		},
	}
}

// TestPCAPTunnelsTCPEcho connects two full stacks through Ethernet/IPv4/UDP,
// including both production bridges, BPF filters, and PCAP packet transports.
func TestPCAPTunnelsTCPEcho(t *testing.T) {
	for _, reserve := range []bool{false, true} {
		t.Run(fmt.Sprintf("reserve_%t", reserve), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			leftMAC, rightMAC := net.HardwareAddr{2, 0, 0, 0, 0, 1}, net.HardwareAddr{2, 0, 0, 0, 0, 2}
			left := &ethernetCapture{inbound: make(chan []byte, 1024), local: leftMAC, remote: rightMAC, done: make(chan struct{})}
			right := &ethernetCapture{inbound: make(chan []byte, 1024), local: rightMAC, remote: leftMAC, done: make(chan struct{})}
			left.peer, right.peer = right, left
			leftPort, rightPort := &fakeReservation{}, &fakeReservation{}
			leftCfg := PCAPConfig{DeviceName: "left", LocalPort: 45000, Peer: netip.MustParseAddrPort("192.0.2.2:45001"), ReserveUDPPort: reserve}
			rightCfg := PCAPConfig{DeviceName: "right", LocalPort: 45001, Peer: netip.MustParseAddrPort("192.0.2.1:45000"), ReserveUDPPort: reserve}
			leftTransport, err := newPCAPTransport(ctx, leftCfg, ethernetSetup(t, leftCfg, netip.MustParseAddr("192.0.2.1"), left, leftPort))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = leftTransport.Close() })
			rightTransport, err := newPCAPTransport(ctx, rightCfg, ethernetSetup(t, rightCfg, netip.MustParseAddr("192.0.2.2"), right, rightPort))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = rightTransport.Close() })
			control, err := NewVirtualStackWithTransport(newTestConfig(), leftTransport)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { closeTestStack(t, control) })
			cfg := newTestConfig()
			cfg.VirtualIP, cfg.PeerVirtualIP = cfg.PeerVirtualIP, cfg.VirtualIP
			target, err := NewVirtualStackWithTransport(cfg, rightTransport)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { closeTestStack(t, target) })
			// Unrelated traffic must be removed by the actual libpcap filter.
			right.inbound <- makeTestUDPFrame(t, []byte("unrelated UDP"))
			listener, err := target.Listen(6767)
			if err != nil {
				t.Fatal(err)
			}
			serverDone := make(chan error, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					serverDone <- err
					return
				}
				defer conn.Close()
				_, err = io.Copy(conn, conn)
				serverDone <- err
			}()
			conn, err := control.Dial(ctx, cfg.VirtualIP.String(), 6767)
			if err != nil {
				t.Fatalf("TCP dial: %v (control: %v; target: %v)", err, control.Err(), target.Err())
			}
			defer conn.Close()
			if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			for _, size := range []int{1, DefaultMTU + 1, 128 * 1024} {
				message := make([]byte, size)
				for i := range message {
					message[i] = byte(i * 31)
				}
				if _, err := conn.Write(message); err != nil {
					t.Fatal(err)
				}
				reply := make([]byte, len(message))
				if _, err := io.ReadFull(conn, reply); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(reply, message) {
					t.Fatalf("echo mismatch for %d-byte message", size)
				}
			}
			if err := conn.Close(); err != nil {
				t.Fatal(err)
			}
			if err := awaitError(t, serverDone); err != nil {
				t.Fatal(err)
			}
			closeTestStack(t, control)
			closeTestStack(t, target)
			if control.Err() != nil || target.Err() != nil {
				t.Fatalf("stack failures: %v; %v", control.Err(), target.Err())
			}
			for _, capture := range []*ethernetCapture{left, right} {
				if capture.frames.Load() < 3 || capture.maxInner.Load() > DefaultMTU {
					t.Fatal("traffic was not segmented within the tunnel MTU")
				}
			}
			if right.filtered.Load() == 0 {
				t.Fatal("unrelated traffic did not exercise the capture filter")
			}
			wantCloses := 0
			if reserve {
				wantCloses = 1
			}
			if leftPort.closes != wantCloses || rightPort.closes != wantCloses {
				t.Fatal("unexpected UDP reservation cleanup")
			}
		})
	}
}
