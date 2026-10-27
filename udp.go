package pcapnet

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// UDPConfig selects a physical Ethernet/IPv4 UDP endpoint. UDP packets are sent
// directly to ordinary network peers; they do not use virtual IPs or gVisor.
type UDPConfig struct {
	DeviceName     string     // Optional capture device; empty selects by route or LocalIP
	LocalIP        netip.Addr // Required for ListenUDP; DialUDP can use the route source
	LocalPort      uint16     // Explicit nonzero UDP port; ephemeral allocation is not provided
	ReserveUDPPort bool       // Optional host socket reservation, default false
	MTU            uint32     // Physical IPv4 MTU cap; zero uses the interface MTU
}

// udpSetupOps supplies endpoint setup and per-destination routing operations.
// Interface lookup is separate from routing because routes to a host's own IP
// can select loopback rather than the Ethernet interface that owns the address.
type udpSetupOps struct {
	pcapSetupOps
	interfaceForIP func(netip.Addr) (*net.Interface, error)
}

func liveUDPSetupOps() udpSetupOps {
	return udpSetupOps{pcapSetupOps: livePCAPSetupOps(), interfaceForIP: udpInterfaceForIP}
}

// udpInterfaceForIP locates the Ethernet interface owning a listener address.
func udpInterfaceForIP(ip netip.Addr) (*net.Interface, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range interfaces {
		addresses, err := iface.Addrs()
		if err != nil {
			return nil, err
		}
		for _, address := range addresses {
			prefix, err := netip.ParsePrefix(address.String())
			if err == nil && prefix.Addr() == ip {
				return &iface, nil
			}
		}
	}
	return nil, fmt.Errorf("no interface owns local IP %s", ip)
}

// DialUDP creates a connected direct-PCAP UDP endpoint for one physical peer.
// It performs route/ARP setup without a UDP handshake. ctx controls setup only.
func DialUDP(ctx context.Context, cfg UDPConfig, peer netip.AddrPort) (*UDPConn, error) {
	if !peer.IsValid() || !validUDPHost(peer.Addr()) || peer.Port() == 0 {
		return nil, fmt.Errorf("peer must be a unicast IPv4 endpoint")
	}
	return newUDPConn(ctx, cfg, peer, liveUDPSetupOps())
}

// ListenUDP creates an unconnected UDP endpoint on a specific host IPv4 address.
// ReadFrom and WriteTo exchange datagrams with multiple physical IPv4 peers.
// There is no Accept operation: every ReadFrom returns one datagram and sender.
func ListenUDP(ctx context.Context, cfg UDPConfig) (*UDPConn, error) {
	return newUDPConn(ctx, cfg, netip.AddrPort{}, liveUDPSetupOps())
}

// udpMAC caches a bounded set of next-hop addresses for listener replies.
type udpMAC struct {
	address net.HardwareAddr
	expires time.Time
}

// UDPConn implements net.Conn and net.PacketConn without a gVisor stack.
// Each write sends one datagram; each read consumes one datagram, discarding any
// tail that does not fit the caller's buffer. Empty datagrams are supported.
// The receive queue holds 256 datagrams and drops new arrivals when full.
type UDPConn struct {
	resources *pcapResources // Physical capture and optional reservation ownership
	config    UDPConfig
	peer      netip.AddrPort // Invalid for an unconnected listener
	ops       udpSetupOps
	inbox     chan *UDPPacket // Bounded datagrams; never closed during capture
	ctx       context.Context // Endpoint lifetime, independent of setup context
	cancel    context.CancelFunc

	sendGate chan struct{} // Serializes injection and the next-hop MAC cache
	macs     map[netip.Addr]udpMAC
	workers  sync.WaitGroup // Tracks the sole native capture worker
	active   sync.WaitGroup // Registered under mu before shutdown begins
	once     sync.Once

	mu                          sync.Mutex // Protects lifecycle, error, and mutable deadlines
	closing                     bool
	err                         error
	readDeadline, writeDeadline time.Time
	changed                     chan struct{} // Broadcast when either deadline changes
}

// newUDPConn prepares native resources before publishing or starting capture.
func newUDPConn(ctx context.Context, cfg UDPConfig, peer netip.AddrPort, ops udpSetupOps) (_ *UDPConn, resultErr error) {
	if ctx == nil {
		return nil, fmt.Errorf("UDP setup context cannot be nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if cfg.DeviceName != "" && strings.TrimSpace(cfg.DeviceName) == "" {
		return nil, fmt.Errorf("capture device name cannot contain only whitespace")
	}
	if cfg.LocalPort == 0 {
		return nil, fmt.Errorf("nonzero local UDP port is required")
	}
	connected := peer.IsValid()
	if connected && (!validUDPHost(peer.Addr()) || peer.Port() == 0) {
		return nil, fmt.Errorf("peer must be a unicast IPv4 endpoint")
	}
	if cfg.LocalIP.IsValid() && !validUDPHost(cfg.LocalIP) {
		return nil, fmt.Errorf("local address must be a unicast IPv4 address")
	}
	var iface *net.Interface
	var gateway, source net.IP
	var err error
	if connected {
		iface, gateway, source, err = ops.lookupRoute(peer.Addr().AsSlice())
		if err == nil {
			addr, ok := netip.AddrFromSlice(source.To4())
			if !ok || !validUDPHost(addr) {
				return nil, fmt.Errorf("route has no usable IPv4 source")
			}
			if cfg.LocalIP.IsValid() && cfg.LocalIP != addr {
				return nil, fmt.Errorf("local IP does not match peer route")
			}
			cfg.LocalIP = addr
		}
	} else {
		if !validUDPHost(cfg.LocalIP) {
			return nil, fmt.Errorf("ListenUDP requires a local unicast IPv4 address")
		}
		iface, err = ops.interfaceForIP(cfg.LocalIP)
		source = cfg.LocalIP.AsSlice()
	}
	if err != nil {
		return nil, fmt.Errorf("resolve UDP interface: %w", err)
	}
	if iface == nil || len(iface.HardwareAddr) != 6 || iface.MTU < 28 {
		return nil, fmt.Errorf("UDP requires an Ethernet interface with a valid MTU")
	}
	if cfg.MTU == 0 {
		cfg.MTU = uint32(iface.MTU)
	}
	if cfg.MTU < 28 || cfg.MTU > 65535 || cfg.MTU > uint32(iface.MTU) {
		return nil, fmt.Errorf("UDP MTU must fit the physical interface and be between 28 and 65535")
	}
	devices, err := ops.findDevices()
	if err != nil {
		return nil, fmt.Errorf("enumerate UDP capture devices: %w", err)
	}
	device, err := matchCaptureDevice(cfg.DeviceName, devices, iface, source)
	if err != nil {
		return nil, err
	}
	// Listener replies reuse this resolved name when opening temporary ARP handles.
	cfg.DeviceName = device.Name
	r := &pcapResources{local: netip.AddrPortFrom(cfg.LocalIP, cfg.LocalPort), srcMAC: append(net.HardwareAddr(nil), iface.HardwareAddr...)}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, r.Close())
		}
	}()
	if cfg.ReserveUDPPort {
		port, err := ops.reservePort(ctx, r.local)
		if err != nil {
			return nil, fmt.Errorf("reserve UDP port: %w", err)
		}
		r.port = port
	}
	handle, err := ops.openCapture(device.Name, captureSnaplen, false, captureTimeout)
	if err != nil {
		return nil, fmt.Errorf("open UDP capture: %w", err)
	}
	// Adopt the interface only after success, so rollback never closes the
	// typed nil pointer that a failed native open can return.
	r.handle = handle
	if r.handle.LinkType() != layers.LinkTypeEthernet {
		return nil, fmt.Errorf("UDP capture device is not Ethernet")
	}
	filter := udpListenFilter(r.local)
	if connected {
		filter = tunnelBPFFilter(r.local, peer)
	}
	if err := r.handle.SetBPFFilter(filter); err != nil {
		return nil, fmt.Errorf("set UDP capture filter: %w", err)
	}
	lifetime, cancel := context.WithCancel(context.Background())
	c := &UDPConn{resources: r, config: cfg, peer: peer, ops: ops, inbox: make(chan *UDPPacket, 256), ctx: lifetime, cancel: cancel, sendGate: make(chan struct{}, 1), macs: make(map[netip.Addr]udpMAC), changed: make(chan struct{})}
	if connected {
		mac, err := c.resolveMAC(ctx, device, peer.Addr(), gateway)
		if err != nil {
			cancel()
			return nil, err
		}
		r.dstMAC = mac
	}
	if err := ctx.Err(); err != nil {
		cancel()
		return nil, err
	}
	c.sendGate <- struct{}{}
	c.workers.Add(1)
	go c.capture()
	return c, nil
}

func validUDPHost(ip netip.Addr) bool {
	return validVirtualIP(ip) && ip != netip.AddrFrom4([4]byte{255, 255, 255, 255})
}

// udpListenFilter captures a local port regardless of remote source tuple.
func udpListenFilter(local netip.AddrPort) string {
	tuple := fmt.Sprintf("ip and udp and dst host %s and dst port %d", local.Addr(), local.Port())
	return fmt.Sprintf("(%s) or (vlan and ((%s) or (vlan and (%s))))", tuple, tuple, tuple)
}

// capture validates all inbound data independently of the native BPF filter.
func (c *UDPConn) capture() {
	defer c.workers.Done()
	for c.ctx.Err() == nil {
		data, info, err := c.resources.handle.ReadPacketData()
		if c.ctx.Err() != nil {
			return
		}
		if errors.Is(err, pcap.NextErrorTimeoutExpired) {
			continue
		}
		if err != nil {
			c.failed(fmt.Errorf("capture UDP: %w", err))
			return
		}
		if info.CaptureLength != len(data) || info.CaptureLength < info.Length {
			continue
		}
		packet, err := ParseUDPPacket(data)
		if err != nil || packet.DestinationIP != c.config.LocalIP || packet.DestinationPort != c.config.LocalPort || !validUDPHost(packet.SourceIP) {
			continue
		}
		if c.peer.IsValid() && (packet.SourceIP != c.peer.Addr() || packet.SourcePort != c.peer.Port()) {
			continue
		}
		if packet.ipLength > int(c.config.MTU) {
			continue
		}
		select {
		case c.inbox <- packet:
		default:
		}
	}
}
