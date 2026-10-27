package pcapnet

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const (
	// captureTimeout allows receive loops to periodically check cancellation.
	// Live-driver shutdown behavior still requires platform integration tests.
	captureTimeout = 100 * time.Millisecond

	// captureSnaplen includes a maximum IPv4 datagram and Ethernet headers
	// with up to two VLAN tags, matching ParseUDPPacket's supported formats.
	captureSnaplen = 65535 + ethernetHeaderSize + 8

	// arpTimeout bounds next-hop resolution independently of caller deadlines.
	arpTimeout = 5 * time.Second
)

// captureHandle exposes the operations needed by tunnel setup and packet I/O.
// Keeping the driver behind an interface permits tests without capture privileges.
type captureHandle interface {
	LinkType() layers.LinkType
	SetBPFFilter(string) error
	ReadPacketData() ([]byte, gopacket.CaptureInfo, error)
	WritePacketData([]byte) error
	Close()
}

// pcapSetupOps supplies operating-system operations to the setup sequence.
// Tests inject operations per call rather than replacing shared global state.
type pcapSetupOps struct {
	lookupRoute func(net.IP) (*net.Interface, net.IP, net.IP, error)
	findDevices func() ([]pcap.Interface, error)
	reservePort func(context.Context, netip.AddrPort) (io.Closer, error)
	openCapture func(string, int32, bool, time.Duration) (captureHandle, error)
	resolveARP  func(context.Context, *pcap.Interface, net.HardwareAddr, net.IP, net.IP) (net.HardwareAddr, error)
}

// livePCAPSetupOps connects setup to the real route, socket, and PCAP APIs.
func livePCAPSetupOps() pcapSetupOps {
	return pcapSetupOps{
		lookupRoute: lookupRoute,
		findDevices: pcap.FindAllDevs,
		reservePort: reserveUDPPort,
		openCapture: func(name string, snaplen int32, promisc bool, timeout time.Duration) (captureHandle, error) {
			return pcap.OpenLive(name, snaplen, promisc, timeout)
		},
		resolveARP: resolveARP,
	}
}

// reserveUDPPort keeps the host UDP endpoint occupied for the tunnel's lifetime.
// The socket prevents ordinary bind collisions and closed-port ICMP replies;
// packet transfer is performed through PCAP rather than this socket.
func reserveUDPPort(ctx context.Context, local netip.AddrPort) (io.Closer, error) {
	var lc net.ListenConfig
	return lc.ListenPacket(ctx, "udp4", local.String())
}

// pcapResources owns a fully prepared physical tunnel endpoint. PCAPTransport
// coordinates packet I/O before releasing these resources.
type pcapResources struct {
	config   PCAPConfig       // Normalized physical tunnel configuration
	local    netip.AddrPort   // Route-selected source IPv4 address and UDP port
	srcMAC   net.HardwareAddr // Independently owned source Ethernet address
	dstMAC   net.HardwareAddr // Independently owned next-hop Ethernet address
	handle   captureHandle    // Persistent capture and injection handle
	port     io.Closer        // Host UDP port reservation
	once     sync.Once        // Serializes resource release across callers
	closeErr error            // Stable result of the first resource release
}

// preparePCAP acquires resources in order and rolls them back on any failure.
// The returned resources belong to the caller only after successful setup.
func preparePCAP(ctx context.Context, cfg PCAPConfig, ops pcapSetupOps) (_ *pcapResources, setupErr error) {
	if ctx == nil {
		return nil, fmt.Errorf("PCAP setup context cannot be nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	cfg, err := cfg.normalize()
	if err != nil {
		return nil, err
	}

	// Route to the physical peer, never to the encapsulated virtual address.
	peerIP := net.IP(cfg.Peer.Addr().AsSlice())
	iface, gateway, source, err := ops.lookupRoute(peerIP)
	if err != nil {
		return nil, fmt.Errorf("lookup peer route: %w", err)
	}
	if iface == nil || len(iface.HardwareAddr) != 6 || iface.MTU <= 0 {
		return nil, fmt.Errorf("peer route requires an Ethernet interface with a valid MTU")
	}
	source = source.To4()
	if source == nil || !validVirtualIP(netip.AddrFrom4([4]byte(source))) {
		return nil, fmt.Errorf("peer route has no usable IPv4 source")
	}
	if err := ValidateInnerMTU(cfg.MTU, uint32(iface.MTU), 0); err != nil {
		return nil, fmt.Errorf("validate tunnel MTU: %w", err)
	}

	// Require the requested capture device to own the selected source address.
	// Capture names may differ from OS interface names, notably with Npcap.
	devices, err := ops.findDevices()
	if err != nil {
		return nil, fmt.Errorf("enumerate capture devices: %w", err)
	}
	device, err := matchCaptureDevice(cfg.DeviceName, devices, iface, source)
	if err != nil {
		return nil, err
	}

	owned := &pcapResources{
		config: cfg,
		local:  netip.AddrPortFrom(netip.AddrFrom4([4]byte(source)), cfg.LocalPort),
		srcMAC: append(net.HardwareAddr(nil), iface.HardwareAddr...),
	}
	defer func() {
		if setupErr != nil {
			setupErr = errors.Join(setupErr, owned.Close())
		}
	}()

	// Reserve only when requested. Raw PCAP packet transfer does not require
	// a host socket; the CLI can select reservation independently of I/O.
	if cfg.ReserveUDPPort {
		owned.port, err = ops.reservePort(ctx, owned.local)
		if err != nil {
			return nil, fmt.Errorf("reserve local UDP endpoint: %w", err)
		}
	}
	owned.handle, err = ops.openCapture(device.Name, captureSnaplen, false, captureTimeout)
	if err != nil {
		return nil, fmt.Errorf("open tunnel capture: %w", err)
	}
	if owned.handle.LinkType() != layers.LinkTypeEthernet {
		return nil, fmt.Errorf("capture device is not Ethernet")
	}
	if err := owned.handle.SetBPFFilter(tunnelBPFFilter(owned.local, cfg.Peer)); err != nil {
		return nil, fmt.Errorf("set tunnel capture filter: %w", err)
	}

	// Direct peers are ARPed themselves; routed peers use the gateway.
	nextHop := peerIP
	if gateway != nil && !gateway.IsUnspecified() {
		if gateway.To4() == nil {
			return nil, fmt.Errorf("peer route gateway is not IPv4")
		}
		nextHop = gateway.To4()
	}
	arpCtx, cancel := context.WithTimeout(ctx, arpTimeout)
	defer cancel()
	mac, err := ops.resolveARP(arpCtx, device, owned.srcMAC, source, nextHop)
	if err != nil {
		return nil, fmt.Errorf("resolve next-hop MAC: %w", err)
	}
	if len(mac) != 6 || mac[0]&1 != 0 || mac.String() == "00:00:00:00:00:00" {
		return nil, fmt.Errorf("next-hop MAC must be a unicast Ethernet address")
	}
	owned.dstMAC = append(net.HardwareAddr(nil), mac...)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return owned, nil
}

// matchCaptureDevice validates the selected device against the route. Matching
// by source address accommodates capture drivers with different naming schemes.
func matchCaptureDevice(name string, devices []pcap.Interface, iface *net.Interface, source net.IP) (*pcap.Interface, error) {
	for _, device := range devices {
		if device.Name != name {
			continue
		}
		if device.Name == iface.Name {
			return &device, nil
		}
		for _, addr := range device.Addresses {
			if addr.IP.Equal(source) {
				return &device, nil
			}
		}
		return nil, fmt.Errorf("capture device %q does not match peer route interface %q", name, iface.Name)
	}
	return nil, fmt.Errorf("capture device %q was not found", name)
}

// tunnelBPFFilter accepts only the inbound outer tuple, untagged or behind one
// or two VLAN headers. Nesting matters: each vlan keyword advances BPF offsets
// for expressions following it, including expressions in subsequent branches.
func tunnelBPFFilter(local, peer netip.AddrPort) string {
	tuple := fmt.Sprintf("ip and udp and src host %s and dst host %s and src port %d and dst port %d",
		peer.Addr(), local.Addr(), peer.Port(), local.Port())
	return fmt.Sprintf("(%s) or (vlan and ((%s) or (vlan and (%s))))", tuple, tuple, tuple)
}

// Close releases the persistent capture and the UDP reservation exactly once.
// Callers must finish all packet I/O before releasing these resources.
func (p *pcapResources) Close() error {
	p.once.Do(func() {
		if p.handle != nil {
			p.handle.Close()
		}
		if p.port != nil {
			p.closeErr = p.port.Close()
		}
	})
	return p.closeErr
}
