package pcapnet

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"

	"github.com/MeHungr/pcapnet/internal/queue"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// UDPCaptureConfig selects UDP prefix capture on one Ethernet interface.
// CaptureUDP observes all destination ports; ListenUDPCapture also permits
// replies on nonzero ports. Neither constructor reserves host sockets.
type UDPCaptureConfig struct {
	DeviceName  string     // Optional; defaults to the interface owning LocalIP
	LocalIP     netip.Addr // Required local unicast IPv4 address
	MagicHeader []byte     // Required nonempty UDP payload prefix; copied during setup
}

// UDPCapture observes matching datagrams without sending packets or binding ports.
// Its queue holds 256 packets and drops new arrivals when full. Capture does not
// consume host socket traffic or prevent the host from sending ICMP responses.
// Close releases the capture handle and wakes pending Receive calls.
type UDPCapture struct {
	resources *pcapResources
	local     netip.Addr
	magic     []byte
	ctx       context.Context
	cancel    context.CancelFunc
	inbox     chan *UDPPacket
	workers   sync.WaitGroup
	once      sync.Once
	mu        sync.Mutex
	err       error
}

// CaptureUDP opens read-only capture for payloads beginning with MagicHeader.
// ctx controls setup only. Receive accepts a separate context for each operation.
// Returned packets own their payload bytes, including the complete magic header.
// Ethernet/IPv4 validation and fragmentation limits match ListenUDP.
func CaptureUDP(ctx context.Context, cfg UDPCaptureConfig) (*UDPCapture, error) {
	return newUDPCapture(ctx, cfg, liveUDPSetupOps())
}

func newUDPCapture(ctx context.Context, cfg UDPCaptureConfig, ops udpSetupOps) (_ *UDPCapture, resultErr error) {
	if ctx == nil {
		return nil, fmt.Errorf("UDP capture setup context cannot be nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !validUDPHost(cfg.LocalIP) {
		return nil, fmt.Errorf("UDP capture requires a local unicast IPv4 address")
	}
	if cfg.DeviceName != "" && strings.TrimSpace(cfg.DeviceName) == "" {
		return nil, fmt.Errorf("capture device name cannot contain only whitespace")
	}
	if len(cfg.MagicHeader) == 0 || len(cfg.MagicHeader) > 65507 {
		return nil, fmt.Errorf("magic header length must be between 1 and 65507")
	}
	magic := bytes.Clone(cfg.MagicHeader)
	iface, err := ops.interfaceForIP(cfg.LocalIP)
	if err != nil {
		return nil, fmt.Errorf("resolve UDP capture interface: %w", err)
	}
	if iface == nil || len(iface.HardwareAddr) != 6 {
		return nil, fmt.Errorf("UDP capture requires an Ethernet interface")
	}
	devices, err := ops.findDevices()
	if err != nil {
		return nil, fmt.Errorf("enumerate UDP capture devices: %w", err)
	}
	device, err := matchCaptureDevice(cfg.DeviceName, devices, iface, net.IP(cfg.LocalIP.AsSlice()))
	if err != nil {
		return nil, err
	}
	resources := &pcapResources{}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, resources.Close())
		}
	}()
	handle, err := ops.openCapture(device.Name, captureSnaplen, false, captureTimeout)
	if err != nil {
		return nil, fmt.Errorf("open UDP capture: %w", err)
	}
	// Adopt only successful opens: a failed native open may return a typed nil.
	resources.handle = handle
	if handle.LinkType() != layers.LinkTypeEthernet {
		return nil, fmt.Errorf("UDP capture device is not Ethernet")
	}
	if err := handle.SetBPFFilter(udpMagicFilter(cfg.LocalIP, magic)); err != nil {
		return nil, fmt.Errorf("set UDP magic filter: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	lifetime, cancel := context.WithCancel(context.Background())
	c := &UDPCapture{resources: resources, local: cfg.LocalIP, magic: magic, ctx: lifetime, cancel: cancel, inbox: make(chan *UDPPacket, 256)}
	c.workers.Add(1)
	go c.capture()
	return c, nil
}

// udpMagicFilter limits native filter size by checking at most 16 prefix bytes.
// The worker checks the entire prefix again, independently of the kernel filter.
// UDP-relative offsets account for IPv4 options; VLAN branches match ListenUDP.
func udpMagicFilter(local netip.Addr, magic []byte) string {
	tuple := fmt.Sprintf("ip and udp and dst host %s", local)
	for i, b := range magic[:min(len(magic), 16)] {
		tuple += fmt.Sprintf(" and udp[%d] = 0x%02x", 8+i, b)
	}
	return fmt.Sprintf("(%s) or (vlan and ((%s) or (vlan and (%s))))", tuple, tuple, tuple)
}

func (c *UDPCapture) capture() {
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
			c.mu.Lock()
			c.err = fmt.Errorf("capture UDP: %w", err)
			c.mu.Unlock()
			// Close joins this worker, so terminal cleanup must run outside it.
			go c.Close()
			return
		}
		if info.CaptureLength != len(data) || info.CaptureLength < info.Length {
			continue
		}
		packet, err := ParseUDPPacket(data)
		if err != nil || packet.DestinationIP != c.local || !validUDPHost(packet.SourceIP) || !bytes.HasPrefix(packet.Payload, c.magic) {
			continue
		}
		select {
		case c.inbox <- packet:
		default:
		}
	}
}

// Receive returns one matching datagram with its source and destination tuple.
// Cancellation affects this call only. After Close, Receive returns net.ErrClosed
// or the terminal capture error. Concurrent receivers share the packet stream.
func (c *UDPCapture) Receive(ctx context.Context) (*UDPPacket, error) {
	if ctx == nil {
		return nil, fmt.Errorf("UDP capture receive context cannot be nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.ctx.Done():
		return nil, c.receiveError()
	case packet := <-c.inbox:
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if c.ctx.Err() != nil {
			return nil, c.receiveError()
		}
		return packet, nil
	}
}

func (c *UDPCapture) receiveError() error {
	if err := c.Err(); err != nil {
		return err
	}
	return net.ErrClosed
}

// Err reports the first terminal capture error. Normal Close leaves Err nil.
func (c *UDPCapture) Err() error { c.mu.Lock(); defer c.mu.Unlock(); return c.err }

// Close is idempotent. It waits for the finite native read timeout before closing
// the handle, avoiding a concurrent native read/close race, then releases packets.
func (c *UDPCapture) Close() error {
	c.once.Do(func() { c.cancel(); c.workers.Wait(); _ = c.resources.Close(); queue.Drain(c.inbox) })
	return nil // Read-only resources contain no fallible socket close operation.
}
