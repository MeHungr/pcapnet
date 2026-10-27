package pcapnet

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
)

// TCPServer owns one shared virtual stack and its TCP listener. Closing it also
// closes accepted connections, session workers, and the datagram endpoint.
type TCPServer struct {
	net.Listener
	stack *VirtualStack
	once  sync.Once
	err   error
}

// NewTCPServer allocates peer addresses over endpoint and starts one shared
// gVisor stack. Initial validation failures leave endpoint owned by the caller.
// Once dispatch starts, the server owns endpoint, including setup rollback.
func NewTCPServer(endpoint DatagramEndpoint, cfg ServerConfig, port int) (*TCPServer, error) {
	cfg, err := cfg.normalize()
	if err != nil {
		return nil, err
	}
	if port < 1 || port > 65535 {
		return nil, errors.New("invalid TCP listening port")
	}
	transport, err := NewServerTransport(endpoint, cfg)
	if err != nil {
		return nil, err
	}
	v, err := NewVirtualStackWithTransport(Config{VirtualIP: cfg.VirtualIP, PeerSubnet: cfg.AddressPool, MTU: cfg.MTU}, transport)
	if err != nil {
		return nil, errors.Join(err, transport.Close())
	}
	listener, err := v.Listen(port)
	if err != nil {
		v.Close()
		return nil, errors.Join(err, v.Err())
	}
	return &TCPServer{Listener: listener, stack: v}, nil
}

// Close stops the shared stack, listener, sessions, and accepted connections.
func (s *TCPServer) Close() error {
	s.once.Do(func() { s.stack.Close(); s.err = s.stack.Err() })
	return s.err
}

// ListenPCAPTCP opens a plain PCAP UDP endpoint and a shared TCP server.
// ctx controls setup only; configuration and endpoint lifetimes end at Close.
func ListenPCAPTCP(ctx context.Context, udp UDPConfig, cfg ServerConfig, port int) (*TCPServer, error) {
	conn, err := ListenUDP(ctx, udp)
	if err != nil {
		return nil, err
	}
	endpoint, _ := NewPlainUDPEndpoint(conn)
	server, err := NewTCPServer(endpoint, cfg, port)
	if err != nil {
		return nil, errors.Join(err, endpoint.Close())
	}
	return server, nil
}

// DialPCAPStack opens plain PCAP UDP, allocates a virtual address, and creates a
// client stack. Callers can open multiple TCP connections on the returned stack.
func DialPCAPStack(ctx context.Context, cfg UDPConfig, peer netip.AddrPort, mtu uint32) (*VirtualStack, Assignment, error) {
	conn, err := DialUDP(ctx, cfg, peer)
	if err != nil {
		return nil, Assignment{}, err
	}
	endpoint, _ := NewPlainUDPEndpoint(conn)
	return DialStack(ctx, endpoint, Peer{AddrPort: peer}, mtu)
}

// DialStack allocates an address and attaches a supplied datagram endpoint to a
// client stack. It owns endpoint on entry and closes it on any setup failure.
// This is the same path for plain, DTLS, and mutually authenticated DTLS clients.
func DialStack(ctx context.Context, endpoint DatagramEndpoint, peer Peer, mtu uint32) (*VirtualStack, Assignment, error) {
	if nilInterface(endpoint) {
		return nil, Assignment{}, errors.New("datagram endpoint is required")
	}
	transport, a, err := AllocateClient(ctx, endpoint, peer, mtu)
	if err != nil {
		return nil, Assignment{}, errors.Join(err, endpoint.Close())
	}
	v, err := NewVirtualStackWithTransport(Config{VirtualIP: a.VirtualIP, PeerSubnet: netip.PrefixFrom(a.ServerIP, 32), MTU: a.MTU}, transport)
	if err != nil {
		return nil, Assignment{}, errors.Join(err, transport.Close())
	}
	return v, a, nil
}
