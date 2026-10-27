package pcapnet

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"time"
)

// The fixed header contains only a protocol marker/version, message type, two
// zero reserved bytes, and an opaque request/session ID. No implementation names
// or error text are transmitted. This format is deliberately incompatible with
// the original unframed fixed-peer tunnel.
const (
	sessionHeaderSize = 24
	sessionMagic      = "PCAT"
	sessionVersion    = 1
)
const (
	sessionRequest    byte = 1
	sessionAssignment byte = 2
	sessionRejected   byte = 3
	sessionData       byte = 4
	sessionKeepalive  byte = 5
)

type sessionID [16]byte

func sessionMessage(kind byte, id sessionID, payload []byte) []byte {
	b := make([]byte, sessionHeaderSize+len(payload))
	copy(b, sessionMagic)
	b[4] = sessionVersion
	b[5] = kind
	copy(b[8:24], id[:])
	copy(b[24:], payload)
	return b
}
func parseSessionMessage(b []byte) (byte, sessionID, []byte, error) {
	var id sessionID
	if len(b) < sessionHeaderSize || string(b[:4]) != sessionMagic || b[4] != sessionVersion || b[6] != 0 || b[7] != 0 {
		return 0, id, nil, fmt.Errorf("invalid tunnel header")
	}
	copy(id[:], b[8:24])
	payload := b[24:]
	valid := false
	switch b[5] {
	case sessionRequest, sessionRejected, sessionKeepalive:
		valid = len(payload) == 0
	case sessionAssignment:
		valid = len(payload) == 30
	case sessionData:
		valid = len(payload) >= 20
	}
	if !valid {
		return 0, id, nil, fmt.Errorf("invalid tunnel message")
	}
	return b[5], id, payload, nil
}

// Assignment is the virtual configuration negotiated before starting gVisor.
// Session tokens stay private to the transport and are not application identity.
type Assignment struct {
	VirtualIP netip.Addr
	ServerIP  netip.Addr
	MTU       uint32
}

func encodeAssignment(a Assignment, token sessionID, seconds uint32) []byte {
	b := make([]byte, 30)
	copy(b, token[:])
	client, server := a.VirtualIP.As4(), a.ServerIP.As4()
	copy(b[16:20], client[:])
	copy(b[20:24], server[:])
	binary.BigEndian.PutUint16(b[24:26], uint16(a.MTU))
	binary.BigEndian.PutUint32(b[26:30], seconds)
	return b
}

// decodeAssignment centralizes wire bounds and negotiated configuration checks.
// Callers may parse untrusted replies before any virtual stack exists.
func decodeAssignment(payload []byte, maxMTU uint32) (Assignment, sessionID, time.Duration, error) {
	var a Assignment
	var token sessionID
	if len(payload) != 30 {
		return a, token, 0, fmt.Errorf("invalid tunnel assignment size")
	}
	copy(token[:], payload[:16])
	a = Assignment{
		VirtualIP: netip.AddrFrom4([4]byte(payload[16:20])),
		ServerIP:  netip.AddrFrom4([4]byte(payload[20:24])),
		MTU:       uint32(binary.BigEndian.Uint16(payload[24:26])),
	}
	lease := time.Duration(binary.BigEndian.Uint32(payload[26:30])) * time.Second
	if !validVirtualIP(a.VirtualIP) || !validVirtualIP(a.ServerIP) || a.VirtualIP == a.ServerIP || a.MTU < MinIPv4MTU || a.MTU > maxMTU || lease < 3*time.Second || lease > 24*time.Hour {
		return Assignment{}, sessionID{}, 0, fmt.Errorf("invalid tunnel assignment")
	}
	return a, token, lease, nil
}
