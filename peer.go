package pcapnet

import (
	"context"
	"crypto/x509"
	"errors"
	"time"
)

// ErrPeerNotFound means the exact peer handle is not currently active.
var ErrPeerNotFound = errors.New("pcapnet: peer is not active")

// PeerInformation is a detached authentication snapshot, never an application
// identity claim. Certificate objects and DER bytes belong to the caller. No
// private keys are included. Done closes on retirement; retained snapshots then
// describe historical authentication, not a currently authorized connection.
// Raw transport has Encrypted=false and no certificate authentication evidence.
type PeerInformation struct {
	Peer                           Peer                  // Exact handle, including its opaque secure connection ID.
	Encrypted                      bool                  // Encryption does not itself establish sensor identity.
	PeerCertificateAuthenticated   bool                  // The remote certificate chain was verified.
	ClientCertificateAuthenticated bool                  // Client-certificate proof participated in the handshake.
	Certificates                   []*x509.Certificate   // Presented peer chain, leaf first; caller-owned copies.
	VerifiedChains                 [][]*x509.Certificate // Actual handshake verification results, including roots.
	LocalCertificates              []*x509.Certificate   // Selected local chain; empty if none was sent; no private keys.
	EstablishedAt                  time.Time             // Authentication snapshot creation time.
	Done                           <-chan struct{}       // Closed means historical, not currently active; raw endpoints expose endpoint lifetime.

}

// PeerInfoProvider optionally supplies authentication evidence for an exact peer.
// A stale secure handle must return ErrPeerNotFound, never replacement metadata.
type PeerInfoProvider interface {
	PeerInfo(Peer) (PeerInformation, error)
}

// PeerLifecycle optionally exposes exact-peer invalidation without callbacks.
// Implementations reject delivery from retired peers, including queued data. Multiple observers can
// wait independently; no unsubscribe is necessary and no callback can deadlock
// endpoint shutdown. Previously returned channels remain closed after retirement.
type PeerLifecycle interface {
	PeerDone(Peer) (<-chan struct{}, error)
}

// PeerDisconnecter optionally retires one exact peer. Invalidation precedes
// cleanup; ctx bounds waiting, not the retirement itself. Repeated/stale requests
// are harmless and must never target replacements sharing a physical address.
// Other peers and the shared endpoint remain open.
type PeerDisconnecter interface {
	DisconnectPeer(context.Context, Peer) error
}

// PeerInfo reports raw UDP's lack of cryptographic authentication. Done describes
// this endpoint's lifetime; raw UDP cannot detect remote disconnect/reconnection.
func (p *PlainUDPEndpoint) PeerInfo(peer Peer) (PeerInformation, error) {
	if peer.ConnectionID != ([16]byte{}) || !peer.IsValid() || peer.Port() == 0 || p.conn.ctx.Err() != nil {
		return PeerInformation{}, ErrPeerNotFound
	}
	if p.conn.peer.IsValid() && peer.AddrPort != p.conn.peer {
		return PeerInformation{}, ErrPeerNotFound
	}
	return PeerInformation{Peer: peer, Done: p.conn.ctx.Done()}, nil
}
