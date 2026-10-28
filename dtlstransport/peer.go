package dtlstransport

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"strings"
	"time"

	"github.com/MeHungr/pcapnet"
	"github.com/pion/dtls/v3"
)

// cloneCertificates reparses owned DER so callers cannot mutate retained
// verification evidence through x509.Certificate's exported slices or pointers.
func cloneCertificates(certs []*x509.Certificate) []*x509.Certificate {
	out := make([]*x509.Certificate, len(certs))
	for i, cert := range certs {
		out[i], _ = x509.ParseCertificate(bytes.Clone(cert.Raw))
	}
	return out
}
func cloneInfo(info pcapnet.PeerInformation) pcapnet.PeerInformation {
	info.Certificates = cloneCertificates(info.Certificates)
	info.LocalCertificates = cloneCertificates(info.LocalCertificates)
	chains := make([][]*x509.Certificate, len(info.VerifiedChains))
	for i, chain := range info.VerifiedChains {
		chains[i] = cloneCertificates(chain)
	}
	info.VerifiedChains = chains
	return info
}

// PeerInfo returns detached evidence for a currently active exact handle. A
// retained result becomes historical when its Done channel closes. Applications
// bind their own sensor UUID/authorization policy to this verified evidence.
func (e *Endpoint) PeerInfo(peer pcapnet.Peer) (pcapnet.PeerInformation, error) {
	e.mu.Lock()
	p := e.peers[peer]
	if p == nil || p.retired || e.closing || e.ctx.Err() != nil {
		e.mu.Unlock()
		return pcapnet.PeerInformation{}, pcapnet.ErrPeerNotFound
	}
	info := p.info // Immutable after publication; clone outside the endpoint lock.
	e.mu.Unlock()
	return cloneInfo(info), nil
}

// PeerDone returns a broadcast invalidation channel for an exact active handle.
// Channels close on explicit retirement, read failure, idle expiry, or Close.
func (e *Endpoint) PeerDone(peer pcapnet.Peer) (<-chan struct{}, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	p := e.peers[peer]
	if p == nil || p.retired || e.closing || e.ctx.Err() != nil {
		return nil, pcapnet.ErrPeerNotFound
	}
	return p.done, nil
}

// DisconnectPeer retires one exact handle before waiting for DTLS cleanup.
// Cancellation bounds waiting; retirement continues and cannot be undone. Stale
// handles are idempotent no-ops. Use TCPServer.DisconnectPeer to additionally wait
// for associated PCAT/TCP cleanup. No application callbacks run during retirement.
func (e *Endpoint) DisconnectPeer(ctx context.Context, peer pcapnet.Peer) error {
	if err := invalidContext(ctx); err != nil {
		return err
	}
	e.mu.Lock()
	p := e.peers[peer]
	e.mu.Unlock()
	if p == nil {
		return nil
	}
	e.remove(p)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-p.cleaned:
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-p.finished:
		return nil
	}
}

// verificationOptions records the actual verified chains supplied by Pion after
// ordinary verification. Selection callbacks record only the certificate chosen
// for this handshake, including an empty client selection when none is requested.
func (e *Endpoint) verificationOptions(p *connection) []dtls.Option {
	return []dtls.Option{dtls.WithVerifyPeerCertificate(func(_ [][]byte, chains [][]*x509.Certificate) error {
		e.mu.Lock()
		defer e.mu.Unlock()
		p.info.VerifiedChains = make([][]*x509.Certificate, len(chains))
		for i, chain := range chains {
			p.info.VerifiedChains[i] = cloneCertificates(chain)
		}
		return nil
	})}
}
func (e *Endpoint) selected(p *connection, cert *tls.Certificate) *tls.Certificate {
	e.mu.Lock()
	defer e.mu.Unlock()
	p.info.LocalCertificates = nil
	for _, der := range cert.Certificate {
		parsed, _ := x509.ParseCertificate(bytes.Clone(der))
		p.info.LocalCertificates = append(p.info.LocalCertificates, parsed)
	}
	return cert
}
func (e *Endpoint) serverCertificate(p *connection, hello *dtls.ClientHelloInfo) (*tls.Certificate, error) {
	// Match SNI first, then fall back to the first configured chain, as Pion does.
	// Supplying only this getter ensures it also runs for IP/no-SNI handshakes.
	cert := &e.server.Certificates[0]
	if hello.ServerName != "" {
		for i := range e.server.Certificates {
			candidate := &e.server.Certificates[i]
			leaf, _ := x509.ParseCertificate(candidate.Certificate[0])
			if leaf.VerifyHostname(strings.TrimRight(hello.ServerName, ".")) == nil {
				cert = candidate
				break
			}
		}
	}
	return e.selected(p, cert), nil
}
func (e *Endpoint) clientCertificate(p *connection, certs []tls.Certificate, request *dtls.CertificateRequestInfo) (*tls.Certificate, error) {
	for i := range certs {
		if request.SupportsCertificate(&certs[i]) == nil {
			return e.selected(p, &certs[i]), nil
		}
	}
	return e.selected(p, &tls.Certificate{}), nil
}

func (e *Endpoint) finishInfo(p *connection, certs []*x509.Certificate) {
	p.info.Peer = p.peer
	p.info.Encrypted = true
	p.info.Certificates = cloneCertificates(certs)
	p.info.PeerCertificateAuthenticated = len(p.info.VerifiedChains) != 0
	p.info.ClientCertificateAuthenticated = (e.server != nil && p.info.PeerCertificateAuthenticated) || (e.server == nil && len(p.info.LocalCertificates) != 0)
	p.info.EstablishedAt = time.Now()
	p.info.Done = p.done
}

func channelRetired(done <-chan struct{}) bool {
	select {
	case <-done:
		return true
	default:
		return false
	}
}
