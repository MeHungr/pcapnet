// Package dtlstransport provides an optional DTLS 1.2 adapter for pcapnet.
// It uses Pion DTLS with certificate authentication and AES-128-GCM. Applications
// supply certificates, trust roots, and authorization policy; pcapnet's allocation
// and TCP code do not depend on DTLS. Plain and secure endpoints are explicit
// alternatives: there is no opportunistic downgrade to plaintext.
package dtlstransport

import (
	"bytes"
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"reflect"
	"time"

	"github.com/MeHungr/pcapnet"
	"github.com/pion/dtls/v3"
)

// PeerInfo is local authorization input after certificate verification. Peer is
// the opaque connection handle exposed to the allocation layer, not a claim of
// application identity. Certificates are the presented chain, leaf first. In
// server-authentication-only mode the client chain can be empty.
type PeerInfo struct {
	Peer         pcapnet.Peer
	Certificates []*x509.Certificate
}

// Limits bounds secure transport resources independently of address leases.
// Zero values use 128 connections, a 10-second handshake timeout, and a 5-minute
// application-data idle timeout. Pending handshakes count toward MaxPeers.
type Limits struct {
	MaxPeers         int
	HandshakeTimeout time.Duration
	IdleTimeout      time.Duration
}

func (l Limits) normalized() (Limits, error) {
	if l.MaxPeers == 0 {
		l.MaxPeers = 128
	}
	if l.HandshakeTimeout == 0 {
		l.HandshakeTimeout = 10 * time.Second
	}
	if l.IdleTimeout == 0 {
		l.IdleTimeout = 5 * time.Minute
	}
	if l.MaxPeers < 1 || l.HandshakeTimeout < 0 || l.IdleTimeout < 0 {
		return l, fmt.Errorf("invalid DTLS limits")
	}
	return l, nil
}

// ClientConfig requires a ServerName matching the server certificate. RootCAs
// defaults to the system trust store. Certificates optionally supply a client
// chain for mutual TLS. Authorize may impose additional policy after normal
// certificate verification; it must honor ctx. Configuration must remain immutable
// while the endpoint is in use. Private keys and trust roots are never generated
// or loaded implicitly by this package.
type ClientConfig struct {
	ServerName   string
	RootCAs      *x509.CertPool
	Certificates []tls.Certificate
	Limits       Limits
	Authorize    func(context.Context, PeerInfo) error
}

// ServerConfig presents Certificates to clients. RequireClientCertificate enables
// certificate verification against ClientCAs (or system roots if nil). Authorize
// can enforce finer policy after verification; it must honor ctx. Disabling
// client-certificate verification allows any client to request a tunnel address.
// Configuration must remain immutable while the endpoint is in use.
type ServerConfig struct {
	Certificates             []tls.Certificate
	ClientCAs                *x509.CertPool
	RequireClientCertificate bool
	Limits                   Limits
	Authorize                func(context.Context, PeerInfo) error
}

// DTLS 1.2 AES-GCM adds a 13-byte record header, 8-byte explicit nonce, and
// 16-byte authentication tag. CID and padding are disabled, so this bound is
// exact for application records. Both permitted certificate suites use it.
const recordOverhead = 13 + 8 + 16

// Pion v3.1.15 reads encrypted datagrams into an 8192-byte buffer. Keep both
// application records and handshake flights within that bound on jumbo links.
// Revisit this implementation limit when upgrading the DTLS dependency.
const maxDTLSDatagramSize = 8192

func commonOptions(mtu int) []dtls.Option {
	return []dtls.Option{
		dtls.WithCipherSuites(dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, dtls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256),
		dtls.WithExtendedMasterSecret(dtls.RequireExtendedMasterSecret),
		dtls.WithReplayProtectionWindow(128), dtls.WithMTU(mtu),
	}
}

// validateRaw and validCertificates run before starting workers or taking raw
// endpoint ownership, so malformed credentials fail locally and immediately.
func validateRaw(raw pcapnet.DatagramEndpoint) error {
	if nilValue(raw) {
		return fmt.Errorf("datagram endpoint is required")
	}
	if raw.MaxDatagramSize() < muxHeaderSize+recordOverhead+1 {
		return fmt.Errorf("datagram capacity is too small for DTLS")
	}
	return nil
}
func nilValue(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Func, reflect.Slice, reflect.Chan, reflect.Interface:
		return v.IsNil()
	}
	return false
}
func validCertificates(certs []tls.Certificate) error {
	if len(certs) == 0 {
		return fmt.Errorf("certificate is required")
	}
	for _, cert := range certs {
		if len(cert.Certificate) == 0 || nilValue(cert.PrivateKey) {
			return fmt.Errorf("certificate chain and private key are required")
		}
		signer, ok := cert.PrivateKey.(crypto.Signer)
		if !ok {
			return fmt.Errorf("certificate private key must support signing")
		}
		var leaf *x509.Certificate
		for i, der := range cert.Certificate {
			parsed, err := x509.ParseCertificate(der)
			if err != nil {
				return fmt.Errorf("invalid certificate chain: %w", err)
			}
			if i == 0 {
				leaf = parsed
			}
		}
		public, err := x509.MarshalPKIXPublicKey(signer.Public())
		if err != nil {
			return fmt.Errorf("invalid certificate public key: %w", err)
		}
		if !bytes.Equal(public, leaf.RawSubjectPublicKeyInfo) {
			return fmt.Errorf("certificate does not match private key")
		}
	}
	return nil
}
