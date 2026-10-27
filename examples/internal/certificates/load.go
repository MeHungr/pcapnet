// Package certificates loads operator-supplied credentials for the examples.
package certificates

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

// Load reads an optional PEM certificate/key pair and an optional PEM CA bundle.
// An empty CA path leaves root selection to the platform trust store. Malformed
// or empty supplied CA bundles are errors; they never disable verification.
func Load(certFile, keyFile, caFile string) ([]tls.Certificate, *x509.CertPool, error) {
	var certs []tls.Certificate
	if (certFile == "") != (keyFile == "") {
		return nil, nil, fmt.Errorf("-cert and -key must be supplied together")
	}
	if certFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, nil, err
		}
		certs = []tls.Certificate{cert}
	}
	var roots *x509.CertPool
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, nil, err
		}
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM(pem) {
			return nil, nil, fmt.Errorf("CA bundle contains no usable certificates")
		}
	}
	return certs, roots, nil
}
