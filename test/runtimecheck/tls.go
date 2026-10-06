//go:build linux

package main

import (
	"crypto/tls"
	"crypto/x509"
)

func tlsConfig(roots *x509.CertPool) *tls.Config {
	return &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
}
