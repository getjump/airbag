// Command echotls is an HTTPS server for test/creds-e2e.sh: it plays a
// host a credential is bound to. It makes its own certificate for
// 127.0.0.1, writes it to DIR/ca.pem and its port to DIR/port, records
// each request's method, path and Authorization in DIR/got, and sends
// the Authorization back, as a careless API might.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

func main() {
	dir := flag.String("dir", ".", "where to write ca.pem, port and got")
	flag.Parse()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "echotls"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(*dir, "ca.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		log.Fatal(err)
	}
	l, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})
	if err != nil {
		log.Fatal(err)
	}
	var mu sync.Mutex
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		mu.Lock()
		f, _ := os.OpenFile(filepath.Join(*dir, "got"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		fmt.Fprintf(f, "%s %s %s\n", r.Method, r.URL.Path, auth)
		f.Close()
		mu.Unlock()
		fmt.Fprintf(w, "you sent: %s\n", auth)
	})
	_, port, _ := net.SplitHostPort(l.Addr().String())
	if err := os.WriteFile(filepath.Join(*dir, "port"), []byte(port), 0o644); err != nil {
		log.Fatal(err)
	}
	log.Fatal(http.Serve(l, h))
}
