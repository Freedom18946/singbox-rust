// reality-fixture-helper: in-repo, stdlib-only helper servers for the A1
// local REALITY fixture. Replaces external/public deps and the fragile
// `openssl s_server` / `socat OPENSSL` daemons used in the A0 spike.
//
//	-mode tls-dest    concurrent TLS listener (runtime self-signed cert) used as
//	                  the REALITY server's handshake.server / dest target.
//	-mode http-target concurrent HTTP server returning a fixed token body.
//
// Both modes print "READY ..." on stdout once listening (readiness signal),
// handle each connection in its own goroutine (no serial-wedge), and exit on
// SIGTERM via the parent's process teardown.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"time"
)

func selfSigned(sni string) tls.Certificate {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("keygen: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: sni},
		DNSNames:              []string{sni},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		log.Fatalf("cert: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// runTLSDest is a concurrent TLS server. Go's crypto/tls does no ClientHello
// inspection, so it accepts any relayed hello (the Go client's uTLS-Chrome hello
// and the Rust client's plain rustls hello alike) without classifying it — which
// is exactly what the REALITY server's handshake dest must do here.
func runTLSDest(listen, sni string) {
	cfg := &tls.Config{Certificates: []tls.Certificate{selfSigned(sni)}, MinVersion: tls.VersionTLS12}
	ln, err := tls.Listen("tcp", listen, cfg)
	if err != nil {
		log.Fatalf("tls listen %s: %v", listen, err)
	}
	fmt.Printf("READY mode=tls-dest addr=%s sni=%s\n", listen, sni)
	os.Stdout.Sync()
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go func(c net.Conn) {
			defer c.Close()
			tc := c.(*tls.Conn)
			_ = tc.SetDeadline(time.Now().Add(10 * time.Second))
			if err := tc.Handshake(); err != nil {
				log.Printf("handshake from %s: %v", c.RemoteAddr(), err)
				return
			}
			buf := make([]byte, 1024)
			_, _ = tc.Read(buf)
			_, _ = tc.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\nlocaldest"))
		}(c)
	}
}

// runHTTPTarget serves a fixed token for any path (concurrent via http.Server).
func runHTTPTarget(listen, token string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Connection", "close")
		fmt.Fprint(w, token)
	})
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		log.Fatalf("http listen %s: %v", listen, err)
	}
	fmt.Printf("READY mode=http-target addr=%s token=%s\n", listen, token)
	os.Stdout.Sync()
	srv := &http.Server{Handler: mux}
	if err := srv.Serve(ln); err != nil {
		log.Fatalf("serve: %v", err)
	}
}

func main() {
	mode := flag.String("mode", "", "tls-dest | http-target")
	listen := flag.String("listen", "127.0.0.1:0", "listen address host:port")
	sni := flag.String("sni", "localhost", "tls-dest self-signed cert CN/SAN")
	token := flag.String("token", "ok", "http-target response body token")
	flag.Parse()
	switch *mode {
	case "tls-dest":
		runTLSDest(*listen, *sni)
	case "http-target":
		runHTTPTarget(*listen, *token)
	default:
		log.Fatalf("unknown -mode %q (want tls-dest|http-target)", *mode)
	}
}
