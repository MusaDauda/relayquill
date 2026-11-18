package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nkeys"
)

type syncBuf struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

func reservePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

func writeTestTopology(t *testing.T, dir string, clientPort, monitorPort int) (topPath string, envMap map[string]string) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caSerial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	caTmpl := &x509.Certificate{
		SerialNumber:          caSerial,
		Subject:               pkix.Name{CommonName: "cli-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	srvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	srvSerial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	srvTmpl := &x509.Certificate{
		SerialNumber: srvSerial,
		Subject:      pkix.Name{CommonName: "broker-cli.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"broker-cli.test"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTmpl, caCert, &srvKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	srvKeyDER, err := x509.MarshalECPrivateKey(srvKey)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srvDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: srvKeyDER})

	genPub := func() (string, string) {
		kp, err := nkeys.CreateUser()
		if err != nil {
			t.Fatal(err)
		}
		pub, _ := kp.PublicKey()
		seed, _ := kp.Seed()
		return pub, string(seed)
	}
	rPub, _ := genPub()
	fPub, _ := genPub()
	aPub, aSeed := genPub()

	caFile := filepath.Join(dir, "ca.pem")
	certFile := filepath.Join(dir, "server.crt")
	keyFile := filepath.Join(dir, "server.key")
	if err := os.WriteFile(caFile, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	topJSON := fmt.Sprintf(`{
		"schema_version": 1,
		"server_name": "broker-cli",
		"host": "127.0.0.1",
		"client_port": %d,
		"monitoring": { "enabled": true, "host": "127.0.0.1", "port": %d },
		"tls": {
			"enabled": true,
			"handshake_first": true,
			"min_version": "1.2",
			"ca_ref": %q,
			"cert_ref": %q,
			"key_ref": %q
		},
		"jetstream": {
			"enabled": true,
			"store_dir": %q,
			"max_memory_store": 33554432,
			"max_file_store": 134217728,
			"sync_interval": "always"
		},
		"principals": {
			"relay": { "public_nkey_ref": "env:CLI_RELAY_PUB" },
			"fanout": { "public_nkey_ref": "env:CLI_FANOUT_PUB" },
			"broker_admin": { "public_nkey_ref": "env:CLI_ADMIN_PUB" }
		}
	}`, clientPort, monitorPort, "file:"+caFile, "file:"+certFile, "file:"+keyFile, filepath.Join(dir, "js"))

	topPath = filepath.Join(dir, "topology.json")
	if err := os.WriteFile(topPath, []byte(topJSON), 0o600); err != nil {
		t.Fatal(err)
	}

	envMap = map[string]string{
		"CLI_RELAY_PUB":                      rPub,
		"CLI_FANOUT_PUB":                     fPub,
		"CLI_ADMIN_PUB":                      aPub,
		"RELAYQUILL_BROKER_PROBE_NKEY_SEED_REF": "env:CLI_ADMIN_SEED",
		"CLI_ADMIN_SEED":                     aSeed,
	}
	return topPath, envMap
}

func TestCLIValidateServeHealthcheckAndCleanShutdown(t *testing.T) {
	dir := t.TempDir()
	clientPort := reservePort(t)
	monitorPort := reservePort(t)
	topPath, envMap := writeTestTopology(t, dir, clientPort, monitorPort)
	for k, v := range envMap {
		t.Setenv(k, v)
	}
	readyFile := filepath.Join(dir, "broker.ready")
	getenv := func(k string) string { return envMap[k] }

	// 1. Validate subcommand succeeds without starting a listener.
	var valOut, valErr bytes.Buffer
	if err := run(context.Background(), []string{"validate", "--topology", topPath}, getenv, &valOut, &valErr); err != nil {
		t.Fatalf("validate failed: %v stderr=%s", err, valErr.String())
	}
	var summary struct {
		OK         bool   `json:"ok"`
		ServerName string `json:"server_name"`
		SyncAlways bool   `json:"sync_always"`
	}
	if err := json.Unmarshal(valOut.Bytes(), &summary); err != nil || !summary.OK || !summary.SyncAlways {
		t.Fatalf("unexpected validate output: %s err=%v", valOut.String(), err)
	}

	// 2. Serve with ready-file, verify healthcheck passes, then cancel context for graceful shutdown.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var srvOut, srvErr syncBuf
	doneCh := make(chan error, 1)
	go func() {
		doneCh <- run(ctx, []string{"--topology", topPath, "--ready-file", readyFile, "--probe-inbox-prefix", "_INBOX.rq.admin"}, getenv, &srvOut, &srvErr)
	}()

	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(readyFile); err == nil {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("timed out waiting for ready file\nstdout=%s\nstderr=%s", srvOut.String(), srvErr.String())
		}
		time.Sleep(30 * time.Millisecond)
	}

	var hcOut, hcErr bytes.Buffer
	hcURL := fmt.Sprintf("http://127.0.0.1:%d/healthz?js-enabled-only=true", monitorPort)
	if err := run(context.Background(), []string{"healthcheck", "--url", hcURL}, getenv, &hcOut, &hcErr); err != nil {
		cancel()
		t.Fatalf("healthcheck failed: %v stderr=%s", err, hcErr.String())
	}
	if !strings.Contains(hcOut.String(), `"ok"`) {
		t.Fatalf("unexpected healthcheck output: %s", hcOut.String())
	}

	// Trigger shutdown (equivalent to SIGINT/SIGTERM context cancellation).
	cancel()
	select {
	case err := <-doneCh:
		if err != nil {
			t.Fatalf("run returned error on shutdown: %v\nstderr=%s", err, srvErr.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for graceful shutdown")
	}

	if _, err := os.Stat(readyFile); !os.IsNotExist(err) {
		t.Fatalf("expected ready file to be removed on shutdown, stat err=%v", err)
	}
}

func TestCLIRejectsMissingTopologyAndNonLoopbackHealthcheck(t *testing.T) {
	var out, errBuf bytes.Buffer
	if err := run(context.Background(), []string{}, func(string) string { return "" }, &out, &errBuf); err == nil {
		t.Fatal("expected error when --topology is omitted")
	}
	if err := run(context.Background(), []string{"healthcheck", "--url", "http://169.254.169.254/latest"}, func(string) string { return "" }, &out, &errBuf); err == nil {
		t.Fatal("expected error when healthcheck targets non-loopback host")
	}
}
