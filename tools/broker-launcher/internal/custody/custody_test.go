package custody

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nkeys"
)

type testPKI struct {
	caCert    *x509.Certificate
	caKey     *ecdsa.PrivateKey
	caPEM     []byte
}

func newTestCA(t *testing.T, cn string) *testPKI {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		t.Fatalf("serial: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return &testPKI{caCert: cert, caKey: key, caPEM: caPEM}
}

func (p *testPKI) issueCert(t *testing.T, cn string, dnsNames []string, ips []net.IP, uris []*url.URL, notAfter time.Time) (certPEM, keyPEM []byte, parsed *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		t.Fatalf("serial: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     dnsNames,
		IPAddresses:  ips,
		URIs:         uris,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.caCert, &key.PublicKey, p.caKey)
	if err != nil {
		t.Fatalf("sign leaf cert: %v", err)
	}
	parsed, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse leaf cert: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal leaf key: %v", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, parsed
}

func TestResolveBytesAndPublicNKey(t *testing.T) {
	dir := t.TempDir()
	ca := newTestCA(t, "test-ca")
	caPath := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caPath, ca.caPEM, 0o600); err != nil {
		t.Fatalf("write ca.pem: %v", err)
	}

	got, err := ResolveBytes("file:" + caPath)
	if err != nil || string(got) != string(ca.caPEM) {
		t.Fatalf("file: resolution failed: got=%d err=%v", len(got), err)
	}

	gotBare, err := ResolveBytes(caPath)
	if err != nil || string(gotBare) != string(ca.caPEM) {
		t.Fatalf("bare path resolution failed: err=%v", err)
	}

	t.Setenv("TEST_PEM_RAW", string(ca.caPEM))
	gotEnvRaw, err := ResolveBytes("env:TEST_PEM_RAW")
	if err != nil || string(gotEnvRaw) != string(ca.caPEM) {
		t.Fatalf("env raw resolution failed: err=%v", err)
	}

	t.Setenv("TEST_PEM_B64", base64.StdEncoding.EncodeToString(ca.caPEM))
	gotEnvB64, err := ResolveBytes("env:TEST_PEM_B64")
	if err != nil || string(gotEnvB64) != string(ca.caPEM) {
		t.Fatalf("env base64 resolution failed: err=%v", err)
	}

	if _, err := ResolveBytes("aws-sm:relayquill/prod/tls"); err == nil {
		t.Fatal("expected unsupported scheme error for aws-sm:")
	}
	if _, err := ResolveBytes("file:" + dir); err == nil {
		t.Fatal("expected directory error")
	}

	kp, err := nkeys.CreateUser()
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	pub, err := kp.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	seed, err := kp.Seed()
	if err != nil {
		t.Fatalf("Seed: %v", err)
	}

	t.Setenv("TEST_PUB_NKEY", pub)
	resolvedPub, err := ResolvePublicNKey("", "env:TEST_PUB_NKEY")
	if err != nil || resolvedPub != pub {
		t.Fatalf("ResolvePublicNKey failed: got=%q err=%v", resolvedPub, err)
	}

	if _, err := ResolvePublicNKey(string(seed), ""); err == nil || !strings.Contains(err.Error(), "seed") {
		t.Fatalf("expected seed rejection error, got %v", err)
	}
}

func TestParseMinTLSVersion(t *testing.T) {
	if v, err := ParseMinTLSVersion(""); err != nil || v != tls.VersionTLS12 {
		t.Fatalf("empty default failed: %v %v", v, err)
	}
	if v, err := ParseMinTLSVersion("1.3"); err != nil || v != tls.VersionTLS13 {
		t.Fatalf("1.3 failed: %v %v", v, err)
	}
	for _, bad := range []string{"1.0", "1.1", "ssl3"} {
		if _, err := ParseMinTLSVersion(bad); err == nil {
			t.Fatalf("expected rejection for %q", bad)
		}
	}
}

func TestRoutePeerAllowlistAndClusterTLS(t *testing.T) {
	ca := newTestCA(t, "cluster-ca")
	future := time.Now().Add(24 * time.Hour)
	spiffeURI, _ := url.Parse("spiffe://relayquill.internal/broker/1")

	b1Cert, b1Key, _ := ca.issueCert(t, "broker-1.internal", []string{"Broker-1.Internal"}, []net.IP{net.ParseIP("127.0.0.1")}, []*url.URL{spiffeURI}, future)
	_, _, rogueSAN := ca.issueCert(t, "rogue.internal", []string{"rogue.internal"}, []net.IP{net.ParseIP("10.9.9.9")}, nil, future)
	_, _, cnOnly := ca.issueCert(t, "broker-1.internal", nil, nil, nil, future)
	expCert, expKey, _ := ca.issueCert(t, "broker-1.internal", []string{"broker-1.internal"}, nil, nil, time.Now().Add(-time.Minute))

	allowlist, err := NewRoutePeerAllowlist([]string{"broker-1.internal", "broker-2.internal"})
	if err != nil {
		t.Fatalf("NewRoutePeerAllowlist: %v", err)
	}
	if allowlist.AllowsCertificate(rogueSAN) {
		t.Fatal("expected rogue SAN to be rejected")
	}
	if allowlist.AllowsCertificate(cnOnly) {
		t.Fatal("expected CN-only certificate without SAN to be rejected")
	}
	if _, err := NewRoutePeerAllowlist([]string{"*.internal"}); err == nil {
		t.Fatal("expected wildcard SAN to be rejected in allowlist")
	}

	t.Setenv("CLUSTER_CA", string(ca.caPEM))
	t.Setenv("B1_CERT", string(b1Cert))
	t.Setenv("B1_KEY", string(b1Key))

	cfg, _, err := BuildClusterTLSConfig(ClusterTLSOptions{
		CARef:        "env:CLUSTER_CA",
		CertRef:      "env:B1_CERT",
		KeyRef:       "env:B1_KEY",
		MinVersion:   "1.3",
		AllowedPeers: []string{"broker-1.internal", "broker-2.internal"},
	})
	if err != nil {
		t.Fatalf("BuildClusterTLSConfig: %v", err)
	}
	if cfg.ClientAuth != tls.RequireAndVerifyClientCert || cfg.MinVersion != tls.VersionTLS13 {
		t.Fatalf("unexpected cluster TLS config: ClientAuth=%v MinVersion=%v", cfg.ClientAuth, cfg.MinVersion)
	}

	if err := cfg.VerifyConnection(tls.ConnectionState{
		VerifiedChains:   [][]*x509.Certificate{{rogueSAN}},
		PeerCertificates: []*x509.Certificate{rogueSAN},
	}); err == nil {
		t.Fatal("expected VerifyConnection to reject unauthorized SAN")
	}

	t.Setenv("EXP_CERT", string(expCert))
	t.Setenv("EXP_KEY", string(expKey))
	if _, _, err := BuildClientTLSConfig(ClientTLSOptions{
		CertRef: "env:EXP_CERT",
		KeyRef:  "env:EXP_KEY",
	}); err == nil {
		t.Fatal("expected expired certificate rejection")
	}
}
