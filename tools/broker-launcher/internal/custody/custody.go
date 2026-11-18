package custody

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/nats-io/nkeys"
)

const maxCustodyFileBytes = 1 << 20 // 1 MiB safety bound for PEM/NKey material

var envVarNameRegex = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// ClientTLSOptions describes custody references and policy for the client listener TLS config.
type ClientTLSOptions struct {
	CertRef          string
	KeyRef           string
	CARef            string
	MinVersion       string
	VerifyClientCert bool
}

// ClusterTLSOptions describes custody references and peer policy for cluster route mTLS.
type ClusterTLSOptions struct {
	CARef        string
	CertRef      string
	KeyRef       string
	MinVersion   string
	AllowedPeers []string
}

// RoutePeerAllowlist enforces explicit peer certificate SAN membership for cluster routes.
type RoutePeerAllowlist struct {
	dnsNames map[string]struct{}
	ips      map[netip.Addr]struct{}
	uris     map[string]struct{}
}

// NewRoutePeerAllowlist builds a validated allowlist of exact DNS, IP, or URI SANs.
func NewRoutePeerAllowlist(peers []string) (*RoutePeerAllowlist, error) {
	if len(peers) == 0 {
		return nil, errors.New("cluster allowed_route_peers must contain at least one explicit peer SAN")
	}

	allowlist := &RoutePeerAllowlist{
		dnsNames: make(map[string]struct{}),
		ips:      make(map[netip.Addr]struct{}),
		uris:     make(map[string]struct{}),
	}

	for _, raw := range peers {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			return nil, errors.New("cluster allowed_route_peers contains an empty entry")
		}
		if strings.ContainsAny(entry, "* \t\r\n") {
			return nil, fmt.Errorf("cluster allowed_route_peers entry %q must be an explicit non-wildcard identity", entry)
		}
		if addr, err := netip.ParseAddr(entry); err == nil {
			allowlist.ips[addr.Unmap()] = struct{}{}
			continue
		}
		if strings.Contains(entry, "://") {
			allowlist.uris[entry] = struct{}{}
			continue
		}
		allowlist.dnsNames[strings.ToLower(entry)] = struct{}{}
	}

	return allowlist, nil
}

// AllowsCertificate verifies that the leaf certificate presents at least one allowed SAN.
func (a *RoutePeerAllowlist) AllowsCertificate(cert *x509.Certificate) bool {
	if a == nil || cert == nil {
		return false
	}
	for _, dns := range cert.DNSNames {
		if _, ok := a.dnsNames[strings.ToLower(strings.TrimSpace(dns))]; ok {
			return true
		}
	}
	for _, ip := range cert.IPAddresses {
		if addr, ok := netip.AddrFromSlice(ip); ok {
			if _, allowed := a.ips[addr.Unmap()]; allowed {
				return true
			}
		}
	}
	for _, uri := range cert.URIs {
		if uri != nil {
			if _, ok := a.uris[uri.String()]; ok {
				return true
			}
		}
	}
	return false
}

// ParseMinTLSVersion maps supported version strings ("1.2", "1.3") to crypto/tls constants.
func ParseMinTLSVersion(raw string) (uint16, error) {
	switch strings.TrimSpace(raw) {
	case "", "1.2":
		return tls.VersionTLS12, nil
	case "1.3":
		return tls.VersionTLS13, nil
	default:
		return 0, fmt.Errorf("unsupported minimum TLS version %q (must be \"1.2\" or \"1.3\")", raw)
	}
}

// ResolveBytes loads credential or certificate material from "file:<path>", "env:<VAR>", or a local path.
func ResolveBytes(ref string) ([]byte, error) {
	trimmed := strings.TrimSpace(ref)
	if trimmed == "" {
		return nil, errors.New("custody reference cannot be empty")
	}
	if strings.ContainsAny(trimmed, "\r\n\x00") {
		return nil, errors.New("custody reference contains invalid control characters")
	}

	if after, ok := strings.CutPrefix(trimmed, "env:"); ok {
		varName := strings.TrimSpace(after)
		if !envVarNameRegex.MatchString(varName) {
			return nil, fmt.Errorf("invalid environment variable custody reference %q", varName)
		}
		rawVal, exists := os.LookupEnv(varName)
		if !exists || strings.TrimSpace(rawVal) == "" {
			return nil, fmt.Errorf("required custody environment variable %s is unset or empty", varName)
		}
		if !strings.Contains(rawVal, "-----BEGIN ") {
			if decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(rawVal)); err == nil && strings.Contains(string(decoded), "-----BEGIN ") {
				return decoded, nil
			}
		}
		return []byte(rawVal), nil
	}

	if after, ok := strings.CutPrefix(trimmed, "file:"); ok {
		return readBoundedFile(strings.TrimSpace(after))
	}

	// Reject unresolved external secret schemes while preserving Windows drive paths (e.g. C:\...).
	if colonIdx := strings.IndexByte(trimmed, ':'); colonIdx > 1 {
		scheme := trimmed[:colonIdx]
		return nil, fmt.Errorf("unsupported custody reference scheme %q; resolve external secrets to file: or env: before launch", scheme)
	}

	return readBoundedFile(trimmed)
}

// ResolvePublicNKey resolves an inline public user NKey or a custody reference pointing to one.
func ResolvePublicNKey(inlineValue, ref string) (string, error) {
	val := strings.TrimSpace(inlineValue)
	if val == "" && strings.TrimSpace(ref) != "" {
		raw, err := ResolveBytes(ref)
		if err != nil {
			return "", fmt.Errorf("resolving public NKey reference: %w", err)
		}
		val = strings.TrimSpace(string(raw))
	}
	if val == "" {
		return "", errors.New("public NKey is missing")
	}
	if strings.HasPrefix(val, "S") {
		return "", errors.New("private NKey seed must not be used in public NKey configuration")
	}
	if !nkeys.IsValidPublicUserKey(val) {
		return "", errors.New("value is not a valid public NKey user identity")
	}
	return val, nil
}

// BuildClientTLSConfig loads the client-listener certificate/key and optional CA into memory.
func BuildClientTLSConfig(opts ClientTLSOptions) (*tls.Config, *x509.CertPool, error) {
	minVer, err := ParseMinTLSVersion(opts.MinVersion)
	if err != nil {
		return nil, nil, err
	}

	certPEM, err := ResolveBytes(opts.CertRef)
	if err != nil {
		return nil, nil, fmt.Errorf("loading client TLS certificate: %w", err)
	}
	keyPEM, err := ResolveBytes(opts.KeyRef)
	if err != nil {
		return nil, nil, fmt.Errorf("loading client TLS private key: %w", err)
	}
	defer clear(keyPEM)

	cert, err := loadKeyPairFromPEM(certPEM, keyPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing client TLS key pair: %w", err)
	}

	var caPool *x509.CertPool
	if strings.TrimSpace(opts.CARef) != "" {
		caPEM, err := ResolveBytes(opts.CARef)
		if err != nil {
			return nil, nil, fmt.Errorf("loading client TLS CA bundle: %w", err)
		}
		caPool, err = ParseCertPoolFromPEM(caPEM)
		if err != nil {
			return nil, nil, fmt.Errorf("parsing client TLS CA bundle: %w", err)
		}
	}

	if opts.VerifyClientCert && caPool == nil {
		return nil, nil, errors.New("client TLS verification requires a CA bundle")
	}

	cfg := &tls.Config{
		Certificates:     []tls.Certificate{cert},
		MinVersion:       minVer,
		CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384},
	}
	if opts.VerifyClientCert {
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
		cfg.ClientCAs = caPool
	}
	return cfg, caPool, nil
}

// BuildClusterTLSConfig builds mutual TLS configuration for cluster routes with explicit SAN checks.
func BuildClusterTLSConfig(opts ClusterTLSOptions) (*tls.Config, *RoutePeerAllowlist, error) {
	minVer, err := ParseMinTLSVersion(opts.MinVersion)
	if err != nil {
		return nil, nil, err
	}
	allowlist, err := NewRoutePeerAllowlist(opts.AllowedPeers)
	if err != nil {
		return nil, nil, err
	}

	caPEM, err := ResolveBytes(opts.CARef)
	if err != nil {
		return nil, nil, fmt.Errorf("loading cluster route CA bundle: %w", err)
	}
	caPool, err := ParseCertPoolFromPEM(caPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing cluster route CA bundle: %w", err)
	}

	certPEM, err := ResolveBytes(opts.CertRef)
	if err != nil {
		return nil, nil, fmt.Errorf("loading cluster route certificate: %w", err)
	}
	keyPEM, err := ResolveBytes(opts.KeyRef)
	if err != nil {
		return nil, nil, fmt.Errorf("loading cluster route private key: %w", err)
	}
	defer clear(keyPEM)

	cert, err := loadKeyPairFromPEM(certPEM, keyPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing cluster route key pair: %w", err)
	}
	if !allowlist.AllowsCertificate(cert.Leaf) {
		return nil, nil, errors.New("node cluster route certificate SAN is not permitted by allowed_route_peers")
	}

	cfg := &tls.Config{
		Certificates:     []tls.Certificate{cert},
		RootCAs:          caPool,
		ClientCAs:        caPool,
		ClientAuth:       tls.RequireAndVerifyClientCert,
		MinVersion:       minVer,
		CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384},
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.VerifiedChains) == 0 || len(cs.PeerCertificates) == 0 {
				return errors.New("cluster route peer presented no verified certificate chain")
			}
			if !allowlist.AllowsCertificate(cs.PeerCertificates[0]) {
				return errors.New("cluster route peer certificate SAN is not in allowed_route_peers")
			}
			return nil
		},
	}
	return cfg, allowlist, nil
}

// ParseCertPoolFromPEM parses one or more PEM-encoded X.509 certificates into a CertPool.
func ParseCertPoolFromPEM(caPEM []byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("failed to parse any PEM certificates")
	}
	return pool, nil
}

// CertFingerprintSHA256 returns the lowercase hex SHA-256 digest of a certificate's raw DER bytes.
func CertFingerprintSHA256(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

func loadKeyPairFromPEM(certPEM, keyPEM []byte) (tls.Certificate, error) {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, err
	}
	if len(cert.Certificate) == 0 {
		return tls.Certificate{}, errors.New("X.509 key pair contains no certificate")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("parsing leaf certificate: %w", err)
	}
	now := time.Now()
	if now.Before(leaf.NotBefore) {
		return tls.Certificate{}, fmt.Errorf("certificate %s is not yet valid", CertFingerprintSHA256(leaf))
	}
	if now.After(leaf.NotAfter) {
		return tls.Certificate{}, fmt.Errorf("certificate %s is expired", CertFingerprintSHA256(leaf))
	}
	cert.Leaf = leaf
	return cert, nil
}

func readBoundedFile(path string) ([]byte, error) {
	if path == "" {
		return nil, errors.New("file custody path cannot be empty")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening %q: %w", path, err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat %q: %w", path, err)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("custody path %q is a directory", path)
	}
	if info.Size() > maxCustodyFileBytes {
		return nil, fmt.Errorf("custody file %q exceeds %d bytes", path, maxCustodyFileBytes)
	}

	data, err := io.ReadAll(io.LimitReader(f, maxCustodyFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading %q: %w", path, err)
	}
	if len(data) > maxCustodyFileBytes {
		return nil, fmt.Errorf("custody file %q exceeds %d bytes", path, maxCustodyFileBytes)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("custody file %q is empty", path)
	}
	return data, nil
}
