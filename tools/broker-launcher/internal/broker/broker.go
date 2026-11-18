package broker

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/nats-io/nkeys"

	"github.com/relayquill/relayquill/tools/broker-launcher/internal/custody"
	"github.com/relayquill/relayquill/tools/broker-launcher/internal/topology"
)

const (
	defaultReadyTimeout = 10 * time.Second
	defaultProbeTimeout = 5 * time.Second
)

// LaunchOptions controls runtime startup, readiness verification, and logging for an embedded server.
type LaunchOptions struct {
	Topology         *topology.ResolvedTopology
	Logger           *slog.Logger
	ReadyTimeout     time.Duration
	ProbeNKeySeedRef string
	ProbeInboxPrefix string
	ReadyFile        string
}

// Instance represents a running embedded NATS JetStream server managed by this launcher.
type Instance struct {
	srv       *server.Server
	top       *topology.ResolvedTopology
	logger    *slog.Logger
	readyFile string
	closeOnce sync.Once
}

type probeServerInfo struct {
	ServerName   string `json:"server_name"`
	TLSRequired  bool   `json:"tls_required"`
	AuthRequired bool   `json:"auth_required"`
	JetStream    bool   `json:"jetstream"`
}

type routePeerAuthenticator struct {
	allowlist *custody.RoutePeerAllowlist
}

func (a *routePeerAuthenticator) Check(c server.ClientAuthentication) bool {
	if a == nil || a.allowlist == nil {
		return false
	}
	cs := c.GetTLSConnectionState()
	if cs == nil || len(cs.VerifiedChains) == 0 || len(cs.PeerCertificates) == 0 {
		return false
	}
	return a.allowlist.AllowsCertificate(cs.PeerCertificates[0])
}

// Start builds in-memory TLS/NKey options, boots the embedded NATS JetStream server, and verifies readiness.
func Start(ctx context.Context, opts LaunchOptions) (*Instance, error) {
	if opts.Topology == nil {
		return nil, errors.New("resolved topology is required")
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	}
	readyTimeout := opts.ReadyTimeout
	if readyTimeout <= 0 {
		readyTimeout = defaultReadyTimeout
	}

	if err := os.MkdirAll(opts.Topology.StoreDir, 0o750); err != nil {
		return nil, fmt.Errorf("creating jetstream store_dir: %w", err)
	}

	clientTLS, clientCAPool, err := custody.BuildClientTLSConfig(opts.Topology.ClientTLS)
	if err != nil {
		return nil, err
	}

	var clusterTLS *tls.Config
	var routeAllowlist *custody.RoutePeerAllowlist
	if opts.Topology.ClusterEnabled {
		clusterTLS, routeAllowlist, err = custody.BuildClusterTLSConfig(opts.Topology.ClusterTLS)
		if err != nil {
			return nil, err
		}
	}

	srvOpts := buildServerOptions(opts.Topology, clientTLS, clusterTLS, routeAllowlist)
	srv, err := server.NewServer(srvOpts)
	if err != nil {
		return nil, fmt.Errorf("initializing NATS server: %w", err)
	}

	srv.SetLogger(newSlogBridge(logger), false, false)

	go srv.Start()

	if !srv.ReadyForConnections(readyTimeout) {
		srv.Shutdown()
		srv.WaitForShutdown()
		return nil, fmt.Errorf("NATS server failed to accept connections within %s", readyTimeout)
	}

	inst := &Instance{
		srv:       srv,
		top:       opts.Topology,
		logger:    logger,
		readyFile: strings.TrimSpace(opts.ReadyFile),
	}

	if err := verifyReadiness(ctx, srv, opts.Topology, clientTLS, clientCAPool, opts.ProbeNKeySeedRef, opts.ProbeInboxPrefix); err != nil {
		_ = inst.Shutdown(context.Background())
		return nil, fmt.Errorf("readiness check failed: %w", err)
	}

	if inst.readyFile != "" {
		if err := os.WriteFile(inst.readyFile, []byte("ready\n"), 0o600); err != nil {
			_ = inst.Shutdown(context.Background())
			return nil, fmt.Errorf("writing ready file: %w", err)
		}
	}

	clientCertFP := ""
	if len(clientTLS.Certificates) > 0 && clientTLS.Certificates[0].Leaf != nil {
		clientCertFP = custody.CertFingerprintSHA256(clientTLS.Certificates[0].Leaf)
	}
	logger.Info("broker_ready",
		"server_name", sanitizeLogValue(opts.Topology.ServerName),
		"client_addr", srv.Addr().String(),
		"monitor_enabled", opts.Topology.MonitorEnabled,
		"cluster_enabled", opts.Topology.ClusterEnabled,
		"tls_handshake_first", opts.Topology.HandshakeFirst,
		"tls_min_version", tls.VersionName(clientTLS.MinVersion),
		"client_cert_sha256", clientCertFP,
		"jetstream", true,
		"sync_always", opts.Topology.SyncAlways,
	)

	return inst, nil
}

// ClientAddr returns the bound client listener address.
func (i *Instance) ClientAddr() net.Addr {
	if i == nil || i.srv == nil {
		return nil
	}
	return i.srv.Addr()
}

// ClusterAddr returns the bound cluster route listener address, or nil if clustering is disabled.
func (i *Instance) ClusterAddr() *net.TCPAddr {
	if i == nil || i.srv == nil {
		return nil
	}
	return i.srv.ClusterAddr()
}

// MonitorAddr returns the bound HTTP monitoring address, or nil if monitoring is disabled.
func (i *Instance) MonitorAddr() *net.TCPAddr {
	if i == nil || i.srv == nil {
		return nil
	}
	return i.srv.MonitorAddr()
}

// Server returns the underlying embedded NATS server instance.
func (i *Instance) Server() *server.Server {
	if i == nil {
		return nil
	}
	return i.srv
}

// Shutdown removes readiness markers and cleanly drains and stops the embedded server.
func (i *Instance) Shutdown(ctx context.Context) error {
	if i == nil || i.srv == nil {
		return nil
	}
	var retErr error
	i.closeOnce.Do(func() {
		if i.readyFile != "" {
			_ = os.Remove(i.readyFile)
		}
		if i.logger != nil {
			i.logger.Info("broker_shutting_down", "server_name", sanitizeLogValue(i.top.ServerName))
		}
		i.srv.Shutdown()

		done := make(chan struct{})
		go func() {
			i.srv.WaitForShutdown()
			close(done)
		}()

		select {
		case <-done:
			if i.logger != nil {
				i.logger.Info("broker_stopped", "server_name", sanitizeLogValue(i.top.ServerName))
			}
		case <-ctx.Done():
			retErr = ctx.Err()
		}
	})
	return retErr
}

func buildServerOptions(
	top *topology.ResolvedTopology,
	clientTLS *tls.Config,
	clusterTLS *tls.Config,
	routeAllowlist *custody.RoutePeerAllowlist,
) *server.Options {
	opts := &server.Options{
		ServerName:             top.ServerName,
		Host:                   top.Host,
		Port:                   top.ClientPort,
		ClientAdvertise:        top.ClientAdvertise,
		MaxPayload:             top.MaxPayload,
		MaxConn:                top.MaxConnections,
		TLS:                    true,
		TLSConfig:              clientTLS,
		TLSHandshakeFirst:      top.HandshakeFirst,
		AllowNonTLS:            false,
		TLSTimeout:             5,
		Nkeys:                  buildNkeyUsers(top),
		JetStream:              true,
		StoreDir:               top.StoreDir,
		JetStreamMaxMemory:     top.MaxMemoryStore,
		JetStreamMaxStore:      top.MaxFileStore,
		JetStreamDomain:        top.JetStreamDomain,
		SyncAlways:             top.SyncAlways,
		DisableJetStreamBanner: true,
		NoSigs:                 true,
		NoLog:                  false,
		Debug:                  false,
		Trace:                  false,
		TraceVerbose:           false,
	}

	if top.MonitorEnabled {
		opts.HTTPHost = top.MonitorHost
		opts.HTTPPort = top.MonitorPort
	}

	if top.ClusterEnabled {
		opts.Cluster = server.ClusterOpts{
			Name:       top.ClusterName,
			Host:       top.ClusterHost,
			Port:       top.ClusterPort,
			Advertise:  top.ClusterAdvertise,
			TLSConfig:  clusterTLS,
			TLSTimeout: 5,
		}
		opts.Routes = top.RouteURLs
		opts.CustomRouterAuthentication = &routePeerAuthenticator{allowlist: routeAllowlist}
	}

	return opts
}

func buildNkeyUsers(top *topology.ResolvedTopology) []*server.NkeyUser {
	principals := []topology.ResolvedPrincipal{top.Relay, top.Fanout, top.BrokerAdmin}
	users := make([]*server.NkeyUser, 0, len(principals))
	for _, p := range principals {
		users = append(users, &server.NkeyUser{
			Nkey: p.PublicNKey,
			Permissions: &server.Permissions{
				Publish:   &server.SubjectPermission{Allow: append([]string(nil), p.PublishAllow...)},
				Subscribe: &server.SubjectPermission{Allow: append([]string(nil), p.SubscribeAllow...)},
			},
		})
	}
	return users
}

func verifyReadiness(
	ctx context.Context,
	srv *server.Server,
	top *topology.ResolvedTopology,
	serverTLS *tls.Config,
	caPool *x509.CertPool,
	probeSeedRef string,
	probeInboxPrefix string,
) error {
	health := srv.Healthz(&server.HealthzOptions{JSEnabledOnly: true})
	if health == nil || health.Status != "ok" {
		msg := "unknown healthz failure"
		if health != nil && health.Error != "" {
			msg = health.Error
		}
		return fmt.Errorf("embedded server healthz not ready: %s", msg)
	}
	if !srv.JetStreamEnabled() {
		return errors.New("jetstream is not enabled after server startup")
	}

	probeTLS, hasCA, err := buildProbeClientTLSConfig(serverTLS, caPool)
	if err != nil {
		return err
	}

	addr := srv.Addr()
	if addr == nil {
		return errors.New("client listener address unavailable")
	}

	if hasCA {
		if err := probeTLSFirstServerInfo(ctx, addr.String(), top.ServerName, probeTLS); err != nil {
			return err
		}
		if strings.TrimSpace(probeSeedRef) != "" {
			if err := probeAuthenticatedJetStream(ctx, addr.String(), probeTLS, probeSeedRef, probeInboxPrefix); err != nil {
				return err
			}
		}
	} else {
		if err := probeRejectsPlaintextOnTLSFirst(ctx, addr.String()); err != nil {
			return err
		}
		if strings.TrimSpace(probeSeedRef) != "" {
			return errors.New("authenticated readiness probe requires tls.ca_ref to verify server certificate")
		}
	}

	return nil
}

func buildProbeClientTLSConfig(serverTLS *tls.Config, caPool *x509.CertPool) (*tls.Config, bool, error) {
	if serverTLS == nil || len(serverTLS.Certificates) == 0 || serverTLS.Certificates[0].Leaf == nil {
		return nil, false, errors.New("server leaf certificate unavailable for readiness probe")
	}
	leaf := serverTLS.Certificates[0].Leaf

	if caPool != nil {
		return &tls.Config{
			MinVersion: serverTLS.MinVersion,
			RootCAs:    caPool,
			ServerName: probeServerName(leaf),
		}, true, nil
	}

	// If intermediate/root certificates were bundled alongside the leaf in cert_ref,
	// verify against those certificates without disabling TLS verification.
	if len(serverTLS.Certificates[0].Certificate) > 1 {
		bundlePool := x509.NewCertPool()
		for _, der := range serverTLS.Certificates[0].Certificate[1:] {
			if parsed, err := x509.ParseCertificate(der); err == nil {
				bundlePool.AddCert(parsed)
			}
		}
		return &tls.Config{
			MinVersion: serverTLS.MinVersion,
			RootCAs:    bundlePool,
			ServerName: probeServerName(leaf),
		}, true, nil
	}

	return nil, false, nil
}

func probeRejectsPlaintextOnTLSFirst(ctx context.Context, addr string) error {
	dialer := &net.Dialer{Timeout: defaultProbeTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("TCP listener probe dial failed: %w", err)
	}
	defer conn.Close()

	// On a TLSHandshakeFirst listener, the server waits for a TLS ClientHello
	// and never emits a plaintext NATS INFO line.
	_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	buf := make([]byte, 16)
	n, err := conn.Read(buf)
	if n > 0 && bytes.HasPrefix(buf[:n], []byte("INFO ")) {
		return errors.New("client listener emitted plaintext INFO despite TLSHandshakeFirst")
	}
	if err != nil {
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			return nil
		}
		return fmt.Errorf("unexpected error probing TLS-first listener: %w", err)
	}
	return nil
}

func probeServerName(leaf *x509.Certificate) string {
	if leaf == nil {
		return "127.0.0.1"
	}
	for _, dns := range leaf.DNSNames {
		if dns != "" && !strings.Contains(dns, "*") {
			return dns
		}
	}
	for _, ip := range leaf.IPAddresses {
		return ip.String()
	}
	return "127.0.0.1"
}

func probeTLSFirstServerInfo(ctx context.Context, addr, expectedServerName string, tlsCfg *tls.Config) error {
	dialCtx, cancel := context.WithTimeout(ctx, defaultProbeTimeout)
	defer cancel()

	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: defaultProbeTimeout},
		Config:    tlsCfg,
	}
	conn, err := dialer.DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("TLS-first listener probe dial failed: %w", err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(defaultProbeTimeout))
	reader := bufio.NewReader(ioLimitReader(conn, 16*1024))
	line, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("reading NATS INFO over TLS-first listener: %w", err)
	}
	payload, ok := strings.CutPrefix(strings.TrimSpace(line), "INFO ")
	if !ok {
		return errors.New("TLS-first listener did not emit expected INFO banner")
	}

	var info probeServerInfo
	if err := json.Unmarshal([]byte(payload), &info); err != nil {
		return fmt.Errorf("parsing NATS INFO banner: %w", err)
	}
	if !info.TLSRequired {
		return errors.New("server INFO reports tls_required=false")
	}
	if !info.AuthRequired {
		return errors.New("server INFO reports auth_required=false")
	}
	if !info.JetStream {
		return errors.New("server INFO reports jetstream=false")
	}
	if expectedServerName != "" && info.ServerName != expectedServerName {
		return fmt.Errorf("server INFO server_name %q does not match expected %q", info.ServerName, expectedServerName)
	}
	return nil
}

func probeAuthenticatedJetStream(ctx context.Context, addr string, tlsCfg *tls.Config, seedRef, inboxPrefix string) error {
	seedBytes, err := custody.ResolveBytes(seedRef)
	if err != nil {
		return fmt.Errorf("loading readiness probe NKey seed: %w", err)
	}
	defer clear(seedBytes)

	trimmedSeed := bytes.TrimSpace(seedBytes)
	kp, err := nkeys.FromSeed(trimmedSeed)
	clear(trimmedSeed)
	if err != nil {
		return fmt.Errorf("parsing readiness probe NKey seed: %w", err)
	}
	pub, err := kp.PublicKey()
	if err != nil {
		return fmt.Errorf("deriving readiness probe public NKey: %w", err)
	}

	natsOpts := []nats.Option{
		nats.TLSHandshakeFirst(),
		nats.Secure(tlsCfg),
		nats.Nkey(pub, func(nonce []byte) ([]byte, error) {
			return kp.Sign(nonce)
		}),
		nats.Timeout(defaultProbeTimeout),
		nats.NoReconnect(),
	}
	if strings.TrimSpace(inboxPrefix) != "" {
		natsOpts = append(natsOpts, nats.CustomInboxPrefix(strings.TrimSpace(inboxPrefix)))
	}

	nc, err := nats.Connect("tls://"+addr, natsOpts...)
	if err != nil {
		return fmt.Errorf("authenticated probe connection failed: %w", err)
	}
	defer nc.Close()

	js, err := jetstream.New(nc)
	if err != nil {
		return fmt.Errorf("initializing JetStream probe context: %w", err)
	}
	probeCtx, cancel := context.WithTimeout(ctx, defaultProbeTimeout)
	defer cancel()
	if _, err := js.AccountInfo(probeCtx); err != nil {
		return fmt.Errorf("authenticated JetStream info probe failed: %w", err)
	}
	return nil
}

func ioLimitReader(conn net.Conn, maxBytes int64) *limitedConnReader {
	return &limitedConnReader{conn: conn, remaining: maxBytes}
}

type limitedConnReader struct {
	conn      net.Conn
	remaining int64
}

func (r *limitedConnReader) Read(p []byte) (int, error) {
	if r.remaining <= 0 {
		return 0, errors.New("probe response exceeded size limit")
	}
	if int64(len(p)) > r.remaining {
		p = p[:r.remaining]
	}
	n, err := r.conn.Read(p)
	r.remaining -= int64(n)
	return n, err
}

type slogBridge struct {
	logger *slog.Logger
}

func newSlogBridge(logger *slog.Logger) *slogBridge {
	return &slogBridge{logger: logger}
}

func (b *slogBridge) Noticef(format string, v ...any) {
	b.logger.Info("nats_server", "detail", sanitizeServerLog(fmt.Sprintf(format, v...)))
}

func (b *slogBridge) Warnf(format string, v ...any) {
	b.logger.Warn("nats_server", "detail", sanitizeServerLog(fmt.Sprintf(format, v...)))
}

func (b *slogBridge) Errorf(format string, v ...any) {
	b.logger.Error("nats_server", "detail", sanitizeServerLog(fmt.Sprintf(format, v...)))
}

func (b *slogBridge) Fatalf(format string, v ...any) {
	b.logger.Error("nats_server_fatal", "detail", sanitizeServerLog(fmt.Sprintf(format, v...)))
}

func (b *slogBridge) Debugf(string, ...any) {}
func (b *slogBridge) Tracef(string, ...any) {}

func sanitizeLogValue(raw string) string {
	var b strings.Builder
	b.Grow(len(raw))
	for _, r := range raw {
		if unicode.IsControl(r) {
			b.WriteByte(' ')
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func sanitizeServerLog(raw string) string {
	clean := sanitizeLogValue(raw)
	if strings.Contains(clean, "-----BEGIN ") {
		return "[redacted PEM material]"
	}
	return clean
}
