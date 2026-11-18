package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/relayquill/relayquill/tools/broker-launcher/internal/broker"
	"github.com/relayquill/relayquill/tools/broker-launcher/internal/topology"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, os.Args[1:], os.Getenv, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer) error {
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		switch args[0] {
		case "healthcheck":
			return runHealthcheck(ctx, args[1:], getenv, stdout, stderr)
		case "validate":
			return runValidate(args[1:], getenv, stdout, stderr)
		case "serve":
			args = args[1:]
		default:
			return fmt.Errorf("unknown subcommand %q (supported: serve, validate, healthcheck)", args[0])
		}
	}

	cfg, err := parseLaunchFlags("relayquill-broker", args, getenv, stderr)
	if err != nil {
		return err
	}

	logger := slog.New(slog.NewJSONHandler(stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	resolved, err := topology.LoadFile(cfg.topologyPath, cfg.overrides)
	if err != nil {
		return fmt.Errorf("loading broker topology: %w", err)
	}

	inst, err := broker.Start(ctx, broker.LaunchOptions{
		Topology:         resolved,
		Logger:           logger,
		ReadyTimeout:     cfg.readyTimeout,
		ProbeNKeySeedRef: cfg.probeSeedRef,
		ProbeInboxPrefix: cfg.probeInbox,
		ReadyFile:        cfg.readyFile,
	})
	if err != nil {
		return fmt.Errorf("starting broker: %w", err)
	}

	<-ctx.Done()

	shutCtx, cancel := context.WithTimeout(context.Background(), cfg.shutdownTimeout)
	defer cancel()
	if err := inst.Shutdown(shutCtx); err != nil {
		return fmt.Errorf("shutting down broker: %w", err)
	}
	return nil
}

type launchCLI struct {
	topologyPath    string
	overrides       topology.Overrides
	probeSeedRef    string
	probeInbox      string
	readyFile       string
	readyTimeout    time.Duration
	shutdownTimeout time.Duration
}

func parseLaunchFlags(name string, args []string, getenv func(string) string, stderr io.Writer) (*launchCLI, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)

	cli := &launchCLI{}
	fs.StringVar(&cli.topologyPath, "topology", getenv("RELAYQUILL_BROKER_TOPOLOGY"), "Path to public topology JSON file")
	fs.StringVar(&cli.overrides.NodeID, "node-id", getenv("RELAYQUILL_BROKER_NODE_ID"), "Node ID or server_name inside multi-node topology")
	fs.StringVar(&cli.overrides.ServerName, "server-name", getenv("RELAYQUILL_BROKER_SERVER_NAME"), "Override server_name")
	fs.StringVar(&cli.overrides.Host, "host", getenv("RELAYQUILL_BROKER_HOST"), "Override client listen host")
	fs.IntVar(&cli.overrides.ClientPort, "client-port", envInt(getenv, "RELAYQUILL_BROKER_CLIENT_PORT"), "Override client listen port")
	fs.StringVar(&cli.overrides.ClusterHost, "cluster-host", getenv("RELAYQUILL_BROKER_CLUSTER_HOST"), "Override cluster route listen host")
	fs.IntVar(&cli.overrides.ClusterPort, "cluster-port", envInt(getenv, "RELAYQUILL_BROKER_CLUSTER_PORT"), "Override cluster route listen port")
	fs.StringVar(&cli.overrides.MonitorHost, "monitor-host", getenv("RELAYQUILL_BROKER_MONITOR_HOST"), "Override HTTP monitoring listen host")
	fs.IntVar(&cli.overrides.MonitorPort, "monitor-port", envInt(getenv, "RELAYQUILL_BROKER_MONITOR_PORT"), "Override HTTP monitoring listen port")
	fs.StringVar(&cli.overrides.StoreDir, "store-dir", getenv("RELAYQUILL_BROKER_STORE_DIR"), "Override JetStream store directory")

	fs.StringVar(&cli.overrides.TLSCertRef, "tls-cert", firstNonEmpty(getenv("RELAYQUILL_BROKER_TLS_CERT_REF"), getenv("RELAYQUILL_BROKER_TLS_CERT_FILE")), "Client TLS certificate custody reference")
	fs.StringVar(&cli.overrides.TLSKeyRef, "tls-key", firstNonEmpty(getenv("RELAYQUILL_BROKER_TLS_KEY_REF"), getenv("RELAYQUILL_BROKER_TLS_KEY_FILE")), "Client TLS private key custody reference")
	fs.StringVar(&cli.overrides.TLSCARef, "tls-ca", firstNonEmpty(getenv("RELAYQUILL_BROKER_TLS_CA_REF"), getenv("RELAYQUILL_BROKER_TLS_CA_FILE")), "Client TLS CA bundle custody reference")

	fs.StringVar(&cli.overrides.ClusterCARef, "cluster-ca", firstNonEmpty(getenv("RELAYQUILL_BROKER_CLUSTER_CA_REF"), getenv("RELAYQUILL_BROKER_CLUSTER_CA_FILE")), "Cluster mTLS CA bundle custody reference")
	fs.StringVar(&cli.overrides.ClusterCertRef, "cluster-cert", firstNonEmpty(getenv("RELAYQUILL_BROKER_CLUSTER_CERT_REF"), getenv("RELAYQUILL_BROKER_CLUSTER_CERT_FILE")), "Cluster mTLS peer certificate custody reference")
	fs.StringVar(&cli.overrides.ClusterKeyRef, "cluster-key", firstNonEmpty(getenv("RELAYQUILL_BROKER_CLUSTER_KEY_REF"), getenv("RELAYQUILL_BROKER_CLUSTER_KEY_FILE")), "Cluster mTLS peer private key custody reference")

	fs.StringVar(&cli.overrides.RelayPublicNKey, "relay-public-nkey", getenv("RELAYQUILL_BROKER_RELAY_PUBLIC_NKEY"), "Override relay public NKey")
	fs.StringVar(&cli.overrides.RelayPublicNKeyRef, "relay-public-nkey-ref", getenv("RELAYQUILL_BROKER_RELAY_PUBLIC_NKEY_REF"), "Override relay public NKey custody reference")
	fs.StringVar(&cli.overrides.FanoutPublicNKey, "fanout-public-nkey", getenv("RELAYQUILL_BROKER_FANOUT_PUBLIC_NKEY"), "Override fanout public NKey")
	fs.StringVar(&cli.overrides.FanoutPublicNKeyRef, "fanout-public-nkey-ref", getenv("RELAYQUILL_BROKER_FANOUT_PUBLIC_NKEY_REF"), "Override fanout public NKey custody reference")
	fs.StringVar(&cli.overrides.AdminPublicNKey, "admin-public-nkey", getenv("RELAYQUILL_BROKER_ADMIN_PUBLIC_NKEY"), "Override broker_admin public NKey")
	fs.StringVar(&cli.overrides.AdminPublicNKeyRef, "admin-public-nkey-ref", getenv("RELAYQUILL_BROKER_ADMIN_PUBLIC_NKEY_REF"), "Override broker_admin public NKey custody reference")

	fs.StringVar(&cli.probeSeedRef, "probe-nkey-seed", getenv("RELAYQUILL_BROKER_PROBE_NKEY_SEED_REF"), "Optional NKey seed custody reference for authenticated JetStream readiness check")
	fs.StringVar(&cli.probeInbox, "probe-inbox-prefix", getenv("RELAYQUILL_BROKER_PROBE_INBOX_PREFIX"), "Optional inbox prefix for authenticated JetStream readiness check")
	fs.StringVar(&cli.readyFile, "ready-file", getenv("RELAYQUILL_BROKER_READY_FILE"), "Optional path for readiness marker file")
	fs.DurationVar(&cli.readyTimeout, "ready-timeout", envDuration(getenv, "RELAYQUILL_BROKER_READY_TIMEOUT", 15*time.Second), "Startup readiness timeout")
	fs.DurationVar(&cli.shutdownTimeout, "shutdown-timeout", envDuration(getenv, "RELAYQUILL_BROKER_SHUTDOWN_TIMEOUT", 15*time.Second), "Graceful shutdown timeout")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() > 0 {
		return nil, fmt.Errorf("unexpected positional arguments: %v", fs.Args())
	}
	if strings.TrimSpace(cli.topologyPath) == "" {
		return nil, errors.New("--topology (or RELAYQUILL_BROKER_TOPOLOGY) is required")
	}
	return cli, nil
}

func runValidate(args []string, getenv func(string) string, stdout, stderr io.Writer) error {
	cli, err := parseLaunchFlags("relayquill-broker validate", args, getenv, stderr)
	if err != nil {
		return err
	}
	resolved, err := topology.LoadFile(cli.topologyPath, cli.overrides)
	if err != nil {
		return fmt.Errorf("topology validation failed: %w", err)
	}
	summary := struct {
		OK             bool   `json:"ok"`
		ServerName     string `json:"server_name"`
		ClientPort     int    `json:"client_port"`
		ClusterEnabled bool   `json:"cluster_enabled"`
		ClusterPort    int    `json:"cluster_port,omitempty"`
		MonitorEnabled bool   `json:"monitor_enabled"`
		MonitorPort    int    `json:"monitor_port,omitempty"`
		StreamName     string `json:"stream_name"`
		ConsumerName   string `json:"consumer_name"`
		SyncAlways     bool   `json:"sync_always"`
	}{
		OK:             true,
		ServerName:     resolved.ServerName,
		ClientPort:     resolved.ClientPort,
		ClusterEnabled: resolved.ClusterEnabled,
		ClusterPort:    resolved.ClusterPort,
		MonitorEnabled: resolved.MonitorEnabled,
		MonitorPort:    resolved.MonitorPort,
		StreamName:     resolved.StreamName,
		ConsumerName:   resolved.ConsumerName,
		SyncAlways:     resolved.SyncAlways,
	}
	return json.NewEncoder(stdout).Encode(summary)
}

func runHealthcheck(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("relayquill-broker healthcheck", flag.ContinueOnError)
	fs.SetOutput(stderr)

	defaultURL := firstNonEmpty(getenv("RELAYQUILL_BROKER_HEALTHCHECK_URL"), "http://127.0.0.1:8222/healthz?js-enabled-only=true")
	rawURL := fs.String("url", defaultURL, "Private monitoring /healthz endpoint URL")
	timeout := fs.Duration("timeout", 3*time.Second, "Healthcheck request timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}

	parsed, err := url.Parse(strings.TrimSpace(*rawURL))
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return errors.New("healthcheck --url must be an http or https URL")
	}
	host := strings.ToLower(parsed.Hostname())
	if host != "127.0.0.1" && host != "localhost" && host != "::1" {
		return fmt.Errorf("healthcheck --url host %q must be loopback", host)
	}

	reqCtx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return err
	}
	client := &http.Client{
		Timeout: *timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("healthcheck request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return fmt.Errorf("reading healthcheck response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("healthcheck returned HTTP %d", resp.StatusCode)
	}

	var status struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(body, &status); err != nil || status.Status != "ok" {
		return fmt.Errorf("healthcheck reported non-ok status %q", status.Status)
	}
	_, err = fmt.Fprintln(stdout, `{"status":"ok"}`)
	return err
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func envInt(getenv func(string) string, key string) int {
	raw := strings.TrimSpace(getenv(key))
	if raw == "" {
		return 0
	}
	val, err := strconv.Atoi(raw)
	if err != nil {
		return 0
	}
	return val
}

func envDuration(getenv func(string) string, key string, fallback time.Duration) time.Duration {
	raw := strings.TrimSpace(getenv(key))
	if raw == "" {
		return fallback
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return fallback
	}
	return d
}
