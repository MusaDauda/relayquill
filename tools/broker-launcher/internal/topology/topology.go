package topology

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/relayquill/relayquill/tools/broker-launcher/internal/custody"
)

const (
	DefaultClientPort     = 4222
	DefaultClusterPort    = 6222
	DefaultMonitorPort    = 8222
	DefaultMaxPayload     = int32(8192)
	DefaultMaxConnections = 256
	DefaultStreamName     = "RELAYQUILL_EVENTS_V1"
	DefaultConsumerName   = "RELAYQUILL_FANOUT_V1"
	DefaultRelayInbox     = "_INBOX.rq.relay"
	DefaultFanoutInbox    = "_INBOX.rq.fanout"
	DefaultAdminInbox     = "_INBOX.rq.admin"
	maxTopologyFileBytes  = 1 << 20
)

var (
	nameIdentRegex     = regexp.MustCompile(`^[A-Z0-9_]{3,64}$`)
	subjectPrefixRegex = regexp.MustCompile(`^([a-z0-9_-]+\.)*$`)
	inboxPrefixRegex   = regexp.MustCompile(`^_INBOX\.[a-z0-9._-]+$`)
)

// Topology defines the non-secret public broker configuration loaded from JSON.
type Topology struct {
	Schema         string           `json:"$schema,omitempty"`
	SchemaVersion  int              `json:"schema_version"`
	ServerName     string           `json:"server_name"`
	Host           string           `json:"host"`
	ClientPort     int              `json:"client_port"`
	ClientAdvertise string          `json:"client_advertise,omitempty"`
	MaxPayload     int32            `json:"max_payload"`
	MaxConnections int              `json:"max_connections"`
	Monitoring     MonitoringConfig `json:"monitoring"`
	TLS            ClientTLSConfig  `json:"tls"`
	Cluster        ClusterConfig    `json:"cluster"`
	Nodes          []NodeConfig     `json:"nodes,omitempty"`
	JetStream      JetStreamConfig  `json:"jetstream"`
	Principals     PrincipalsConfig `json:"principals"`
}

// MonitoringConfig defines private NATS HTTP monitoring settings.
type MonitoringConfig struct {
	Enabled *bool  `json:"enabled,omitempty"`
	Host    string `json:"host,omitempty"`
	Port    int    `json:"port,omitempty"`
}

// ClientTLSConfig defines native client-listener TLS policy and custody references.
type ClientTLSConfig struct {
	Enabled          *bool  `json:"enabled"`
	HandshakeFirst   *bool  `json:"handshake_first,omitempty"`
	MinVersion       string `json:"min_version,omitempty"`
	VerifyClientCert bool   `json:"verify_client_cert,omitempty"`
	CertRef          string `json:"cert_ref,omitempty"`
	KeyRef           string `json:"key_ref,omitempty"`
	CARef            string `json:"ca_ref,omitempty"`
}

// ClusterConfig defines cluster route listener, peers, and mutual TLS configuration.
type ClusterConfig struct {
	Enabled           bool             `json:"enabled"`
	Name              string           `json:"name,omitempty"`
	Host              string           `json:"host,omitempty"`
	Port              int              `json:"port,omitempty"`
	Advertise         string           `json:"advertise,omitempty"`
	Routes            []string         `json:"routes,omitempty"`
	AllowedRoutePeers []string         `json:"allowed_route_peers,omitempty"`
	TLS               ClusterTLSConfig `json:"tls"`
}

// ClusterTLSConfig defines mTLS custody references for cluster route traffic.
type ClusterTLSConfig struct {
	MinVersion string `json:"min_version,omitempty"`
	CARef      string `json:"ca_ref,omitempty"`
	CertRef    string `json:"cert_ref,omitempty"`
	KeyRef     string `json:"key_ref,omitempty"`
}

// NodeConfig allows a single shared topology file to describe multiple broker nodes.
type NodeConfig struct {
	ID               string `json:"id"`
	ServerName       string `json:"server_name"`
	Host             string `json:"host,omitempty"`
	ClientPort       int    `json:"client_port,omitempty"`
	ClientAdvertise  string `json:"client_advertise,omitempty"`
	ClusterHost      string `json:"cluster_host,omitempty"`
	ClusterPort      int    `json:"cluster_port,omitempty"`
	ClusterAdvertise string `json:"cluster_advertise,omitempty"`
	MonitorHost      string `json:"monitor_host,omitempty"`
	MonitorPort      int    `json:"monitor_port,omitempty"`
	StoreDir         string `json:"store_dir,omitempty"`
	TLSCertRef       string `json:"tls_cert_ref,omitempty"`
	TLSKeyRef        string `json:"tls_key_ref,omitempty"`
	TLSCARef         string `json:"tls_ca_ref,omitempty"`
	ClusterCARef     string `json:"cluster_ca_ref,omitempty"`
	ClusterCertRef   string `json:"cluster_cert_ref,omitempty"`
	ClusterKeyRef    string `json:"cluster_key_ref,omitempty"`
}

// JetStreamConfig defines JetStream store limits and persistence settings.
type JetStreamConfig struct {
	Enabled         *bool  `json:"enabled"`
	StoreDir        string `json:"store_dir"`
	MaxMemoryStore  int64  `json:"max_memory_store"`
	MaxFileStore    int64  `json:"max_file_store"`
	SyncInterval    string `json:"sync_interval"`
	StreamName      string `json:"stream_name,omitempty"`
	ConsumerName    string `json:"consumer_name,omitempty"`
	SubjectPrefix   string `json:"subject_prefix,omitempty"`
	Domain          string `json:"domain,omitempty"`
}

// PrincipalsConfig defines public NKey identities and subject scopes for each operational principal.
type PrincipalsConfig struct {
	Relay       PrincipalConfig `json:"relay"`
	Fanout      PrincipalConfig `json:"fanout"`
	BrokerAdmin PrincipalConfig `json:"broker_admin"`
}

// PrincipalConfig defines one scoped NKey identity and its allowed subject patterns.
type PrincipalConfig struct {
	PublicNKey     string   `json:"public_nkey,omitempty"`
	PublicNKeyRef  string   `json:"public_nkey_ref,omitempty"`
	InboxPrefix    string   `json:"inbox_prefix,omitempty"`
	PublishAllow   []string `json:"publish_allow,omitempty"`
	SubscribeAllow []string `json:"subscribe_allow,omitempty"`
}

// Overrides carries runtime CLI/env values that customize or resolve node/custody settings.
type Overrides struct {
	NodeID               string
	ServerName           string
	Host                 string
	ClientPort           int
	ClusterHost          string
	ClusterPort          int
	MonitorHost          string
	MonitorPort          int
	StoreDir             string
	TLSCertRef           string
	TLSKeyRef            string
	TLSCARef             string
	ClusterCARef         string
	ClusterCertRef       string
	ClusterKeyRef        string
	RelayPublicNKey      string
	RelayPublicNKeyRef   string
	FanoutPublicNKey     string
	FanoutPublicNKeyRef  string
	AdminPublicNKey      string
	AdminPublicNKeyRef   string
}

// ResolvedPrincipal is a fully validated principal with a resolved public user NKey and ACLs.
type ResolvedPrincipal struct {
	Role           string
	PublicNKey     string
	InboxPrefix    string
	PublishAllow   []string
	SubscribeAllow []string
}

// ResolvedTopology is the validated, self-consistent runtime configuration for one broker node.
type ResolvedTopology struct {
	ServerName        string
	Host              string
	ClientPort        int
	ClientAdvertise   string
	MaxPayload        int32
	MaxConnections    int
	MonitorEnabled    bool
	MonitorHost       string
	MonitorPort       int
	ClientTLS         custody.ClientTLSOptions
	HandshakeFirst    bool
	ClusterEnabled    bool
	ClusterName       string
	ClusterHost       string
	ClusterPort       int
	ClusterAdvertise  string
	RouteURLs         []*url.URL
	AllowedRoutePeers []string
	ClusterTLS        custody.ClusterTLSOptions
	StoreDir          string
	MaxMemoryStore    int64
	MaxFileStore      int64
	SyncAlways        bool
	StreamName        string
	ConsumerName      string
	SubjectPrefix     string
	JetStreamDomain   string
	Relay             ResolvedPrincipal
	Fanout            ResolvedPrincipal
	BrokerAdmin       ResolvedPrincipal
}

// LoadFile reads, parses, and validates a public topology JSON file with optional runtime overrides.
func LoadFile(path string, overrides Overrides) (*ResolvedTopology, error) {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return nil, errors.New("topology file path is required")
	}
	f, err := os.Open(trimmed)
	if err != nil {
		return nil, fmt.Errorf("opening topology file %q: %w", trimmed, err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat topology file %q: %w", trimmed, err)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("topology path %q is a directory", trimmed)
	}
	if info.Size() > maxTopologyFileBytes {
		return nil, fmt.Errorf("topology file %q exceeds %d bytes", trimmed, maxTopologyFileBytes)
	}

	raw, err := io.ReadAll(io.LimitReader(f, maxTopologyFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading topology file %q: %w", trimmed, err)
	}
	if len(raw) > maxTopologyFileBytes {
		return nil, fmt.Errorf("topology file %q exceeds %d bytes", trimmed, maxTopologyFileBytes)
	}

	return ParseAndResolve(raw, overrides)
}

// ParseAndResolve strictly decodes public topology JSON and validates all security invariants.
func ParseAndResolve(raw []byte, overrides Overrides) (*ResolvedTopology, error) {
	var top Topology
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&top); err != nil {
		return nil, fmt.Errorf("decoding topology JSON: %w", err)
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return nil, errors.New("topology JSON contains unexpected trailing content")
	}

	if top.SchemaVersion != 1 {
		return nil, fmt.Errorf("unsupported schema_version %d (expected 1)", top.SchemaVersion)
	}

	if err := applyNodeSelection(&top, overrides.NodeID); err != nil {
		return nil, err
	}
	applyRuntimeOverrides(&top, overrides)

	return validateAndBuild(&top)
}

func applyNodeSelection(top *Topology, nodeID string) error {
	if len(top.Nodes) == 0 {
		return nil
	}
	trimmedID := strings.TrimSpace(nodeID)
	if trimmedID == "" {
		if len(top.Nodes) == 1 && strings.TrimSpace(top.ServerName) == "" {
			trimmedID = top.Nodes[0].ID
		} else {
			return errors.New("node-id is required when topology defines nodes")
		}
	}

	var matched *NodeConfig
	for i := range top.Nodes {
		n := &top.Nodes[i]
		if n.ID == trimmedID || (n.ServerName != "" && n.ServerName == trimmedID) {
			matched = n
			break
		}
	}
	if matched == nil {
		return fmt.Errorf("node-id %q not found in topology nodes", trimmedID)
	}

	if matched.ServerName != "" {
		top.ServerName = matched.ServerName
	} else if matched.ID != "" && top.ServerName == "" {
		top.ServerName = matched.ID
	}
	if matched.Host != "" {
		top.Host = matched.Host
	}
	if matched.ClientPort != 0 {
		top.ClientPort = matched.ClientPort
	}
	if matched.ClientAdvertise != "" {
		top.ClientAdvertise = matched.ClientAdvertise
	}
	if matched.ClusterHost != "" {
		top.Cluster.Host = matched.ClusterHost
	}
	if matched.ClusterPort != 0 {
		top.Cluster.Port = matched.ClusterPort
	}
	if matched.ClusterAdvertise != "" {
		top.Cluster.Advertise = matched.ClusterAdvertise
	}
	if matched.MonitorHost != "" {
		top.Monitoring.Host = matched.MonitorHost
	}
	if matched.MonitorPort != 0 {
		top.Monitoring.Port = matched.MonitorPort
	}
	if matched.StoreDir != "" {
		top.JetStream.StoreDir = matched.StoreDir
	}
	if matched.TLSCertRef != "" {
		top.TLS.CertRef = matched.TLSCertRef
	}
	if matched.TLSKeyRef != "" {
		top.TLS.KeyRef = matched.TLSKeyRef
	}
	if matched.TLSCARef != "" {
		top.TLS.CARef = matched.TLSCARef
	}
	if matched.ClusterCARef != "" {
		top.Cluster.TLS.CARef = matched.ClusterCARef
	}
	if matched.ClusterCertRef != "" {
		top.Cluster.TLS.CertRef = matched.ClusterCertRef
	}
	if matched.ClusterKeyRef != "" {
		top.Cluster.TLS.KeyRef = matched.ClusterKeyRef
	}
	return nil
}

func applyRuntimeOverrides(top *Topology, ov Overrides) {
	if ov.ServerName != "" {
		top.ServerName = ov.ServerName
	}
	if ov.Host != "" {
		top.Host = ov.Host
	}
	if ov.ClientPort != 0 {
		top.ClientPort = ov.ClientPort
	}
	if ov.ClusterHost != "" {
		top.Cluster.Host = ov.ClusterHost
	}
	if ov.ClusterPort != 0 {
		top.Cluster.Port = ov.ClusterPort
	}
	if ov.MonitorHost != "" {
		top.Monitoring.Host = ov.MonitorHost
	}
	if ov.MonitorPort != 0 {
		top.Monitoring.Port = ov.MonitorPort
	}
	if ov.StoreDir != "" {
		top.JetStream.StoreDir = ov.StoreDir
	}
	if ov.TLSCertRef != "" {
		top.TLS.CertRef = ov.TLSCertRef
	}
	if ov.TLSKeyRef != "" {
		top.TLS.KeyRef = ov.TLSKeyRef
	}
	if ov.TLSCARef != "" {
		top.TLS.CARef = ov.TLSCARef
	}
	if ov.ClusterCARef != "" {
		top.Cluster.TLS.CARef = ov.ClusterCARef
	}
	if ov.ClusterCertRef != "" {
		top.Cluster.TLS.CertRef = ov.ClusterCertRef
	}
	if ov.ClusterKeyRef != "" {
		top.Cluster.TLS.KeyRef = ov.ClusterKeyRef
	}
	if ov.RelayPublicNKey != "" {
		top.Principals.Relay.PublicNKey = ov.RelayPublicNKey
	}
	if ov.RelayPublicNKeyRef != "" {
		top.Principals.Relay.PublicNKeyRef = ov.RelayPublicNKeyRef
	}
	if ov.FanoutPublicNKey != "" {
		top.Principals.Fanout.PublicNKey = ov.FanoutPublicNKey
	}
	if ov.FanoutPublicNKeyRef != "" {
		top.Principals.Fanout.PublicNKeyRef = ov.FanoutPublicNKeyRef
	}
	if ov.AdminPublicNKey != "" {
		top.Principals.BrokerAdmin.PublicNKey = ov.AdminPublicNKey
	}
	if ov.AdminPublicNKeyRef != "" {
		top.Principals.BrokerAdmin.PublicNKeyRef = ov.AdminPublicNKeyRef
	}
}

func validateAndBuild(top *Topology) (*ResolvedTopology, error) {
	serverName := strings.TrimSpace(top.ServerName)
	if serverName == "" || strings.ContainsAny(serverName, " \t\r\n") {
		return nil, errors.New("server_name must be non-empty and contain no spaces")
	}

	host := strings.TrimSpace(top.Host)
	if host == "" {
		host = "127.0.0.1"
	}

	clientPort := top.ClientPort
	if clientPort == 0 {
		clientPort = DefaultClientPort
	}
	if err := validateListenPort("client_port", clientPort); err != nil {
		return nil, err
	}

	maxPayload := top.MaxPayload
	if maxPayload == 0 {
		maxPayload = DefaultMaxPayload
	}
	if maxPayload < 4096 {
		return nil, fmt.Errorf("max_payload (%d) must be at least 4096 bytes", maxPayload)
	}

	maxConn := top.MaxConnections
	if maxConn == 0 {
		maxConn = DefaultMaxConnections
	}
	if maxConn < 1 {
		return nil, fmt.Errorf("max_connections (%d) must be positive", maxConn)
	}

	monitorEnabled := true
	if top.Monitoring.Enabled != nil {
		monitorEnabled = *top.Monitoring.Enabled
	}
	monitorHost := strings.TrimSpace(top.Monitoring.Host)
	if monitorHost == "" {
		monitorHost = "127.0.0.1"
	}
	monitorPort := top.Monitoring.Port
	if monitorEnabled && monitorPort == 0 {
		monitorPort = DefaultMonitorPort
	}
	if !monitorEnabled {
		monitorPort = 0
	} else if err := validateListenPort("monitoring.port", monitorPort); err != nil {
		return nil, err
	}

	if top.TLS.Enabled == nil || !*top.TLS.Enabled {
		return nil, errors.New("tls.enabled must be true; plaintext client listeners are forbidden")
	}
	handshakeFirst := true
	if top.TLS.HandshakeFirst != nil {
		handshakeFirst = *top.TLS.HandshakeFirst
	}
	if !handshakeFirst {
		return nil, errors.New("tls.handshake_first must be true")
	}
	if _, err := custody.ParseMinTLSVersion(top.TLS.MinVersion); err != nil {
		return nil, fmt.Errorf("tls.min_version: %w", err)
	}
	if strings.TrimSpace(top.TLS.CertRef) == "" || strings.TrimSpace(top.TLS.KeyRef) == "" {
		return nil, errors.New("tls.cert_ref and tls.key_ref are required")
	}

	if top.JetStream.Enabled == nil || !*top.JetStream.Enabled {
		return nil, errors.New("jetstream.enabled must be true")
	}
	storeDir := strings.TrimSpace(top.JetStream.StoreDir)
	if storeDir == "" {
		return nil, errors.New("jetstream.store_dir is required")
	}
	if top.JetStream.MaxMemoryStore <= 0 {
		return nil, errors.New("jetstream.max_memory_store must be positive")
	}
	if top.JetStream.MaxFileStore <= 0 {
		return nil, errors.New("jetstream.max_file_store must be positive")
	}
	if strings.ToLower(strings.TrimSpace(top.JetStream.SyncInterval)) != "always" {
		return nil, fmt.Errorf("jetstream.sync_interval must be \"always\" (got %q)", top.JetStream.SyncInterval)
	}

	streamName := strings.TrimSpace(top.JetStream.StreamName)
	if streamName == "" {
		streamName = DefaultStreamName
	}
	if !nameIdentRegex.MatchString(streamName) {
		return nil, fmt.Errorf("invalid jetstream.stream_name %q", streamName)
	}

	consumerName := strings.TrimSpace(top.JetStream.ConsumerName)
	if consumerName == "" {
		consumerName = DefaultConsumerName
	}
	if !nameIdentRegex.MatchString(consumerName) {
		return nil, fmt.Errorf("invalid jetstream.consumer_name %q", consumerName)
	}

	subjectPrefix := strings.TrimSpace(top.JetStream.SubjectPrefix)
	if len(subjectPrefix) > 64 || !subjectPrefixRegex.MatchString(subjectPrefix) {
		return nil, fmt.Errorf("invalid jetstream.subject_prefix %q", subjectPrefix)
	}

	jsDomain := strings.TrimSpace(top.JetStream.Domain)
	if jsDomain != "" && strings.ContainsAny(jsDomain, " .*>\t\r\n") {
		return nil, fmt.Errorf("invalid jetstream.domain %q", jsDomain)
	}

	res := &ResolvedTopology{
		ServerName:      serverName,
		Host:            host,
		ClientPort:      clientPort,
		ClientAdvertise: strings.TrimSpace(top.ClientAdvertise),
		MaxPayload:      maxPayload,
		MaxConnections:  maxConn,
		MonitorEnabled:  monitorEnabled,
		MonitorHost:     monitorHost,
		MonitorPort:     monitorPort,
		ClientTLS: custody.ClientTLSOptions{
			CertRef:          strings.TrimSpace(top.TLS.CertRef),
			KeyRef:           strings.TrimSpace(top.TLS.KeyRef),
			CARef:            strings.TrimSpace(top.TLS.CARef),
			MinVersion:       strings.TrimSpace(top.TLS.MinVersion),
			VerifyClientCert: top.TLS.VerifyClientCert,
		},
		HandshakeFirst:  true,
		StoreDir:        storeDir,
		MaxMemoryStore:  top.JetStream.MaxMemoryStore,
		MaxFileStore:    top.JetStream.MaxFileStore,
		SyncAlways:      true,
		StreamName:      streamName,
		ConsumerName:    consumerName,
		SubjectPrefix:   subjectPrefix,
		JetStreamDomain: jsDomain,
	}

	if top.Cluster.Enabled {
		clusterName := strings.TrimSpace(top.Cluster.Name)
		if clusterName == "" || strings.ContainsAny(clusterName, " \t\r\n") {
			return nil, errors.New("cluster.name must be non-empty and contain no spaces when cluster is enabled")
		}
		clusterHost := strings.TrimSpace(top.Cluster.Host)
		if clusterHost == "" {
			clusterHost = "127.0.0.1"
		}
		clusterPort := top.Cluster.Port
		if clusterPort == 0 {
			clusterPort = DefaultClusterPort
		}
		if err := validateListenPort("cluster.port", clusterPort); err != nil {
			return nil, err
		}
		if _, err := custody.ParseMinTLSVersion(top.Cluster.TLS.MinVersion); err != nil {
			return nil, fmt.Errorf("cluster.tls.min_version: %w", err)
		}
		if strings.TrimSpace(top.Cluster.TLS.CARef) == "" ||
			strings.TrimSpace(top.Cluster.TLS.CertRef) == "" ||
			strings.TrimSpace(top.Cluster.TLS.KeyRef) == "" {
			return nil, errors.New("cluster.tls ca_ref, cert_ref, and key_ref are required when cluster is enabled")
		}
		if _, err := custody.NewRoutePeerAllowlist(top.Cluster.AllowedRoutePeers); err != nil {
			return nil, err
		}

		routeURLs := make([]*url.URL, 0, len(top.Cluster.Routes))
		for _, rawRoute := range top.Cluster.Routes {
			u, err := parseRouteURL(rawRoute)
			if err != nil {
				return nil, fmt.Errorf("invalid cluster route %q: %w", rawRoute, err)
			}
			routeURLs = append(routeURLs, u)
		}

		res.ClusterEnabled = true
		res.ClusterName = clusterName
		res.ClusterHost = clusterHost
		res.ClusterPort = clusterPort
		res.ClusterAdvertise = strings.TrimSpace(top.Cluster.Advertise)
		res.RouteURLs = routeURLs
		res.AllowedRoutePeers = append([]string(nil), top.Cluster.AllowedRoutePeers...)
		res.ClusterTLS = custody.ClusterTLSOptions{
			CARef:        strings.TrimSpace(top.Cluster.TLS.CARef),
			CertRef:      strings.TrimSpace(top.Cluster.TLS.CertRef),
			KeyRef:       strings.TrimSpace(top.Cluster.TLS.KeyRef),
			MinVersion:   strings.TrimSpace(top.Cluster.TLS.MinVersion),
			AllowedPeers: append([]string(nil), top.Cluster.AllowedRoutePeers...),
		}
	}

	relay, err := resolvePrincipal("relay", top.Principals.Relay, DefaultRelayInbox, res)
	if err != nil {
		return nil, err
	}
	fanout, err := resolvePrincipal("fanout", top.Principals.Fanout, DefaultFanoutInbox, res)
	if err != nil {
		return nil, err
	}
	admin, err := resolvePrincipal("broker_admin", top.Principals.BrokerAdmin, DefaultAdminInbox, res)
	if err != nil {
		return nil, err
	}

	if relay.PublicNKey == fanout.PublicNKey ||
		relay.PublicNKey == admin.PublicNKey ||
		fanout.PublicNKey == admin.PublicNKey {
		return nil, errors.New("principals relay, fanout, and broker_admin must each use a distinct public NKey")
	}
	if relay.InboxPrefix == fanout.InboxPrefix ||
		relay.InboxPrefix == admin.InboxPrefix ||
		fanout.InboxPrefix == admin.InboxPrefix {
		return nil, errors.New("principals relay, fanout, and broker_admin must each use a distinct inbox_prefix")
	}

	res.Relay = relay
	res.Fanout = fanout
	res.BrokerAdmin = admin
	return res, nil
}

func resolvePrincipal(role string, cfg PrincipalConfig, defaultInbox string, top *ResolvedTopology) (ResolvedPrincipal, error) {
	pubKey, err := custody.ResolvePublicNKey(cfg.PublicNKey, cfg.PublicNKeyRef)
	if err != nil {
		return ResolvedPrincipal{}, fmt.Errorf("principal %s: %w", role, err)
	}

	inbox := strings.TrimSpace(cfg.InboxPrefix)
	if inbox == "" {
		inbox = defaultInbox
	}
	if !inboxPrefixRegex.MatchString(inbox) {
		return ResolvedPrincipal{}, fmt.Errorf("principal %s: invalid inbox_prefix %q", role, inbox)
	}

	pubAllow, subAllow := deriveRoleACLs(role, inbox, top)
	if len(cfg.PublishAllow) > 0 {
		pubAllow = append([]string(nil), cfg.PublishAllow...)
	}
	if len(cfg.SubscribeAllow) > 0 {
		subAllow = append([]string(nil), cfg.SubscribeAllow...)
	}

	if err := validateRoleACLs(role, inbox, top, pubAllow, subAllow); err != nil {
		return ResolvedPrincipal{}, err
	}

	return ResolvedPrincipal{
		Role:           role,
		PublicNKey:     pubKey,
		InboxPrefix:    inbox,
		PublishAllow:   pubAllow,
		SubscribeAllow: subAllow,
	}, nil
}

func deriveRoleACLs(role, inbox string, top *ResolvedTopology) (pubAllow, subAllow []string) {
	subAllow = []string{inbox + ".*", inbox + ".*.*"}

	switch role {
	case "relay":
		pubAllow = []string{top.SubjectPrefix + "rq.events.*.accepted"}
	case "fanout":
		pubAllow = []string{
			fmt.Sprintf("$JS.API.CONSUMER.MSG.NEXT.%s.%s", top.StreamName, top.ConsumerName),
			fmt.Sprintf("$JS.API.CONSUMER.INFO.%s.%s", top.StreamName, top.ConsumerName),
			fmt.Sprintf("$JS.API.STREAM.INFO.%s", top.StreamName),
			fmt.Sprintf("$JS.ACK.%s.%s.>", top.StreamName, top.ConsumerName),
			fmt.Sprintf("$JS.ACK.*.*.%s.%s.>", top.StreamName, top.ConsumerName),
		}
	case "broker_admin":
		pubAllow = []string{
			"$JS.API.INFO",
			"$JS.API.STREAM.NAMES",
			"$JS.API.STREAM.LIST",
			fmt.Sprintf("$JS.API.STREAM.INFO.%s", top.StreamName),
			fmt.Sprintf("$JS.API.STREAM.CREATE.%s", top.StreamName),
			fmt.Sprintf("$JS.API.STREAM.UPDATE.%s", top.StreamName),
			fmt.Sprintf("$JS.API.STREAM.DELETE.%s", top.StreamName),
			fmt.Sprintf("$JS.API.STREAM.PURGE.%s", top.StreamName),
			fmt.Sprintf("$JS.API.CONSUMER.NAMES.%s", top.StreamName),
			fmt.Sprintf("$JS.API.CONSUMER.LIST.%s", top.StreamName),
			fmt.Sprintf("$JS.API.CONSUMER.INFO.%s.*", top.StreamName),
			fmt.Sprintf("$JS.API.CONSUMER.CREATE.%s.>", top.StreamName),
			fmt.Sprintf("$JS.API.CONSUMER.DELETE.%s.*", top.StreamName),
			fmt.Sprintf("$JS.API.CONSUMER.PAUSE.%s.*", top.StreamName),
		}
	}
	return pubAllow, subAllow
}

func validateRoleACLs(role, inbox string, top *ResolvedTopology, pubAllow, subAllow []string) error {
	if len(pubAllow) == 0 {
		return fmt.Errorf("principal %s: publish_allow cannot be empty", role)
	}
	if len(subAllow) == 0 {
		return fmt.Errorf("principal %s: subscribe_allow cannot be empty", role)
	}

	expectedInboxDot := inbox + "."
	for _, sub := range subAllow {
		if err := validateSubjectToken("subscribe_allow", sub); err != nil {
			return fmt.Errorf("principal %s: %w", role, err)
		}
		if !strings.HasPrefix(sub, expectedInboxDot) {
			return fmt.Errorf("principal %s: subscribe_allow subject %q escapes inbox_prefix %q", role, sub, inbox)
		}
	}

	expectedEventPrefix := top.SubjectPrefix + "rq.events."
	for _, pub := range pubAllow {
		if err := validateSubjectToken("publish_allow", pub); err != nil {
			return fmt.Errorf("principal %s: %w", role, err)
		}
		switch role {
		case "relay":
			if !strings.HasPrefix(pub, expectedEventPrefix) || !strings.HasSuffix(pub, ".accepted") {
				return fmt.Errorf("principal relay: publish_allow subject %q exceeds accepted event scope", pub)
			}
		case "fanout":
			if strings.HasPrefix(pub, expectedEventPrefix) {
				return fmt.Errorf("principal fanout: publish_allow subject %q cannot publish accepted events", pub)
			}
			allowedFanout := pub == fmt.Sprintf("$JS.API.CONSUMER.MSG.NEXT.%s.%s", top.StreamName, top.ConsumerName) ||
				pub == fmt.Sprintf("$JS.API.CONSUMER.INFO.%s.%s", top.StreamName, top.ConsumerName) ||
				pub == fmt.Sprintf("$JS.API.STREAM.INFO.%s", top.StreamName) ||
				pub == fmt.Sprintf("$JS.ACK.%s.%s.>", top.StreamName, top.ConsumerName) ||
				pub == fmt.Sprintf("$JS.ACK.*.*.%s.%s.>", top.StreamName, top.ConsumerName)
			if !allowedFanout {
				return fmt.Errorf("principal fanout: publish_allow subject %q exceeds pull/info/ack scope", pub)
			}
		case "broker_admin":
			if strings.HasPrefix(pub, expectedEventPrefix) {
				return fmt.Errorf("principal broker_admin: publish_allow subject %q cannot publish accepted events", pub)
			}
			if strings.HasPrefix(pub, "$JS.ACK.") || strings.HasPrefix(pub, "$JS.API.CONSUMER.MSG.NEXT.") {
				return fmt.Errorf("principal broker_admin: publish_allow subject %q cannot pull or ack messages", pub)
			}
			if !strings.HasPrefix(pub, "$JS.API.") {
				return fmt.Errorf("principal broker_admin: publish_allow subject %q must be scoped to $JS.API", pub)
			}
		}
	}
	return nil
}

func validateSubjectToken(field, subj string) error {
	s := strings.TrimSpace(subj)
	if s == "" || s != subj || strings.ContainsAny(s, " \t\r\n") {
		return fmt.Errorf("%s entry %q is empty or contains whitespace", field, subj)
	}
	if s == ">" || s == "*" || s == "$JS.API.>" || s == "$JS.ACK.>" {
		return fmt.Errorf("%s entry %q is overly broad", field, subj)
	}
	return nil
}

func validateListenPort(field string, port int) error {
	if port == -1 {
		return nil
	}
	if port < 1 || port > 65535 {
		return fmt.Errorf("%s (%d) must be 1..65535 or -1", field, port)
	}
	return nil
}

func parseRouteURL(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, err
	}
	if u.Scheme != "nats" && u.Scheme != "nats-route" {
		return nil, fmt.Errorf("unexpected route scheme %q", u.Scheme)
	}
	if u.Hostname() == "" || u.Port() == "" {
		return nil, errors.New("route URL must include host and port")
	}
	return u, nil
}
