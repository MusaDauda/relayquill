package broker

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/nats-io/nkeys"

	"github.com/relayquill/relayquill/tools/broker-launcher/internal/custody"
	"github.com/relayquill/relayquill/tools/broker-launcher/internal/topology"
)

type pkiAuthority struct {
	cert  *x509.Certificate
	key   *ecdsa.PrivateKey
	caPEM []byte
	pool  *x509.CertPool
}

type certMaterial struct {
	certPEM []byte
	keyPEM  []byte
	tlsCert tls.Certificate
}

type nkeyCreds struct {
	kp   nkeys.KeyPair
	pub  string
	seed string
}

func newPKI(t *testing.T, cn string) *pkiAuthority {
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
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &pkiAuthority{cert: cert, key: key, caPEM: caPEM, pool: pool}
}

func (p *pkiAuthority) issue(t *testing.T, cn string, dns []string, ips []net.IP) certMaterial {
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
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     dns,
		IPAddresses:  ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.cert, &key.PublicKey, p.key)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal leaf key: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}
	return certMaterial{certPEM: certPEM, keyPEM: keyPEM, tlsCert: tlsCert}
}

func newUserNKey(t *testing.T) nkeyCreds {
	t.Helper()
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
	return nkeyCreds{kp: kp, pub: pub, seed: string(seed)}
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

type brokerTestFixture struct {
	inst      *Instance
	ca        *pkiAuthority
	relay     nkeyCreds
	fanout    nkeyCreds
	admin     nkeyCreds
	logBuffer *syncBuffer
}

func startSingleNodeFixture(t *testing.T, minTLS string, withProbe bool) *brokerTestFixture {
	t.Helper()
	ca := newPKI(t, "relayquill-broker-ca")
	srvCert := ca.issue(t, "broker-1.internal.test", []string{"broker-1.internal.test", "localhost"}, []net.IP{net.ParseIP("127.0.0.1")})
	relayKey := newUserNKey(t)
	fanoutKey := newUserNKey(t)
	adminKey := newUserNKey(t)

	dir := t.TempDir()
	caFile := filepath.Join(dir, "ca.pem")
	certFile := filepath.Join(dir, "server.crt")
	keyFile := filepath.Join(dir, "server.key")
	if err := os.WriteFile(caFile, ca.caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certFile, srvCert.certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, srvCert.keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	probeSeedRef := ""
	probeInbox := ""
	if withProbe {
		t.Setenv("TEST_PROBE_ADMIN_SEED", adminKey.seed)
		probeSeedRef = "env:TEST_PROBE_ADMIN_SEED"
		probeInbox = topology.DefaultAdminInbox
	}

	topJSON := fmt.Sprintf(`{
		"schema_version": 1,
		"server_name": "broker-1",
		"host": "127.0.0.1",
		"client_port": -1,
		"max_payload": 8192,
		"max_connections": 64,
		"monitoring": { "enabled": true, "host": "127.0.0.1", "port": -1 },
		"tls": {
			"enabled": true,
			"handshake_first": true,
			"min_version": %q,
			"ca_ref": %q,
			"cert_ref": %q,
			"key_ref": %q
		},
		"jetstream": {
			"enabled": true,
			"store_dir": %q,
			"max_memory_store": 67108864,
			"max_file_store": 268435456,
			"sync_interval": "always",
			"stream_name": "RELAYQUILL_EVENTS_V1",
			"consumer_name": "RELAYQUILL_FANOUT_V1",
			"subject_prefix": ""
		},
		"principals": {
			"relay": { "public_nkey": %q, "inbox_prefix": "_INBOX.rq.relay" },
			"fanout": { "public_nkey": %q, "inbox_prefix": "_INBOX.rq.fanout" },
			"broker_admin": { "public_nkey": %q, "inbox_prefix": "_INBOX.rq.admin" }
		}
	}`, minTLS, "file:"+caFile, "file:"+certFile, "file:"+keyFile, filepath.Join(dir, "js"), relayKey.pub, fanoutKey.pub, adminKey.pub)

	resolved, err := topology.ParseAndResolve([]byte(topJSON), topology.Overrides{})
	if err != nil {
		t.Fatalf("ParseAndResolve: %v", err)
	}

	var logBuf syncBuffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	inst, err := Start(ctx, LaunchOptions{
		Topology:         resolved,
		Logger:           logger,
		ReadyTimeout:     10 * time.Second,
		ProbeNKeySeedRef: probeSeedRef,
		ProbeInboxPrefix: probeInbox,
		ReadyFile:        filepath.Join(dir, "broker.ready"),
	})
	if err != nil {
		t.Fatalf("Start broker: %v\nlogs: %s", err, logBuf.String())
	}

	t.Cleanup(func() {
		shutCtx, shutCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutCancel()
		_ = inst.Shutdown(shutCtx)
	})

	return &brokerTestFixture{
		inst:      inst,
		ca:        ca,
		relay:     relayKey,
		fanout:    fanoutKey,
		admin:     adminKey,
		logBuffer: &logBuf,
	}
}

func connectTLSPrincipal(t *testing.T, addr string, caPool *x509.CertPool, serverName string, creds nkeyCreds, inboxPrefix string, errCh chan<- error) (*nats.Conn, error) {
	t.Helper()
	tlsCfg := &tls.Config{
		RootCAs:    caPool,
		ServerName: serverName,
		MinVersion: tls.VersionTLS12,
	}
	opts := []nats.Option{
		nats.TLSHandshakeFirst(),
		nats.Secure(tlsCfg),
		nats.Nkey(creds.pub, func(nonce []byte) ([]byte, error) {
			return creds.kp.Sign(nonce)
		}),
		nats.CustomInboxPrefix(inboxPrefix),
		nats.Timeout(3 * time.Second),
		nats.NoReconnect(),
	}
	if errCh != nil {
		opts = append(opts, nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) {
			select {
			case errCh <- err:
			default:
			}
		}))
	}
	return nats.Connect("tls://"+addr, opts...)
}

func TestAuthorizedRelayPublishAndFanoutPullAck(t *testing.T) {
	fx := startSingleNodeFixture(t, "1.2", true)
	addr := fx.inst.ClientAddr().String()

	// Verify /healthz?js-enabled-only=true on private monitoring port.
	monAddr := fx.inst.MonitorAddr()
	if monAddr == nil {
		t.Fatal("expected MonitorAddr")
	}
	resp, err := http.Get(fmt.Sprintf("http://%s/healthz?js-enabled-only=true", monAddr.String()))
	if err != nil {
		t.Fatalf("monitoring /healthz GET: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK from /healthz, got %d: %s", resp.StatusCode, string(body))
	}

	adminConn, err := connectTLSPrincipal(t, addr, fx.ca.pool, "broker-1.internal.test", fx.admin, "_INBOX.rq.admin", nil)
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	defer adminConn.Close()

	adminJS, err := jetstream.New(adminConn)
	if err != nil {
		t.Fatalf("admin jetstream: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	stream, err := adminJS.CreateOrUpdateStream(ctx, jetstream.StreamConfig{
		Name:       "RELAYQUILL_EVENTS_V1",
		Subjects:   []string{"rq.events.*.accepted"},
		Storage:    jetstream.FileStorage,
		Retention:  jetstream.LimitsPolicy,
		Discard:    jetstream.DiscardNew,
		MaxMsgs:    1000,
		MaxBytes:   1024 * 1024,
		MaxMsgSize: 4096,
		MaxAge:     time.Hour,
		Duplicates: 2 * time.Minute,
		Replicas:   1,
	})
	if err != nil {
		t.Fatalf("CreateOrUpdateStream: %v", err)
	}
	_, err = stream.CreateOrUpdateConsumer(ctx, jetstream.ConsumerConfig{
		Durable:       "RELAYQUILL_FANOUT_V1",
		AckPolicy:     jetstream.AckExplicitPolicy,
		DeliverPolicy: jetstream.DeliverAllPolicy,
		AckWait:       30 * time.Second,
		MaxDeliver:    10,
		MaxAckPending: 128,
	})
	if err != nil {
		t.Fatalf("CreateOrUpdateConsumer: %v", err)
	}

	// Relay publishes notification envelope with Nats-Msg-Id and verifies dedup on retry.
	relayConn, err := connectTLSPrincipal(t, addr, fx.ca.pool, "broker-1.internal.test", fx.relay, "_INBOX.rq.relay", nil)
	if err != nil {
		t.Fatalf("relay connect: %v", err)
	}
	defer relayConn.Close()

	relayJS, err := jetstream.New(relayConn)
	if err != nil {
		t.Fatalf("relay jetstream: %v", err)
	}
	envelope := []byte(`{"envelope_version":1,"event_id":"22222222-2222-4222-8222-222222222222","project_id":"11111111-1111-4111-8111-111111111111"}`)
	subject := "rq.events.11111111-1111-4111-8111-111111111111.accepted"
	msgID := "rq:33333333-3333-4333-8333-333333333333:1"

	pubAck, err := relayJS.Publish(ctx, subject, envelope, jetstream.WithMsgID(msgID))
	if err != nil {
		t.Fatalf("relay Publish: %v", err)
	}
	if pubAck.Stream != "RELAYQUILL_EVENTS_V1" || pubAck.Sequence != 1 || pubAck.Duplicate {
		t.Fatalf("unexpected PubAck: %+v", pubAck)
	}

	dupAck, err := relayJS.Publish(ctx, subject, envelope, jetstream.WithMsgID(msgID))
	if err != nil {
		t.Fatalf("relay duplicate Publish: %v", err)
	}
	if !dupAck.Duplicate || dupAck.Sequence != 1 {
		t.Fatalf("expected deduplicated PubAck seq 1, got %+v", dupAck)
	}

	// Fanout inspects stream/consumer, fetches message, and DoubleAcks it.
	fanoutConn, err := connectTLSPrincipal(t, addr, fx.ca.pool, "broker-1.internal.test", fx.fanout, "_INBOX.rq.fanout", nil)
	if err != nil {
		t.Fatalf("fanout connect: %v", err)
	}
	defer fanoutConn.Close()

	fanoutJS, err := jetstream.New(fanoutConn)
	if err != nil {
		t.Fatalf("fanout jetstream: %v", err)
	}
	fanoutStream, err := fanoutJS.Stream(ctx, "RELAYQUILL_EVENTS_V1")
	if err != nil {
		t.Fatalf("fanout Stream info: %v", err)
	}
	consumer, err := fanoutStream.Consumer(ctx, "RELAYQUILL_FANOUT_V1")
	if err != nil {
		t.Fatalf("fanout Consumer info: %v", err)
	}
	batch, err := consumer.Fetch(1, jetstream.FetchMaxWait(3*time.Second))
	if err != nil {
		t.Fatalf("fanout Fetch: %v", err)
	}

	var received jetstream.Msg
	for msg := range batch.Messages() {
		received = msg
	}
	if err := batch.Error(); err != nil {
		t.Fatalf("batch error: %v", err)
	}
	if received == nil || received.Subject() != subject || !bytes.Equal(received.Data(), envelope) {
		t.Fatalf("unexpected fetched message: %v", received)
	}
	if err := received.DoubleAck(ctx); err != nil {
		t.Fatalf("fanout DoubleAck: %v", err)
	}

	cInfo, err := consumer.Info(ctx)
	if err != nil {
		t.Fatalf("consumer info after ack: %v", err)
	}
	if cInfo.NumPending != 0 || cInfo.AckFloor.Stream != 1 {
		t.Fatalf("expected pending=0 and ack_floor=1, got pending=%d ack_floor=%d", cInfo.NumPending, cInfo.AckFloor.Stream)
	}
}

func TestTLSAndPlaintextRejection(t *testing.T) {
	fx := startSingleNodeFixture(t, "1.3", false)
	addr := fx.inst.ClientAddr().String()

	// 1. Plaintext connection must fail.
	if nc, err := nats.Connect("nats://"+addr, nats.UserInfo("x", "y"), nats.Timeout(time.Second)); err == nil {
		nc.Close()
		t.Fatal("expected plaintext nats:// connection to fail")
	}

	// 2. TLS without TLSHandshakeFirst must fail because server requires TLS before INFO.
	if nc, err := nats.Connect("tls://"+addr,
		nats.Secure(&tls.Config{RootCAs: fx.ca.pool, ServerName: "broker-1.internal.test", MinVersion: tls.VersionTLS13}),
		nats.Nkey(fx.relay.pub, func(nonce []byte) ([]byte, error) { return fx.relay.kp.Sign(nonce) }),
		nats.Timeout(1200*time.Millisecond),
		nats.NoReconnect(),
	); err == nil {
		nc.Close()
		t.Fatal("expected TLS connection without TLSHandshakeFirst to fail")
	}

	// 3. Untrusted CA must fail TLS verification.
	rogueCA := newPKI(t, "rogue-ca")
	if nc, err := connectTLSPrincipal(t, addr, rogueCA.pool, "broker-1.internal.test", fx.relay, "_INBOX.rq.relay", nil); err == nil {
		nc.Close()
		t.Fatal("expected untrusted CA connection to fail")
	}

	// 4. Wrong ServerName hostname must fail certificate hostname verification.
	if nc, err := connectTLSPrincipal(t, addr, fx.ca.pool, "wrong-host.internal.test", fx.relay, "_INBOX.rq.relay", nil); err == nil {
		nc.Close()
		t.Fatal("expected wrong hostname connection to fail")
	}

	// 5. TLS 1.2 client against MinVersion 1.3 server must fail.
	if nc, err := nats.Connect("tls://"+addr,
		nats.TLSHandshakeFirst(),
		nats.Secure(&tls.Config{RootCAs: fx.ca.pool, ServerName: "broker-1.internal.test", MaxVersion: tls.VersionTLS12}),
		nats.Nkey(fx.relay.pub, func(nonce []byte) ([]byte, error) { return fx.relay.kp.Sign(nonce) }),
		nats.Timeout(2*time.Second),
		nats.NoReconnect(),
	); err == nil {
		nc.Close()
		t.Fatal("expected TLS 1.2 client to fail against TLS 1.3 minimum server")
	}

	// 6. Unregistered NKey over valid TLS must fail authentication.
	unknownKey := newUserNKey(t)
	if nc, err := connectTLSPrincipal(t, addr, fx.ca.pool, "broker-1.internal.test", unknownKey, "_INBOX.rq.relay", nil); err == nil {
		nc.Close()
		t.Fatal("expected unregistered NKey to fail authentication")
	}
}

func TestCrossPrincipalPermissionIsolation(t *testing.T) {
	fx := startSingleNodeFixture(t, "1.2", false)
	addr := fx.inst.ClientAddr().String()

	adminErrs := make(chan error, 16)
	relayErrs := make(chan error, 16)
	fanoutErrs := make(chan error, 16)

	adminConn, err := connectTLSPrincipal(t, addr, fx.ca.pool, "broker-1.internal.test", fx.admin, "_INBOX.rq.admin", adminErrs)
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	defer adminConn.Close()

	relayConn, err := connectTLSPrincipal(t, addr, fx.ca.pool, "broker-1.internal.test", fx.relay, "_INBOX.rq.relay", relayErrs)
	if err != nil {
		t.Fatalf("relay connect: %v", err)
	}
	defer relayConn.Close()

	fanoutConn, err := connectTLSPrincipal(t, addr, fx.ca.pool, "broker-1.internal.test", fx.fanout, "_INBOX.rq.fanout", fanoutErrs)
	if err != nil {
		t.Fatalf("fanout connect: %v", err)
	}
	defer fanoutConn.Close()

	// Ensure stream/consumer exist via broker_admin.
	adminJS, err := jetstream.New(adminConn)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream, err := adminJS.CreateOrUpdateStream(ctx, jetstream.StreamConfig{
		Name:     "RELAYQUILL_EVENTS_V1",
		Subjects: []string{"rq.events.*.accepted"},
		Storage:  jetstream.FileStorage,
		Discard:  jetstream.DiscardNew,
	})
	if err != nil {
		t.Fatalf("create stream: %v", err)
	}
	if _, err := stream.CreateOrUpdateConsumer(ctx, jetstream.ConsumerConfig{
		Durable:   "RELAYQUILL_FANOUT_V1",
		AckPolicy: jetstream.AckExplicitPolicy,
	}); err != nil {
		t.Fatalf("create consumer: %v", err)
	}

	assertDenied := func(label string, nc *nats.Conn, errCh <-chan error, action func()) {
		t.Helper()
		for len(errCh) > 0 {
			<-errCh
		}
		action()
		_ = nc.Flush()
		select {
		case got := <-errCh:
			if !strings.Contains(strings.ToLower(got.Error()), "permissions violation") {
				t.Fatalf("%s: expected permissions violation, got %v", label, got)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("%s: expected permissions violation error, timed out", label)
		}
	}

	// Relay cannot publish outside rq.events.*.accepted, cannot pull/ack, cannot admin JS, cannot subscribe to other inboxes.
	assertDenied("relay_pub_arbitrary", relayConn, relayErrs, func() {
		_ = relayConn.Publish("rq.other.topic", []byte("x"))
	})
	assertDenied("relay_pub_js_admin", relayConn, relayErrs, func() {
		_ = relayConn.Publish("$JS.API.STREAM.CREATE.EVIL", []byte("{}"))
	})
	assertDenied("relay_pub_ack", relayConn, relayErrs, func() {
		_ = relayConn.Publish("$JS.ACK.RELAYQUILL_EVENTS_V1.RELAYQUILL_FANOUT_V1.1.1.1.1.1", []byte("+ACK"))
	})
	assertDenied("relay_sub_fanout_inbox", relayConn, relayErrs, func() {
		if sub, subErr := relayConn.SubscribeSync("_INBOX.rq.fanout.hijack"); subErr == nil {
			_ = sub.Unsubscribe()
		}
	})
	assertDenied("relay_sub_events", relayConn, relayErrs, func() {
		if sub, subErr := relayConn.SubscribeSync("rq.events.*.accepted"); subErr == nil {
			_ = sub.Unsubscribe()
		}
	})

	// Fanout cannot publish events, cannot create/delete streams or consumers, cannot ack unrelated stream/consumer.
	assertDenied("fanout_pub_event", fanoutConn, fanoutErrs, func() {
		_ = fanoutConn.Publish("rq.events.11111111-1111-4111-8111-111111111111.accepted", []byte("{}"))
	})
	assertDenied("fanout_create_stream", fanoutConn, fanoutErrs, func() {
		_ = fanoutConn.Publish("$JS.API.STREAM.CREATE.EVIL", []byte("{}"))
	})
	assertDenied("fanout_delete_stream", fanoutConn, fanoutErrs, func() {
		_ = fanoutConn.Publish("$JS.API.STREAM.DELETE.RELAYQUILL_EVENTS_V1", []byte("{}"))
	})
	assertDenied("fanout_create_consumer", fanoutConn, fanoutErrs, func() {
		_ = fanoutConn.Publish("$JS.API.CONSUMER.CREATE.RELAYQUILL_EVENTS_V1.ROGUE", []byte("{}"))
	})
	assertDenied("fanout_ack_other_stream", fanoutConn, fanoutErrs, func() {
		_ = fanoutConn.Publish("$JS.ACK.OTHER_STREAM.RELAYQUILL_FANOUT_V1.1.1.1.1.1", []byte("+ACK"))
	})
	assertDenied("fanout_ack_other_consumer", fanoutConn, fanoutErrs, func() {
		_ = fanoutConn.Publish("$JS.ACK.RELAYQUILL_EVENTS_V1.OTHER_CONSUMER.1.1.1.1.1", []byte("+ACK"))
	})
	assertDenied("fanout_ack_domain_other_stream", fanoutConn, fanoutErrs, func() {
		_ = fanoutConn.Publish("$JS.ACK.dom.acc.OTHER_STREAM.RELAYQUILL_FANOUT_V1.1.1.1.1.1", []byte("+ACK"))
	})
	assertDenied("fanout_sub_relay_inbox", fanoutConn, fanoutErrs, func() {
		if sub, subErr := fanoutConn.SubscribeSync("_INBOX.rq.relay.hijack"); subErr == nil {
			_ = sub.Unsubscribe()
		}
	})

	// Verify fanout domain/account-hash ACK layout IS allowed for RELAYQUILL_EVENTS_V1 / RELAYQUILL_FANOUT_V1.
	if err := fanoutConn.Publish("$JS.ACK.dom1.acc1.RELAYQUILL_EVENTS_V1.RELAYQUILL_FANOUT_V1.1.1.1.1.1", []byte("+ACK")); err != nil {
		t.Fatalf("expected domain ACK subject publish call to succeed locally: %v", err)
	}
	if err := fanoutConn.Flush(); err != nil {
		t.Fatalf("flush domain ACK: %v", err)
	}
	select {
	case unexpected := <-fanoutErrs:
		t.Fatalf("expected domain ACK layout for scoped stream/consumer to be permitted, got %v", unexpected)
	case <-time.After(150 * time.Millisecond):
	}

	// Admin cannot publish events, cannot pull consumer messages, cannot ack messages, cannot subscribe to fanout inbox.
	assertDenied("admin_pub_event", adminConn, adminErrs, func() {
		_ = adminConn.Publish("rq.events.11111111-1111-4111-8111-111111111111.accepted", []byte("{}"))
	})
	assertDenied("admin_pull_next", adminConn, adminErrs, func() {
		_ = adminConn.Publish("$JS.API.CONSUMER.MSG.NEXT.RELAYQUILL_EVENTS_V1.RELAYQUILL_FANOUT_V1", []byte(`{"batch":1}`))
	})
	assertDenied("admin_pub_ack", adminConn, adminErrs, func() {
		_ = adminConn.Publish("$JS.ACK.RELAYQUILL_EVENTS_V1.RELAYQUILL_FANOUT_V1.1.1.1.1.1", []byte("+ACK"))
	})
	assertDenied("admin_sub_fanout_inbox", adminConn, adminErrs, func() {
		if sub, subErr := adminConn.SubscribeSync("_INBOX.rq.fanout.hijack"); subErr == nil {
			_ = sub.Unsubscribe()
		}
	})
}

func reserveLoopbackPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

func TestClusterRouteMTLSAndUnauthorizedPeerRejection(t *testing.T) {
	clientCA := newPKI(t, "client-ca")
	clusterCA := newPKI(t, "cluster-ca")
	rogueCA := newPKI(t, "rogue-ca")

	relayKey := newUserNKey(t)
	fanoutKey := newUserNKey(t)
	adminKey := newUserNKey(t)

	routePorts := []int{reserveLoopbackPort(t), reserveLoopbackPort(t), reserveLoopbackPort(t)}
	routes := []string{
		fmt.Sprintf("nats://127.0.0.1:%d", routePorts[0]),
		fmt.Sprintf("nats://127.0.0.1:%d", routePorts[1]),
		fmt.Sprintf("nats://127.0.0.1:%d", routePorts[2]),
	}
	routesJSON, _ := json.Marshal(routes)

	baseDir := t.TempDir()
	clientCAPath := filepath.Join(baseDir, "client-ca.pem")
	clusterCAPath := filepath.Join(baseDir, "cluster-ca.pem")
	if err := os.WriteFile(clientCAPath, clientCA.caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(clusterCAPath, clusterCA.caPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	var nodeLogs [3]syncBuffer
	instances := make([]*Instance, 0, 3)
	for idx := range 3 {
		nodeName := fmt.Sprintf("broker-%d", idx+1)
		clientDNS := fmt.Sprintf("broker-%d.internal.test", idx+1)
		routeDNS := fmt.Sprintf("broker-%d.cluster.test", idx+1)

		cCert := clientCA.issue(t, clientDNS, []string{clientDNS}, []net.IP{net.ParseIP("127.0.0.1")})
		rCert := clusterCA.issue(t, routeDNS, []string{routeDNS}, []net.IP{net.ParseIP("127.0.0.1")})

		nodeDir := filepath.Join(baseDir, nodeName)
		if err := os.MkdirAll(nodeDir, 0o750); err != nil {
			t.Fatal(err)
		}
		cCertPath := filepath.Join(nodeDir, "client.crt")
		cKeyPath := filepath.Join(nodeDir, "client.key")
		rCertPath := filepath.Join(nodeDir, "route.crt")
		rKeyPath := filepath.Join(nodeDir, "route.key")
		for path, data := range map[string][]byte{
			cCertPath: cCert.certPEM,
			cKeyPath:  cCert.keyPEM,
			rCertPath: rCert.certPEM,
			rKeyPath:  rCert.keyPEM,
		} {
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
		}

		topJSON := fmt.Sprintf(`{
			"schema_version": 1,
			"server_name": %q,
			"host": "127.0.0.1",
			"client_port": -1,
			"max_payload": 8192,
			"max_connections": 64,
			"monitoring": { "enabled": false },
			"tls": {
				"enabled": true,
				"handshake_first": true,
				"min_version": "1.2",
				"ca_ref": %q,
				"cert_ref": %q,
				"key_ref": %q
			},
			"cluster": {
				"enabled": true,
				"name": "rq-cluster-test",
				"host": "127.0.0.1",
				"port": %d,
				"routes": %s,
				"allowed_route_peers": ["broker-1.cluster.test", "broker-2.cluster.test", "broker-3.cluster.test"],
				"tls": {
					"min_version": "1.3",
					"ca_ref": %q,
					"cert_ref": %q,
					"key_ref": %q
				}
			},
			"jetstream": {
				"enabled": true,
				"store_dir": %q,
				"max_memory_store": 67108864,
				"max_file_store": 268435456,
				"sync_interval": "always"
			},
			"principals": {
				"relay": { "public_nkey": %q },
				"fanout": { "public_nkey": %q },
				"broker_admin": { "public_nkey": %q }
			}
		}`,
			nodeName,
			"file:"+clientCAPath, "file:"+cCertPath, "file:"+cKeyPath,
			routePorts[idx], string(routesJSON),
			"file:"+clusterCAPath, "file:"+rCertPath, "file:"+rKeyPath,
			filepath.Join(nodeDir, "js"),
			relayKey.pub, fanoutKey.pub, adminKey.pub,
		)

		resolved, err := topology.ParseAndResolve([]byte(topJSON), topology.Overrides{})
		if err != nil {
			t.Fatalf("ParseAndResolve %s: %v", nodeName, err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		inst, err := Start(ctx, LaunchOptions{
			Topology:     resolved,
			Logger:       slog.New(slog.NewJSONHandler(&nodeLogs[idx], nil)),
			ReadyTimeout: 10 * time.Second,
		})
		cancel()
		if err != nil {
			t.Fatalf("Start %s: %v", nodeName, err)
		}
		instances = append(instances, inst)
		t.Cleanup(func() {
			shutCtx, shutCancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer shutCancel()
			_ = inst.Shutdown(shutCtx)
		})
	}

	// Wait for full 3-node route mesh.
	deadline := time.Now().Add(10 * time.Second)
	for {
		allConnected := true
		for _, inst := range instances {
			if inst.Server().NumRoutes() < 2 {
				allConnected = false
				break
			}
		}
		if allConnected {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for 3-node cluster routes\nnode0=%s\nnode1=%s\nnode2=%s", nodeLogs[0].String(), nodeLogs[1].String(), nodeLogs[2].String())
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Create 3-replica stream & consumer via broker-1 and publish/consume via broker-2/broker-3.
	adminConn, err := connectTLSPrincipal(t, instances[0].ClientAddr().String(), clientCA.pool, "broker-1.internal.test", adminKey, "_INBOX.rq.admin", nil)
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	defer adminConn.Close()
	adminJS, err := jetstream.New(adminConn)
	if err != nil {
		t.Fatal(err)
	}

	// Wait briefly for JetStream meta leader election in the 3-node cluster.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var stream jetstream.Stream
	var lastCreateErr error
	for {
		attemptCtx, attemptCancel := context.WithTimeout(ctx, 2*time.Second)
		stream, err = adminJS.CreateOrUpdateStream(attemptCtx, jetstream.StreamConfig{
			Name:     "RELAYQUILL_EVENTS_V1",
			Subjects: []string{"rq.events.*.accepted"},
			Storage:  jetstream.FileStorage,
			Discard:  jetstream.DiscardNew,
			Replicas: 3,
		})
		attemptCancel()
		if err == nil {
			break
		}
		lastCreateErr = err
		if ctx.Err() != nil {
			t.Fatalf("create R=3 stream failed: lastErr=%v ctxErr=%v\nnode0=%s\nnode1=%s\nnode2=%s", lastCreateErr, ctx.Err(), nodeLogs[0].String(), nodeLogs[1].String(), nodeLogs[2].String())
		}
		time.Sleep(150 * time.Millisecond)
	}
	if _, err := stream.CreateOrUpdateConsumer(ctx, jetstream.ConsumerConfig{
		Durable:   "RELAYQUILL_FANOUT_V1",
		AckPolicy: jetstream.AckExplicitPolicy,
		Replicas:  3,
	}); err != nil {
		t.Fatalf("create R=3 consumer: %v", err)
	}

	relayConn, err := connectTLSPrincipal(t, instances[1].ClientAddr().String(), clientCA.pool, "broker-2.internal.test", relayKey, "_INBOX.rq.relay", nil)
	if err != nil {
		t.Fatalf("relay connect to broker-2: %v", err)
	}
	defer relayConn.Close()
	relayJS, _ := jetstream.New(relayConn)
	if _, err := relayJS.Publish(ctx, "rq.events.aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa.accepted", []byte(`{"ok":true}`)); err != nil {
		t.Fatalf("clustered publish on broker-2: %v", err)
	}

	fanoutConn, err := connectTLSPrincipal(t, instances[2].ClientAddr().String(), clientCA.pool, "broker-3.internal.test", fanoutKey, "_INBOX.rq.fanout", nil)
	if err != nil {
		t.Fatalf("fanout connect to broker-3: %v", err)
	}
	defer fanoutConn.Close()
	fanoutJS, _ := jetstream.New(fanoutConn)
	c, err := fanoutJS.Consumer(ctx, "RELAYQUILL_EVENTS_V1", "RELAYQUILL_FANOUT_V1")
	if err != nil {
		t.Fatalf("fanout consumer lookup on broker-3: %v", err)
	}
	batch, err := c.Fetch(1, jetstream.FetchMaxWait(5*time.Second))
	if err != nil {
		t.Fatalf("fanout fetch on broker-3: %v", err)
	}
	count := 0
	for m := range batch.Messages() {
		count++
		if err := m.DoubleAck(ctx); err != nil {
			t.Fatalf("clustered DoubleAck: %v", err)
		}
	}
	if count != 1 || batch.Error() != nil {
		t.Fatalf("expected 1 message across cluster, got count=%d err=%v", count, batch.Error())
	}

	// Negative route check A: untrusted CA route cert must fail mTLS handshake.
	routeAddr := instances[0].ClusterAddr().String()
	untrustedRouteCert := rogueCA.issue(t, "broker-2.cluster.test", []string{"broker-2.cluster.test"}, []net.IP{net.ParseIP("127.0.0.1")})
	assertRouteTLSDenied(t, "untrusted_ca_route_cert", routeAddr, clusterCA.pool, untrustedRouteCert.tlsCert)

	// Negative route check B: cert signed by SAME cluster CA, but unauthorized SAN, must fail!
	unauthorizedPeerCert := clusterCA.issue(t, "rogue.cluster.test", []string{"rogue.cluster.test"}, []net.IP{net.ParseIP("127.0.0.1")})
	assertRouteTLSDenied(t, "ca_signed_unauthorized_peer_san", routeAddr, clusterCA.pool, unauthorizedPeerCert.tlsCert)

	// Negative route check C: rogue embedded NATS server with CA-signed unauthorized cert fails to join cluster.
	routesBeforeRogue := instances[0].Server().NumRoutes()
	rogueRouteURL, _ := url.Parse("nats://" + routeAddr)
	rogueSrv, err := server.NewServer(&server.Options{
		ServerName: "rogue-broker",
		Host:       "127.0.0.1",
		Port:       -1,
		NoSigs:     true,
		NoLog:      true,
		Cluster: server.ClusterOpts{
			Name: "rq-cluster-test",
			Host: "127.0.0.1",
			Port: -1,
			TLSConfig: &tls.Config{
				Certificates: []tls.Certificate{unauthorizedPeerCert.tlsCert},
				RootCAs:      clusterCA.pool,
				ClientCAs:    clusterCA.pool,
				ClientAuth:   tls.RequireAndVerifyClientCert,
				MinVersion:   tls.VersionTLS13,
			},
		},
		Routes: []*url.URL{rogueRouteURL},
	})
	if err != nil {
		t.Fatalf("new rogue server: %v", err)
	}
	go rogueSrv.Start()
	defer rogueSrv.Shutdown()
	time.Sleep(400 * time.Millisecond)
	if rogueSrv.NumRoutes() != 0 || instances[0].Server().NumRoutes() != routesBeforeRogue {
		t.Fatalf("expected rogue server rejected (rogueRoutes=%d, broker1Before=%d, broker1After=%d)",
			rogueSrv.NumRoutes(), routesBeforeRogue, instances[0].Server().NumRoutes())
	}
}

func assertRouteTLSDenied(t *testing.T, label, addr string, rootCA *x509.CertPool, clientCert tls.Certificate) {
	t.Helper()
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", addr, &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      rootCA,
		ServerName:   "broker-1.cluster.test",
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		return
	}
	defer conn.Close()
	// In TLS 1.3, server certificate rejection alert arrives on the subsequent Read.
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	if _, readErr := conn.Read(buf); readErr == nil {
		t.Fatalf("%s: expected TLS handshake/read failure, but server accepted route connection", label)
	}
}

func TestLogsDoNotLeakOptionsOrSecrets(t *testing.T) {
	fx := startSingleNodeFixture(t, "1.2", true)
	shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := fx.inst.Shutdown(shutCtx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	logs := fx.logBuffer.String()
	if !strings.Contains(logs, `"broker_ready"`) || !strings.Contains(logs, `"broker_stopped"`) {
		t.Fatalf("expected structured broker_ready and broker_stopped logs, got:\n%s", logs)
	}
	forbidden := []string{
		"-----BEGIN",
		fx.relay.seed,
		fx.fanout.seed,
		fx.admin.seed,
		"TLSConfig",
		"CustomRouterAuthentication",
		"PrivateKey",
	}
	for _, needle := range forbidden {
		if strings.Contains(logs, needle) {
			t.Fatalf("logs leaked forbidden substring %q:\n%s", needle, logs)
		}
	}
	_ = custody.CertFingerprintSHA256
}
