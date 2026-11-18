package topology

import (
	"fmt"
	"strings"
	"testing"

	"github.com/nats-io/nkeys"
)

func genPubKey(t *testing.T) string {
	t.Helper()
	kp, err := nkeys.CreateUser()
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	pub, err := kp.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	return pub
}

func validSingleNodeJSON(t *testing.T, relayPub, fanoutPub, adminPub string) string {
	t.Helper()
	return fmt.Sprintf(`{
		"schema_version": 1,
		"server_name": "broker-1",
		"host": "127.0.0.1",
		"client_port": 4222,
		"max_payload": 8192,
		"max_connections": 128,
		"monitoring": { "enabled": true, "host": "127.0.0.1", "port": 8222 },
		"tls": {
			"enabled": true,
			"handshake_first": true,
			"min_version": "1.2",
			"cert_ref": "env:TEST_TLS_CERT",
			"key_ref": "env:TEST_TLS_KEY"
		},
		"cluster": {
			"enabled": true,
			"name": "relayquill-cluster",
			"host": "127.0.0.1",
			"port": 6222,
			"routes": ["nats://broker-2.internal.example:6222"],
			"allowed_route_peers": ["broker-1.internal.example", "broker-2.internal.example"],
			"tls": {
				"min_version": "1.3",
				"ca_ref": "env:TEST_CLUSTER_CA",
				"cert_ref": "env:TEST_CLUSTER_CERT",
				"key_ref": "env:TEST_CLUSTER_KEY"
			}
		},
		"jetstream": {
			"enabled": true,
			"store_dir": "/tmp/js",
			"max_memory_store": 67108864,
			"max_file_store": 536870912,
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
	}`, relayPub, fanoutPub, adminPub)
}

func TestParseAndResolveValidTopology(t *testing.T) {
	rPub, fPub, aPub := genPubKey(t), genPubKey(t), genPubKey(t)
	raw := validSingleNodeJSON(t, rPub, fPub, aPub)

	resolved, err := ParseAndResolve([]byte(raw), Overrides{})
	if err != nil {
		t.Fatalf("ParseAndResolve failed: %v", err)
	}
	if !resolved.SyncAlways || !resolved.HandshakeFirst || !resolved.ClusterEnabled {
		t.Fatalf("expected SyncAlways, HandshakeFirst, ClusterEnabled: %+v", resolved)
	}
	if len(resolved.Relay.PublishAllow) != 1 || resolved.Relay.PublishAllow[0] != "rq.events.*.accepted" {
		t.Fatalf("unexpected relay publish ACL: %v", resolved.Relay.PublishAllow)
	}
	expectedFanout := map[string]bool{
		"$JS.API.CONSUMER.MSG.NEXT.RELAYQUILL_EVENTS_V1.RELAYQUILL_FANOUT_V1": true,
		"$JS.API.CONSUMER.INFO.RELAYQUILL_EVENTS_V1.RELAYQUILL_FANOUT_V1":     true,
		"$JS.API.STREAM.INFO.RELAYQUILL_EVENTS_V1":                          true,
		"$JS.ACK.RELAYQUILL_EVENTS_V1.RELAYQUILL_FANOUT_V1.>":               true,
		"$JS.ACK.*.*.RELAYQUILL_EVENTS_V1.RELAYQUILL_FANOUT_V1.>":           true,
	}
	if len(resolved.Fanout.PublishAllow) != len(expectedFanout) {
		t.Fatalf("unexpected fanout publish ACL count: %v", resolved.Fanout.PublishAllow)
	}
	for _, s := range resolved.Fanout.PublishAllow {
		if !expectedFanout[s] {
			t.Fatalf("unexpected fanout publish subject: %q", s)
		}
	}
}

func TestParseAndResolveRejectsUnknownFieldsAndWeakSecurity(t *testing.T) {
	rPub, fPub, aPub := genPubKey(t), genPubKey(t), genPubKey(t)
	base := validSingleNodeJSON(t, rPub, fPub, aPub)

	cases := []struct {
		name    string
		mutator func(string) string
	}{
		{
			name: "unknown_field",
			mutator: func(s string) string {
				return strings.Replace(s, `"schema_version": 1,`, `"schema_version": 1, "unknown_key": true,`, 1)
			},
		},
		{
			name: "tls_disabled",
			mutator: func(s string) string {
				return strings.Replace(s, "\"tls\": {\n\t\t\t\"enabled\": true,", "\"tls\": {\n\t\t\t\"enabled\": false,", 1)
			},
		},
		{
			name: "handshake_first_false",
			mutator: func(s string) string {
				return strings.Replace(s, `"handshake_first": true,`, `"handshake_first": false,`, 1)
			},
		},
		{
			name: "sync_interval_not_always",
			mutator: func(s string) string {
				return strings.Replace(s, `"sync_interval": "always",`, `"sync_interval": "2s",`, 1)
			},
		},
		{
			name: "duplicate_nkey",
			mutator: func(s string) string {
				return strings.Replace(s, fPub, rPub, 1)
			},
		},
		{
			name: "overbroad_fanout_acl",
			mutator: func(s string) string {
				return strings.Replace(s,
					`"fanout": { "public_nkey": "`+fPub+`", "inbox_prefix": "_INBOX.rq.fanout" }`,
					`"fanout": { "public_nkey": "`+fPub+`", "inbox_prefix": "_INBOX.rq.fanout", "publish_allow": ["$JS.API.>"] }`,
					1)
			},
		},
		{
			name: "relay_cross_inbox_subscribe",
			mutator: func(s string) string {
				return strings.Replace(s,
					`"relay": { "public_nkey": "`+rPub+`", "inbox_prefix": "_INBOX.rq.relay" }`,
					`"relay": { "public_nkey": "`+rPub+`", "inbox_prefix": "_INBOX.rq.relay", "subscribe_allow": ["_INBOX.rq.fanout.*"] }`,
					1)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseAndResolve([]byte(tc.mutator(base)), Overrides{}); err == nil {
				t.Fatalf("expected error for case %s, got nil", tc.name)
			}
		})
	}
}

func TestMultiNodeSelectionAndOverrides(t *testing.T) {
	rPub, fPub, aPub := genPubKey(t), genPubKey(t), genPubKey(t)
	raw := fmt.Sprintf(`{
		"schema_version": 1,
		"host": "0.0.0.0",
		"client_port": 4222,
		"max_payload": 8192,
		"max_connections": 256,
		"monitoring": { "enabled": true, "host": "127.0.0.1", "port": 8222 },
		"tls": { "enabled": true, "handshake_first": true, "min_version": "1.2", "ca_ref": "env:CA" },
		"cluster": {
			"enabled": true,
			"name": "rq-prod",
			"routes": ["nats://broker-1.internal:6222", "nats://broker-2.internal:6222"],
			"allowed_route_peers": ["broker-1.internal", "broker-2.internal"],
			"tls": { "min_version": "1.3", "ca_ref": "env:CLUSTER_CA" }
		},
		"nodes": [
			{
				"id": "broker-1",
				"server_name": "relayquill-broker-1",
				"store_dir": "/data/js-1",
				"tls_cert_ref": "env:B1_CERT",
				"tls_key_ref": "env:B1_KEY",
				"cluster_cert_ref": "env:B1_ROUTE_CERT",
				"cluster_key_ref": "env:B1_ROUTE_KEY"
			},
			{
				"id": "broker-2",
				"server_name": "relayquill-broker-2",
				"store_dir": "/data/js-2",
				"tls_cert_ref": "env:B2_CERT",
				"tls_key_ref": "env:B2_KEY",
				"cluster_cert_ref": "env:B2_ROUTE_CERT",
				"cluster_key_ref": "env:B2_ROUTE_KEY"
			}
		],
		"jetstream": {
			"enabled": true,
			"max_memory_store": 67108864,
			"max_file_store": 536870912,
			"sync_interval": "always",
			"subject_prefix": "rq_prod."
		},
		"principals": {
			"relay": { "public_nkey": %q },
			"fanout": { "public_nkey": %q },
			"broker_admin": { "public_nkey": %q }
		}
	}`, rPub, fPub, aPub)

	if _, err := ParseAndResolve([]byte(raw), Overrides{}); err == nil {
		t.Fatal("expected error when node-id omitted for multi-node topology")
	}

	resolved, err := ParseAndResolve([]byte(raw), Overrides{NodeID: "broker-2"})
	if err != nil {
		t.Fatalf("ParseAndResolve node broker-2 failed: %v", err)
	}
	if resolved.ServerName != "relayquill-broker-2" || resolved.StoreDir != "/data/js-2" {
		t.Fatalf("unexpected node selection result: %+v", resolved)
	}
	if resolved.Relay.PublishAllow[0] != "rq_prod.rq.events.*.accepted" {
		t.Fatalf("expected subject_prefix applied: %v", resolved.Relay.PublishAllow)
	}
}
