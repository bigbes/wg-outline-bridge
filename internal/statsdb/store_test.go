package statsdb

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.sqlite")
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	s, err := Open(path, logger)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestDaemonStartTime(t *testing.T) {
	s := testStore(t)
	now := time.Now().Truncate(time.Second)
	if err := s.SetDaemonStartTime(now); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetDaemonStartTime()
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(now) {
		t.Fatalf("got %v, want %v", got, now)
	}
}

func TestFlushWireGuardPeers(t *testing.T) {
	s := testStore(t)

	// First flush: initial insert
	peers := []WGPeerSnapshot{
		{PublicKey: "pk1", Name: "alice", LastHandshakeSec: 1000, RxBytes: 100, TxBytes: 200},
		{PublicKey: "pk2", Name: "bob", LastHandshakeSec: 0, RxBytes: 0, TxBytes: 0},
	}
	if err := s.FlushWireGuardPeers(peers); err != nil {
		t.Fatal(err)
	}

	recs, err := s.GetWGPeerStats()
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 {
		t.Fatalf("got %d records, want 2", len(recs))
	}
	if recs["pk1"].RxTotal != 100 || recs["pk1"].TxTotal != 200 {
		t.Fatalf("pk1 totals: rx=%d tx=%d", recs["pk1"].RxTotal, recs["pk1"].TxTotal)
	}
	if recs["pk1"].ConnectionsTotal != 0 {
		t.Fatalf("pk1 connections should be 0 on first flush, got %d", recs["pk1"].ConnectionsTotal)
	}

	// Second flush: delta accumulation
	peers[0].RxBytes = 150
	peers[0].TxBytes = 250
	peers[0].LastHandshakeSec = 2000 // handshake advanced
	if err := s.FlushWireGuardPeers(peers); err != nil {
		t.Fatal(err)
	}

	recs, _ = s.GetWGPeerStats()
	if recs["pk1"].RxTotal != 150 {
		t.Fatalf("pk1 rx_total: got %d, want 150", recs["pk1"].RxTotal)
	}
	if recs["pk1"].TxTotal != 250 {
		t.Fatalf("pk1 tx_total: got %d, want 250", recs["pk1"].TxTotal)
	}
	if recs["pk1"].ConnectionsTotal != 1 {
		t.Fatalf("pk1 connections: got %d, want 1", recs["pk1"].ConnectionsTotal)
	}

	// Third flush: simulate counter reset (daemon restart, lower values)
	peers[0].RxBytes = 30
	peers[0].TxBytes = 40
	peers[0].LastHandshakeSec = 2000 // same handshake
	if err := s.FlushWireGuardPeers(peers); err != nil {
		t.Fatal(err)
	}

	recs, _ = s.GetWGPeerStats()
	// After reset: rx_total = 150 (prev) + 30 (new baseline) = 180
	if recs["pk1"].RxTotal != 180 {
		t.Fatalf("pk1 rx_total after reset: got %d, want 180", recs["pk1"].RxTotal)
	}
	if recs["pk1"].TxTotal != 290 {
		t.Fatalf("pk1 tx_total after reset: got %d, want 290", recs["pk1"].TxTotal)
	}
	// No handshake advancement, connections unchanged
	if recs["pk1"].ConnectionsTotal != 1 {
		t.Fatalf("pk1 connections after reset: got %d, want 1", recs["pk1"].ConnectionsTotal)
	}
}

func TestFlushMTProxySecrets(t *testing.T) {
	s := testStore(t)

	secrets := []MTSecretSnapshot{
		{SecretHex: "aabbccdd11223344", LastConnectionUnix: 1000, Connections: 5, BytesC2B: 1000, BytesB2C: 2000},
	}
	if err := s.FlushMTProxySecrets(secrets); err != nil {
		t.Fatal(err)
	}

	recs, err := s.GetMTSecretStats()
	if err != nil {
		t.Fatal(err)
	}
	if recs["aabbccdd11223344"].ConnectionsTotal != 5 {
		t.Fatalf("connections: got %d, want 5", recs["aabbccdd11223344"].ConnectionsTotal)
	}

	// Second flush: delta accumulation
	secrets[0].Connections = 8
	secrets[0].BytesC2B = 1500
	secrets[0].BytesB2C = 2500
	secrets[0].LastConnectionUnix = 2000
	if err := s.FlushMTProxySecrets(secrets); err != nil {
		t.Fatal(err)
	}

	recs, _ = s.GetMTSecretStats()
	if recs["aabbccdd11223344"].ConnectionsTotal != 8 {
		t.Fatalf("connections: got %d, want 8", recs["aabbccdd11223344"].ConnectionsTotal)
	}
	if recs["aabbccdd11223344"].BytesC2BTotal != 1500 {
		t.Fatalf("bytes_c2b: got %d, want 1500", recs["aabbccdd11223344"].BytesC2BTotal)
	}
	if recs["aabbccdd11223344"].LastConnectionUnix != 2000 {
		t.Fatalf("last_connection: got %d, want 2000", recs["aabbccdd11223344"].LastConnectionUnix)
	}

	// Third flush: simulate counter reset
	secrets[0].Connections = 2
	secrets[0].BytesC2B = 100
	secrets[0].BytesB2C = 200
	secrets[0].LastConnectionUnix = 3000
	if err := s.FlushMTProxySecrets(secrets); err != nil {
		t.Fatal(err)
	}

	recs, _ = s.GetMTSecretStats()
	// 8 + 2 (reset treats full value as delta) = 10
	if recs["aabbccdd11223344"].ConnectionsTotal != 10 {
		t.Fatalf("connections after reset: got %d, want 10", recs["aabbccdd11223344"].ConnectionsTotal)
	}
}
