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

func TestFlushMTProxyPeers(t *testing.T) {
	s := testStore(t)

	peers := []MTPeerSnapshot{
		{PeerKey: "1.2.3.4", LastConnectionUnix: 1000, Connections: 5, BytesC2B: 1000, BytesB2C: 2000},
	}
	if err := s.FlushMTProxyPeers(peers); err != nil {
		t.Fatal(err)
	}

	recs, err := s.GetMTPeerStats()
	if err != nil {
		t.Fatal(err)
	}
	if recs["1.2.3.4"].ConnectionsTotal != 5 {
		t.Fatalf("connections: got %d, want 5", recs["1.2.3.4"].ConnectionsTotal)
	}

	// Second flush: delta accumulation
	peers[0].Connections = 8
	peers[0].BytesC2B = 1500
	peers[0].BytesB2C = 2500
	peers[0].LastConnectionUnix = 2000
	if err := s.FlushMTProxyPeers(peers); err != nil {
		t.Fatal(err)
	}

	recs, _ = s.GetMTPeerStats()
	if recs["1.2.3.4"].ConnectionsTotal != 8 {
		t.Fatalf("connections: got %d, want 8", recs["1.2.3.4"].ConnectionsTotal)
	}
	if recs["1.2.3.4"].BytesC2BTotal != 1500 {
		t.Fatalf("bytes_c2b: got %d, want 1500", recs["1.2.3.4"].BytesC2BTotal)
	}
	if recs["1.2.3.4"].LastConnectionUnix != 2000 {
		t.Fatalf("last_connection: got %d, want 2000", recs["1.2.3.4"].LastConnectionUnix)
	}

	// Third flush: simulate counter reset
	peers[0].Connections = 2
	peers[0].BytesC2B = 100
	peers[0].BytesB2C = 200
	peers[0].LastConnectionUnix = 3000
	if err := s.FlushMTProxyPeers(peers); err != nil {
		t.Fatal(err)
	}

	recs, _ = s.GetMTPeerStats()
	// 8 + 2 (reset treats full value as delta) = 10
	if recs["1.2.3.4"].ConnectionsTotal != 10 {
		t.Fatalf("connections after reset: got %d, want 10", recs["1.2.3.4"].ConnectionsTotal)
	}
}
