package statsdb

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bigbes/wireguard-outline-bridge/internal/config"
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

func TestPeerCRUD(t *testing.T) {
	s := testStore(t)

	// Empty list initially
	peers, err := s.ListPeers()
	if err != nil {
		t.Fatal(err)
	}
	if len(peers) != 0 {
		t.Fatalf("expected 0 peers, got %d", len(peers))
	}

	// GetPeer on missing ID
	_, found, err := s.GetPeer(999)
	if err != nil {
		t.Fatal(err)
	}
	if found {
		t.Fatal("expected not found")
	}

	// InsertPeer
	alice := config.PeerConfig{
		PrivateKey:   "alice-priv",
		PublicKey:    "alice-pub",
		PresharedKey: "alice-psk",
		AllowedIPs:   "10.0.0.2/32",
		Disabled:     false,
	}
	aliceID, err := s.InsertPeer("alice", alice)
	if err != nil {
		t.Fatal(err)
	}

	got, found, err := s.GetPeer(aliceID)
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("expected found")
	}
	if got.PublicKey != alice.PublicKey {
		t.Fatalf("got pub key %q, want %q", got.PublicKey, alice.PublicKey)
	}

	// UpdatePeer
	alice.Disabled = true
	alice.AllowedIPs = "10.0.0.3/32"
	if err := s.UpdatePeer(aliceID, alice); err != nil {
		t.Fatal(err)
	}
	got, _, _ = s.GetPeer(aliceID)
	if got.AllowedIPs != alice.AllowedIPs || got.Disabled != alice.Disabled {
		t.Fatalf("after update: got %+v, want updated fields", got)
	}

	// Add second peer and list
	bob := config.PeerConfig{
		PrivateKey: "bob-priv",
		PublicKey:  "bob-pub",
		AllowedIPs: "10.0.0.4/32",
	}
	bobID, err := s.InsertPeer("bob", bob)
	if err != nil {
		t.Fatal(err)
	}
	_ = bobID
	peers, err = s.ListPeers()
	if err != nil {
		t.Fatal(err)
	}
	if len(peers) != 2 {
		t.Fatalf("expected 2 peers, got %d", len(peers))
	}

	// DeletePeer
	deleted, found, err := s.DeletePeer(aliceID)
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("expected found on delete")
	}
	if deleted.PublicKey != alice.PublicKey {
		t.Fatalf("deleted config mismatch: got pub key %q, want %q", deleted.PublicKey, alice.PublicKey)
	}

	// Delete again returns not found
	_, found, err = s.DeletePeer(aliceID)
	if err != nil {
		t.Fatal(err)
	}
	if found {
		t.Fatal("expected not found on second delete")
	}

	peers, _ = s.ListPeers()
	if len(peers) != 1 {
		t.Fatalf("expected 1 peer after delete, got %d", len(peers))
	}
}

func TestSecretCRUD(t *testing.T) {
	s := testStore(t)

	// Empty list initially
	secrets, err := s.ListSecrets()
	if err != nil {
		t.Fatal(err)
	}
	if len(secrets) != 0 {
		t.Fatalf("expected 0 secrets, got %d", len(secrets))
	}

	// AddSecret
	id1, err := s.AddSecret("aabb", "test comment")
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.AddSecret("ccdd", "")
	if err != nil {
		t.Fatal(err)
	}

	secrets, err = s.ListSecrets()
	if err != nil {
		t.Fatal(err)
	}
	if len(secrets) != 2 {
		t.Fatalf("expected 2 secrets, got %d", len(secrets))
	}

	// AddSecret duplicate returns error
	if _, err := s.AddSecret("aabb", "dup"); err == nil {
		t.Fatal("expected error on duplicate add")
	}

	// DeleteSecret
	hex, ok, err := s.DeleteSecret(id1)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected true from delete")
	}
	if hex != "aabb" {
		t.Fatalf("expected deleted hex 'aabb', got %q", hex)
	}

	// Delete non-existent
	_, ok, err = s.DeleteSecret(id1)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("expected false from second delete")
	}

	secrets, _ = s.ListSecrets()
	if len(secrets) != 1 {
		t.Fatalf("expected 1 secret after delete, got %d", len(secrets))
	}
}

func TestAWGConfigRoundTrip(t *testing.T) {
	s := testStore(t)

	// Initially not set.
	_, ok := s.GetAWGConfig()
	if ok {
		t.Fatal("expected no AWG config initially")
	}

	cfg := &config.AmneziaWGConfig{
		Jc:   5,
		Jmin: 75,
		Jmax: 750,
		S1:   20,
		S2:   25,
		S3:   0,
		S4:   0,
		H1:   "1500000000",
		H2:   "1600000000",
		H3:   "1700000000",
		H4:   "1800000000",
		I1:   "<b 0xc700000001><rc 8><t><r 100>",
		I2:   "",
		I3:   "",
		I4:   "",
		I5:   "",
	}

	if err := s.SetAWGConfig(cfg); err != nil {
		t.Fatal(err)
	}

	got, ok := s.GetAWGConfig()
	if !ok {
		t.Fatal("expected AWG config after set")
	}

	if got.Jc != cfg.Jc || got.Jmin != cfg.Jmin || got.Jmax != cfg.Jmax {
		t.Errorf("junk params mismatch: got jc=%d jmin=%d jmax=%d", got.Jc, got.Jmin, got.Jmax)
	}
	if got.S1 != cfg.S1 || got.S2 != cfg.S2 {
		t.Errorf("s params mismatch: got s1=%d s2=%d", got.S1, got.S2)
	}
	if got.H1 != cfg.H1 || got.H2 != cfg.H2 || got.H3 != cfg.H3 || got.H4 != cfg.H4 {
		t.Errorf("h params mismatch")
	}
	if got.I1 != cfg.I1 {
		t.Errorf("I1=%q, want %q", got.I1, cfg.I1)
	}

	// Overwrite with new config.
	cfg2 := &config.AmneziaWGConfig{Jc: 99, I1: "updated"}
	if err := s.SetAWGConfig(cfg2); err != nil {
		t.Fatal(err)
	}
	got2, ok := s.GetAWGConfig()
	if !ok {
		t.Fatal("expected AWG config after overwrite")
	}
	if got2.Jc != 99 || got2.I1 != "updated" {
		t.Errorf("overwrite failed: got jc=%d i1=%q", got2.Jc, got2.I1)
	}
}

func TestImportPeers(t *testing.T) {
	s := testStore(t)

	batch := map[int]config.PeerConfig{
		0: {Name: "alice", PrivateKey: "a-priv", PublicKey: "a-pub", AllowedIPs: "10.0.0.2/32"},
		1: {Name: "bob", PrivateKey: "b-priv", PublicKey: "b-pub", AllowedIPs: "10.0.0.3/32"},
	}

	n, err := s.ImportPeers(batch)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("imported %d, want 2", n)
	}

	// Import again with overlap + new (alice's pub key already exists, so INSERT OR IGNORE skips)
	batch2 := map[int]config.PeerConfig{
		0: {Name: "alice", PrivateKey: "a-priv2", PublicKey: "a-pub2", AllowedIPs: "10.0.0.2/32"},
		1: {Name: "charlie", PrivateKey: "c-priv", PublicKey: "c-pub", AllowedIPs: "10.0.0.4/32"},
	}
	n, err = s.ImportPeers(batch2)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("imported %d, want 2 (both new rows, no pub key overlap)", n)
	}

	peers, _ := s.ListPeers()
	if len(peers) != 4 {
		t.Fatalf("expected 4 peers, got %d", len(peers))
	}
}

func TestImportSecrets(t *testing.T) {
	s := testStore(t)

	n, err := s.ImportSecrets([]string{"aa", "bb", "cc"})
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("imported %d, want 3", n)
	}

	// Import with overlap
	n, err = s.ImportSecrets([]string{"bb", "cc", "dd"})
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("imported %d, want 1 (bb,cc skipped)", n)
	}

	secrets, _ := s.ListSecrets()
	if len(secrets) != 4 {
		t.Fatalf("expected 4 secrets, got %d", len(secrets))
	}
}
