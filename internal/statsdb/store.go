package statsdb

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/bigbes/wireguard-outline-bridge/internal/config"
)

// Store is a SQLite-backed persistent stats store.
type Store struct {
	db     *sql.DB
	path   string
	logger *slog.Logger
}

// Open opens (or creates) the SQLite database at path and initialises the schema.
func Open(path string, logger *slog.Logger) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("statsdb: open %q: %w", path, err)
	}

	for _, pragma := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA synchronous=NORMAL",
		"PRAGMA busy_timeout=5000",
	} {
		if _, err := db.Exec(pragma); err != nil {
			db.Close()
			return nil, fmt.Errorf("statsdb: %s: %w", pragma, err)
		}
	}

	s := &Store{db: db, path: path, logger: logger}
	if err := s.initSchema(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Close closes the underlying database.
func (s *Store) Close() error {
	return s.db.Close()
}

// Backup writes a consistent snapshot of the database to w.
func (s *Store) Backup(w io.Writer) error {
	if _, err := s.db.Exec("PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		return fmt.Errorf("statsdb: checkpoint: %w", err)
	}
	f, err := os.Open(s.path)
	if err != nil {
		return fmt.Errorf("statsdb: open for backup: %w", err)
	}
	defer f.Close()
	if _, err := io.Copy(w, f); err != nil {
		return fmt.Errorf("statsdb: backup copy: %w", err)
	}
	return nil
}

// Restore replaces the current database with the data from r.
// The new file is validated before swapping. A .bak copy of the
// previous database is kept alongside the original path.
func (s *Store) Restore(r io.Reader) error {
	tmpPath := s.path + ".restore"
	f, err := os.Create(tmpPath)
	if err != nil {
		return fmt.Errorf("statsdb: create restore file: %w", err)
	}
	if _, err := io.Copy(f, r); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("statsdb: write restore file: %w", err)
	}
	f.Close()

	// Validate the uploaded file is a usable SQLite database.
	testDB, err := sql.Open("sqlite", tmpPath)
	if err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("statsdb: invalid database: %w", err)
	}
	var count int
	if err := testDB.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table'").Scan(&count); err != nil {
		testDB.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("statsdb: invalid database: %w", err)
	}
	testDB.Close()

	// Close current database and swap files.
	s.db.Close()

	bakPath := s.path + ".bak"
	os.Rename(s.path, bakPath)
	os.Remove(s.path + "-wal")
	os.Remove(s.path + "-shm")

	if err := os.Rename(tmpPath, s.path); err != nil {
		os.Rename(bakPath, s.path)
		return fmt.Errorf("statsdb: rename restore file: %w", err)
	}

	newDB, err := sql.Open("sqlite", s.path)
	if err != nil {
		os.Rename(bakPath, s.path)
		return fmt.Errorf("statsdb: reopen after restore: %w", err)
	}
	for _, pragma := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA synchronous=NORMAL",
		"PRAGMA busy_timeout=5000",
	} {
		if _, err := newDB.Exec(pragma); err != nil {
			newDB.Close()
			os.Rename(bakPath, s.path)
			return fmt.Errorf("statsdb: pragma after restore: %w", err)
		}
	}

	s.db = newDB
	return nil
}

func (s *Store) initSchema() error {
	const ddl = `
CREATE TABLE IF NOT EXISTS daemon (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  start_time_unix INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS wg_peer_stats (
  public_key TEXT PRIMARY KEY,
  name TEXT NOT NULL DEFAULT '',
  last_handshake_unix INTEGER NOT NULL DEFAULT 0,
  rx_total INTEGER NOT NULL DEFAULT 0,
  tx_total INTEGER NOT NULL DEFAULT 0,
  connections_total INTEGER NOT NULL DEFAULT 0,
  rx_last_seen INTEGER NOT NULL DEFAULT 0,
  tx_last_seen INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS mtproxy_secret_stats (
  secret_hex TEXT PRIMARY KEY,
  last_connection_unix INTEGER NOT NULL DEFAULT 0,
  connections_total INTEGER NOT NULL DEFAULT 0,
  bytes_c2b_total INTEGER NOT NULL DEFAULT 0,
  bytes_b2c_total INTEGER NOT NULL DEFAULT 0,
  backend_dial_errors_total INTEGER NOT NULL DEFAULT 0,
  connections_last_seen INTEGER NOT NULL DEFAULT 0,
  bytes_c2b_last_seen INTEGER NOT NULL DEFAULT 0,
  bytes_b2c_last_seen INTEGER NOT NULL DEFAULT 0,
  backend_dial_errors_last_seen INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS wg_peers (
  name TEXT PRIMARY KEY,
  private_key TEXT NOT NULL,
  public_key TEXT NOT NULL UNIQUE,
  preshared_key TEXT NOT NULL DEFAULT '',
  allowed_ips TEXT NOT NULL,
  disabled INTEGER NOT NULL DEFAULT 0,
  created_unix INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_unix INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TABLE IF NOT EXISTS mtproxy_secrets (
  secret_hex TEXT PRIMARY KEY,
  disabled INTEGER NOT NULL DEFAULT 0,
  comment TEXT NOT NULL DEFAULT '',
  created_unix INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TABLE IF NOT EXISTS proxy_servers (
  name TEXT PRIMARY KEY,
  type TEXT NOT NULL,
  listen TEXT NOT NULL,
  username TEXT NOT NULL DEFAULT '',
  password TEXT NOT NULL DEFAULT '',
  tls_cert_file TEXT NOT NULL DEFAULT '',
  tls_key_file TEXT NOT NULL DEFAULT '',
  tls_domain TEXT NOT NULL DEFAULT '',
  tls_acme_email TEXT NOT NULL DEFAULT '',
  created_unix INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TABLE IF NOT EXISTS upstreams (
  name TEXT PRIMARY KEY,
  type TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  is_default INTEGER NOT NULL DEFAULT 0,
  groups TEXT NOT NULL DEFAULT '',
  transport TEXT NOT NULL DEFAULT '',
  health_check_enabled INTEGER NOT NULL DEFAULT 0,
  health_check_interval INTEGER NOT NULL DEFAULT 30,
  health_check_target TEXT NOT NULL DEFAULT '1.1.1.1:80',
  created_unix INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_unix INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TABLE IF NOT EXISTS allowed_users (
  user_id INTEGER PRIMARY KEY,
  username TEXT NOT NULL DEFAULT '',
  first_name TEXT NOT NULL DEFAULT '',
  last_name TEXT NOT NULL DEFAULT '',
  photo_url TEXT NOT NULL DEFAULT '',
  role TEXT NOT NULL DEFAULT 'admin',
  created_unix INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TABLE IF NOT EXISTS upstream_groups (
  name TEXT PRIMARY KEY,
  created_unix INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TABLE IF NOT EXISTS dns_records (
  name TEXT PRIMARY KEY,
  a_json TEXT NOT NULL DEFAULT '[]',
  aaaa_json TEXT NOT NULL DEFAULT '[]',
  ttl INTEGER NOT NULL DEFAULT 3600,
  created_unix INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_unix INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TABLE IF NOT EXISTS dns_rules (
  name TEXT PRIMARY KEY,
  action TEXT NOT NULL,
  upstream TEXT NOT NULL DEFAULT '',
  domains_json TEXT NOT NULL DEFAULT '[]',
  lists_json TEXT NOT NULL DEFAULT '[]',
  priority INTEGER NOT NULL DEFAULT 0,
  created_unix INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_unix INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TABLE IF NOT EXISTS routing_cidrs (
  cidr TEXT PRIMARY KEY,
  mode TEXT NOT NULL DEFAULT 'disallow',
  priority INTEGER NOT NULL DEFAULT 0,
  created_unix INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TABLE IF NOT EXISTS routing_ip_rules (
  name TEXT PRIMARY KEY,
  action TEXT NOT NULL,
  upstream_group TEXT NOT NULL DEFAULT '',
  cidrs_json TEXT NOT NULL DEFAULT '[]',
  asns_json TEXT NOT NULL DEFAULT '[]',
  lists_json TEXT NOT NULL DEFAULT '[]',
  priority INTEGER NOT NULL DEFAULT 0,
  created_unix INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_unix INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TABLE IF NOT EXISTS routing_sni_rules (
  name TEXT PRIMARY KEY,
  action TEXT NOT NULL,
  upstream_group TEXT NOT NULL DEFAULT '',
  domains_json TEXT NOT NULL DEFAULT '[]',
  priority INTEGER NOT NULL DEFAULT 0,
  created_unix INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_unix INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TABLE IF NOT EXISTS db_seeds (
  table_name TEXT PRIMARY KEY,
  seeded_unix INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TABLE IF NOT EXISTS invite_links (
  token TEXT PRIMARY KEY,
  role TEXT NOT NULL DEFAULT 'guest',
  created_by INTEGER NOT NULL,
  created_unix INTEGER NOT NULL DEFAULT (unixepoch())
);`
	if _, err := s.db.Exec(ddl); err != nil {
		return fmt.Errorf("statsdb: init schema: %w", err)
	}
	if err := s.migrateSchema(); err != nil {
		return fmt.Errorf("statsdb: migrate schema: %w", err)
	}
	return nil
}

// migrateSchema applies incremental ALTER TABLE migrations for columns added
// after the initial schema.  Each migration is idempotent (checks column
// existence before altering).
func (s *Store) migrateSchema() error {
	migrations := []struct {
		table  string
		column string
		ddl    string
	}{
		{"allowed_users", "role", `ALTER TABLE allowed_users ADD COLUMN role TEXT NOT NULL DEFAULT 'admin'`},
		{"wg_peers", "owner_user_id", `ALTER TABLE wg_peers ADD COLUMN owner_user_id INTEGER`},
		{"mtproxy_secrets", "owner_user_id", `ALTER TABLE mtproxy_secrets ADD COLUMN owner_user_id INTEGER`},
		{"daemon", "dns_enabled", `ALTER TABLE daemon ADD COLUMN dns_enabled INTEGER`},
		{"wg_peers", "upstream_group", `ALTER TABLE wg_peers ADD COLUMN upstream_group TEXT NOT NULL DEFAULT ''`},
		{"proxy_servers", "upstream_group", `ALTER TABLE proxy_servers ADD COLUMN upstream_group TEXT NOT NULL DEFAULT ''`},
		{"mtproxy_secrets", "upstream_group", `ALTER TABLE mtproxy_secrets ADD COLUMN upstream_group TEXT NOT NULL DEFAULT ''`},
		{"allowed_users", "custom_name", `ALTER TABLE allowed_users ADD COLUMN custom_name TEXT NOT NULL DEFAULT ''`},
		{"allowed_users", "disabled", `ALTER TABLE allowed_users ADD COLUMN disabled INTEGER NOT NULL DEFAULT 0`},
		{"allowed_users", "max_peers", `ALTER TABLE allowed_users ADD COLUMN max_peers INTEGER`},
		{"allowed_users", "max_secrets", `ALTER TABLE allowed_users ADD COLUMN max_secrets INTEGER`},
		{"routing_cidrs", "mode", `ALTER TABLE routing_cidrs ADD COLUMN mode TEXT NOT NULL DEFAULT 'disallow'`},
		{"wg_peers", "exclude_private", `ALTER TABLE wg_peers ADD COLUMN exclude_private INTEGER NOT NULL DEFAULT 1`},
		{"wg_peers", "exclude_server", `ALTER TABLE wg_peers ADD COLUMN exclude_server INTEGER NOT NULL DEFAULT 0`},
		{"dns_rules", "peers_json", `ALTER TABLE dns_rules ADD COLUMN peers_json TEXT NOT NULL DEFAULT '[]'`},
	}
	for _, m := range migrations {
		var count int
		err := s.db.QueryRow(
			`SELECT COUNT(*) FROM pragma_table_info(?) WHERE name = ?`,
			m.table, m.column,
		).Scan(&count)
		if err != nil {
			return fmt.Errorf("check column %s.%s: %w", m.table, m.column, err)
		}
		if count == 0 {
			if _, err := s.db.Exec(m.ddl); err != nil {
				return fmt.Errorf("add column %s.%s: %w", m.table, m.column, err)
			}
		}
	}

	return nil
}

// Reset drops all tables and re-initialises the schema, effectively
// creating a fresh empty database without replacing the file.
func (s *Store) Reset() error {
	rows, err := s.db.Query(`SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'`)
	if err != nil {
		return fmt.Errorf("statsdb: list tables: %w", err)
	}
	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			return fmt.Errorf("statsdb: scan table name: %w", err)
		}
		tables = append(tables, name)
	}
	rows.Close()

	for _, t := range tables {
		if _, err := s.db.Exec("DROP TABLE IF EXISTS " + t); err != nil {
			return fmt.Errorf("statsdb: drop table %s: %w", t, err)
		}
	}
	return s.initSchema()
}

// SetDaemonStartTime records the daemon start time (upsert, id=1).
func (s *Store) SetDaemonStartTime(t time.Time) error {
	_, err := s.db.Exec(
		`INSERT INTO daemon (id, start_time_unix) VALUES (1, ?)
		 ON CONFLICT(id) DO UPDATE SET start_time_unix = excluded.start_time_unix`,
		t.Unix(),
	)
	if err != nil {
		return fmt.Errorf("statsdb: set daemon start time: %w", err)
	}
	return nil
}

// GetDaemonStartTime returns the stored daemon start time.
func (s *Store) GetDaemonStartTime() (time.Time, error) {
	var unix int64
	err := s.db.QueryRow(`SELECT start_time_unix FROM daemon WHERE id = 1`).Scan(&unix)
	if err != nil {
		return time.Time{}, fmt.Errorf("statsdb: get daemon start time: %w", err)
	}
	return time.Unix(unix, 0), nil
}

// SetDNSEnabled persists the DNS enabled state (upsert into daemon row).
func (s *Store) SetDNSEnabled(enabled bool) error {
	v := 0
	if enabled {
		v = 1
	}
	_, err := s.db.Exec(
		`INSERT INTO daemon (id, start_time_unix, dns_enabled) VALUES (1, 0, ?)
		 ON CONFLICT(id) DO UPDATE SET dns_enabled = excluded.dns_enabled`,
		v,
	)
	if err != nil {
		return fmt.Errorf("statsdb: set dns_enabled: %w", err)
	}
	return nil
}

// GetDNSEnabled returns the stored DNS enabled state.
// Returns (value, true) if stored, or (false, false) if not set.
func (s *Store) GetDNSEnabled() (bool, bool) {
	var v sql.NullInt64
	err := s.db.QueryRow(`SELECT dns_enabled FROM daemon WHERE id = 1`).Scan(&v)
	if err != nil || !v.Valid {
		return false, false
	}
	return v.Int64 != 0, true
}

// IsSeeded returns true if the given table has been marked as seeded from config.
func (s *Store) IsSeeded(tableName string) bool {
	var count int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM db_seeds WHERE table_name = ?`, tableName).Scan(&count)
	return err == nil && count > 0
}

// MarkSeeded records that the given table has been seeded from config.
func (s *Store) MarkSeeded(tableName string) {
	s.db.Exec(`INSERT OR IGNORE INTO db_seeds (table_name) VALUES (?)`, tableName)
}

// FlushWireGuardPeers performs delta-accumulation for a batch of WireGuard peer snapshots.
func (s *Store) FlushWireGuardPeers(peers []WGPeerSnapshot) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("statsdb: begin tx: %w", err)
	}
	defer tx.Rollback()

	selStmt, err := tx.Prepare(
		`SELECT rx_last_seen, tx_last_seen, last_handshake_unix,
		        connections_total, rx_total, tx_total
		 FROM wg_peer_stats WHERE public_key = ?`)
	if err != nil {
		return fmt.Errorf("statsdb: prepare select: %w", err)
	}
	defer selStmt.Close()

	updStmt, err := tx.Prepare(
		`UPDATE wg_peer_stats
		 SET name = ?, last_handshake_unix = ?,
		     rx_total = ?, tx_total = ?, connections_total = ?,
		     rx_last_seen = ?, tx_last_seen = ?
		 WHERE public_key = ?`)
	if err != nil {
		return fmt.Errorf("statsdb: prepare update: %w", err)
	}
	defer updStmt.Close()

	insStmt, err := tx.Prepare(
		`INSERT INTO wg_peer_stats
		 (public_key, name, last_handshake_unix, rx_total, tx_total,
		  connections_total, rx_last_seen, tx_last_seen)
		 VALUES (?, ?, ?, ?, ?, 0, ?, ?)`)
	if err != nil {
		return fmt.Errorf("statsdb: prepare insert: %w", err)
	}
	defer insStmt.Close()

	for _, p := range peers {
		var rxLastSeen, txLastSeen, dbHandshake, connTotal, rxTotal, txTotal int64
		err := selStmt.QueryRow(p.PublicKey).Scan(
			&rxLastSeen, &txLastSeen, &dbHandshake,
			&connTotal, &rxTotal, &txTotal,
		)
		if err == sql.ErrNoRows {
			if _, err := insStmt.Exec(
				p.PublicKey, p.Name, p.LastHandshakeSec,
				p.RxBytes, p.TxBytes,
				p.RxBytes, p.TxBytes,
			); err != nil {
				return fmt.Errorf("statsdb: insert wg peer %s: %w", p.PublicKey, err)
			}
			continue
		}
		if err != nil {
			return fmt.Errorf("statsdb: select wg peer %s: %w", p.PublicKey, err)
		}

		rxDelta := p.RxBytes - rxLastSeen
		if rxDelta < 0 {
			rxDelta = p.RxBytes
		}
		txDelta := p.TxBytes - txLastSeen
		if txDelta < 0 {
			txDelta = p.TxBytes
		}

		var connDelta int64
		if p.LastHandshakeSec > dbHandshake && p.LastHandshakeSec != 0 {
			connDelta = 1
		}

		if _, err := updStmt.Exec(
			p.Name, p.LastHandshakeSec,
			rxTotal+rxDelta, txTotal+txDelta, connTotal+connDelta,
			p.RxBytes, p.TxBytes,
			p.PublicKey,
		); err != nil {
			return fmt.Errorf("statsdb: update wg peer %s: %w", p.PublicKey, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("statsdb: commit wg flush: %w", err)
	}
	return nil
}

// FlushMTProxySecrets performs delta-accumulation for a batch of MTProxy secret snapshots.
func (s *Store) FlushMTProxySecrets(secrets []MTSecretSnapshot) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("statsdb: begin tx: %w", err)
	}
	defer tx.Rollback()

	selStmt, err := tx.Prepare(
		`SELECT connections_last_seen, bytes_c2b_last_seen, bytes_b2c_last_seen,
		        backend_dial_errors_last_seen,
		        last_connection_unix, connections_total, bytes_c2b_total,
		        bytes_b2c_total, backend_dial_errors_total
		 FROM mtproxy_secret_stats WHERE secret_hex = ?`)
	if err != nil {
		return fmt.Errorf("statsdb: prepare select: %w", err)
	}
	defer selStmt.Close()

	updStmt, err := tx.Prepare(
		`UPDATE mtproxy_secret_stats
		 SET last_connection_unix = ?,
		     connections_total = ?, bytes_c2b_total = ?, bytes_b2c_total = ?,
		     backend_dial_errors_total = ?,
		     connections_last_seen = ?, bytes_c2b_last_seen = ?, bytes_b2c_last_seen = ?,
		     backend_dial_errors_last_seen = ?
		 WHERE secret_hex = ?`)
	if err != nil {
		return fmt.Errorf("statsdb: prepare update: %w", err)
	}
	defer updStmt.Close()

	insStmt, err := tx.Prepare(
		`INSERT INTO mtproxy_secret_stats
		 (secret_hex, last_connection_unix,
		  connections_total, bytes_c2b_total, bytes_b2c_total,
		  backend_dial_errors_total,
		  connections_last_seen, bytes_c2b_last_seen, bytes_b2c_last_seen,
		  backend_dial_errors_last_seen)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("statsdb: prepare insert: %w", err)
	}
	defer insStmt.Close()

	for _, p := range secrets {
		var connLS, c2bLS, b2cLS, bdErrLS int64
		var dbLastConn, connTotal, c2bTotal, b2cTotal, bdErrTotal int64
		err := selStmt.QueryRow(p.SecretHex).Scan(
			&connLS, &c2bLS, &b2cLS, &bdErrLS,
			&dbLastConn, &connTotal, &c2bTotal, &b2cTotal, &bdErrTotal,
		)
		if err == sql.ErrNoRows {
			if _, err := insStmt.Exec(
				p.SecretHex, p.LastConnectionUnix,
				p.Connections, p.BytesC2B, p.BytesB2C,
				p.BackendDialErrors,
				p.Connections, p.BytesC2B, p.BytesB2C,
				p.BackendDialErrors,
			); err != nil {
				return fmt.Errorf("statsdb: insert mt secret %s: %w", p.SecretHex, err)
			}
			continue
		}
		if err != nil {
			return fmt.Errorf("statsdb: select mt secret %s: %w", p.SecretHex, err)
		}

		delta := func(curr, lastSeen int64) int64 {
			d := curr - lastSeen
			if d < 0 {
				return curr
			}
			return d
		}

		connDelta := delta(p.Connections, connLS)
		c2bDelta := delta(p.BytesC2B, c2bLS)
		b2cDelta := delta(p.BytesB2C, b2cLS)
		bdErrDelta := delta(p.BackendDialErrors, bdErrLS)

		lastConn := max(p.LastConnectionUnix, dbLastConn)

		if _, err := updStmt.Exec(
			lastConn,
			connTotal+connDelta, c2bTotal+c2bDelta, b2cTotal+b2cDelta,
			bdErrTotal+bdErrDelta,
			p.Connections, p.BytesC2B, p.BytesB2C,
			p.BackendDialErrors,
			p.SecretHex,
		); err != nil {
			return fmt.Errorf("statsdb: update mt secret %s: %w", p.SecretHex, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("statsdb: commit mt flush: %w", err)
	}
	return nil
}

// GetWGPeerStats returns all persisted WireGuard peer records keyed by public key.
func (s *Store) GetWGPeerStats() (map[string]WGPeerRecord, error) {
	rows, err := s.db.Query(
		`SELECT public_key, name, last_handshake_unix, rx_total, tx_total, connections_total
		 FROM wg_peer_stats`)
	if err != nil {
		return nil, fmt.Errorf("statsdb: query wg peers: %w", err)
	}
	defer rows.Close()

	out := make(map[string]WGPeerRecord)
	for rows.Next() {
		var pk string
		var r WGPeerRecord
		if err := rows.Scan(&pk, &r.Name, &r.LastHandshakeUnix, &r.RxTotal, &r.TxTotal, &r.ConnectionsTotal); err != nil {
			return nil, fmt.Errorf("statsdb: scan wg peer: %w", err)
		}
		out[pk] = r
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statsdb: iterate wg peers: %w", err)
	}
	return out, nil
}

// GetMTSecretStats returns all persisted MTProxy secret records keyed by secret hex.
func (s *Store) GetMTSecretStats() (map[string]MTSecretRecord, error) {
	rows, err := s.db.Query(
		`SELECT secret_hex, last_connection_unix, connections_total,
		        bytes_c2b_total, bytes_b2c_total,
		        backend_dial_errors_total
		 FROM mtproxy_secret_stats`)
	if err != nil {
		return nil, fmt.Errorf("statsdb: query mt secrets: %w", err)
	}
	defer rows.Close()

	out := make(map[string]MTSecretRecord)
	for rows.Next() {
		var key string
		var r MTSecretRecord
		if err := rows.Scan(&key, &r.LastConnectionUnix, &r.ConnectionsTotal,
			&r.BytesC2BTotal, &r.BytesB2CTotal,
			&r.BackendDialErrorsTotal); err != nil {
			return nil, fmt.Errorf("statsdb: scan mt secret: %w", err)
		}
		out[key] = r
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statsdb: iterate mt secrets: %w", err)
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Peer CRUD
// ---------------------------------------------------------------------------

// ListPeers returns all peers from the database keyed by name.
func (s *Store) ListPeers() (map[string]config.PeerConfig, error) {
	rows, err := s.db.Query(
		`SELECT name, private_key, public_key, preshared_key, allowed_ips, disabled, upstream_group, exclude_private, exclude_server
		 FROM wg_peers`)
	if err != nil {
		return nil, fmt.Errorf("statsdb: list peers: %w", err)
	}
	defer rows.Close()

	out := make(map[string]config.PeerConfig)
	for rows.Next() {
		var name string
		var p config.PeerConfig
		var disabled, excludePrivate, excludeServer int
		if err := rows.Scan(&name, &p.PrivateKey, &p.PublicKey, &p.PresharedKey, &p.AllowedIPs, &disabled, &p.UpstreamGroup, &excludePrivate, &excludeServer); err != nil {
			return nil, fmt.Errorf("statsdb: scan peer: %w", err)
		}
		p.Disabled = disabled != 0
		p.ExcludePrivate = excludePrivate != 0
		p.ExcludeServer = excludeServer != 0
		out[name] = p
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statsdb: iterate peers: %w", err)
	}
	return out, nil
}

// GetPeer returns a single peer by name.
func (s *Store) GetPeer(name string) (config.PeerConfig, bool, error) {
	var p config.PeerConfig
	var disabled int
	err := s.db.QueryRow(
		`SELECT private_key, public_key, preshared_key, allowed_ips, disabled
		 FROM wg_peers WHERE name = ?`, name,
	).Scan(&p.PrivateKey, &p.PublicKey, &p.PresharedKey, &p.AllowedIPs, &disabled)
	if err == sql.ErrNoRows {
		return config.PeerConfig{}, false, nil
	}
	if err != nil {
		return config.PeerConfig{}, false, fmt.Errorf("statsdb: get peer %q: %w", name, err)
	}
	p.Disabled = disabled != 0
	return p, true, nil
}

// UpsertPeer inserts or updates a peer.
func (s *Store) UpsertPeer(name string, peer config.PeerConfig) error {
	disabled := 0
	if peer.Disabled {
		disabled = 1
	}
	excludePrivate := 0
	if peer.ExcludePrivate {
		excludePrivate = 1
	}
	excludeServer := 0
	if peer.ExcludeServer {
		excludeServer = 1
	}
	_, err := s.db.Exec(
		`INSERT INTO wg_peers (name, private_key, public_key, preshared_key, allowed_ips, disabled, upstream_group, exclude_private, exclude_server)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(name) DO UPDATE SET
		   private_key = excluded.private_key,
		   public_key = excluded.public_key,
		   preshared_key = excluded.preshared_key,
		   allowed_ips = excluded.allowed_ips,
		   disabled = excluded.disabled,
		   upstream_group = excluded.upstream_group,
		   exclude_private = excluded.exclude_private,
		   exclude_server = excluded.exclude_server,
		   updated_unix = unixepoch()`,
		name, peer.PrivateKey, peer.PublicKey, peer.PresharedKey, peer.AllowedIPs, disabled, peer.UpstreamGroup, excludePrivate, excludeServer,
	)
	if err != nil {
		return fmt.Errorf("statsdb: upsert peer %q: %w", name, err)
	}
	return nil
}

// DeletePeer deletes a peer by name, returning the deleted config.
func (s *Store) DeletePeer(name string) (config.PeerConfig, bool, error) {
	p, found, err := s.GetPeer(name)
	if err != nil {
		return config.PeerConfig{}, false, err
	}
	if !found {
		return config.PeerConfig{}, false, nil
	}
	if _, err := s.db.Exec(`DELETE FROM wg_peers WHERE name = ?`, name); err != nil {
		return config.PeerConfig{}, false, fmt.Errorf("statsdb: delete peer %q: %w", name, err)
	}
	return p, true, nil
}

// RenamePeer renames a peer from oldName to newName.
func (s *Store) RenamePeer(oldName, newName string) error {
	_, found, err := s.GetPeer(oldName)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("statsdb: peer %q not found", oldName)
	}

	_, found, err = s.GetPeer(newName)
	if err != nil {
		return err
	}
	if found {
		return fmt.Errorf("statsdb: peer %q already exists", newName)
	}

	_, err = s.db.Exec(
		`UPDATE wg_peers SET name = ?, updated_unix = unixepoch() WHERE name = ?`,
		newName, oldName,
	)
	if err != nil {
		return fmt.Errorf("statsdb: rename peer %q to %q: %w", oldName, newName, err)
	}
	return nil
}

// ImportPeers inserts peers from a map, skipping names that already exist.
func (s *Store) ImportPeers(peers map[string]config.PeerConfig) (int, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, fmt.Errorf("statsdb: begin tx: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(
		`INSERT OR IGNORE INTO wg_peers (name, private_key, public_key, preshared_key, allowed_ips, disabled, upstream_group)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return 0, fmt.Errorf("statsdb: prepare import peers: %w", err)
	}
	defer stmt.Close()

	var count int
	for name, p := range peers {
		disabled := 0
		if p.Disabled {
			disabled = 1
		}
		res, err := stmt.Exec(name, p.PrivateKey, p.PublicKey, p.PresharedKey, p.AllowedIPs, disabled, p.UpstreamGroup)
		if err != nil {
			return 0, fmt.Errorf("statsdb: import peer %q: %w", name, err)
		}
		n, _ := res.RowsAffected()
		count += int(n)
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("statsdb: commit import peers: %w", err)
	}
	return count, nil
}

// SetPeerUpstreamGroup updates the upstream_group for a peer.
func (s *Store) SetPeerUpstreamGroup(name, group string) error {
	res, err := s.db.Exec(`UPDATE wg_peers SET upstream_group = ?, updated_unix = unixepoch() WHERE name = ?`, group, name)
	if err != nil {
		return fmt.Errorf("statsdb: set peer upstream group %q: %w", name, err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("peer %q not found", name)
	}
	return nil
}

// SetPeerExcludePrivate updates the exclude_private flag for a peer.
func (s *Store) SetPeerExcludePrivate(name string, excludePrivate bool) error {
	val := 0
	if excludePrivate {
		val = 1
	}
	res, err := s.db.Exec(`UPDATE wg_peers SET exclude_private = ?, updated_unix = unixepoch() WHERE name = ?`, val, name)
	if err != nil {
		return fmt.Errorf("statsdb: set peer exclude_private %q: %w", name, err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("peer %q not found", name)
	}
	return nil
}

// SetPeerExcludeServer updates the exclude_server flag for a peer.
func (s *Store) SetPeerExcludeServer(name string, excludeServer bool) error {
	val := 0
	if excludeServer {
		val = 1
	}
	res, err := s.db.Exec(`UPDATE wg_peers SET exclude_server = ?, updated_unix = unixepoch() WHERE name = ?`, val, name)
	if err != nil {
		return fmt.Errorf("statsdb: set peer exclude_server %q: %w", name, err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("peer %q not found", name)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Secret CRUD
// ---------------------------------------------------------------------------

// ListSecrets returns all non-disabled secret hex strings.
func (s *Store) ListSecrets() ([]string, error) {
	rows, err := s.db.Query(`SELECT secret_hex FROM mtproxy_secrets WHERE disabled = 0`)
	if err != nil {
		return nil, fmt.Errorf("statsdb: list secrets: %w", err)
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var hex string
		if err := rows.Scan(&hex); err != nil {
			return nil, fmt.Errorf("statsdb: scan secret: %w", err)
		}
		out = append(out, hex)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statsdb: iterate secrets: %w", err)
	}
	return out, nil
}

// AddSecret inserts a new secret. Returns error if it already exists.
func (s *Store) AddSecret(secretHex, comment string) error {
	_, err := s.db.Exec(
		`INSERT INTO mtproxy_secrets (secret_hex, comment) VALUES (?, ?)`,
		secretHex, comment,
	)
	if err != nil {
		return fmt.Errorf("statsdb: add secret: %w", err)
	}
	return nil
}

// SecretNames returns a map of secret_hex → comment for the given secrets.
func (s *Store) SecretNames(secrets []string) (map[string]string, error) {
	if len(secrets) == 0 {
		return nil, nil
	}
	placeholders := make([]string, len(secrets))
	args := make([]any, len(secrets))
	for i, sec := range secrets {
		placeholders[i] = "?"
		args[i] = sec
	}
	query := `SELECT secret_hex, comment FROM mtproxy_secrets WHERE secret_hex IN (` + strings.Join(placeholders, ",") + `)`
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("statsdb: secret names: %w", err)
	}
	defer rows.Close()

	out := make(map[string]string)
	for rows.Next() {
		var hex, comment string
		if err := rows.Scan(&hex, &comment); err != nil {
			return nil, fmt.Errorf("statsdb: scan secret name: %w", err)
		}
		if comment != "" {
			out[hex] = comment
		}
	}
	return out, rows.Err()
}

// RenameSecret updates the comment (display name) of a secret.
func (s *Store) RenameSecret(secretHex, name string) error {
	res, err := s.db.Exec(`UPDATE mtproxy_secrets SET comment = ? WHERE secret_hex = ?`, name, secretHex)
	if err != nil {
		return fmt.Errorf("statsdb: rename secret: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("statsdb: secret not found")
	}
	return nil
}

// DeleteSecret deletes a secret by hex string.
func (s *Store) DeleteSecret(secretHex string) (bool, error) {
	res, err := s.db.Exec(`DELETE FROM mtproxy_secrets WHERE secret_hex = ?`, secretHex)
	if err != nil {
		return false, fmt.Errorf("statsdb: delete secret: %w", err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// ImportSecrets inserts secrets from a list, skipping those that already exist.
func (s *Store) ImportSecrets(secrets []string) (int, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, fmt.Errorf("statsdb: begin tx: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`INSERT OR IGNORE INTO mtproxy_secrets (secret_hex) VALUES (?)`)
	if err != nil {
		return 0, fmt.Errorf("statsdb: prepare import secrets: %w", err)
	}
	defer stmt.Close()

	var count int
	for _, hex := range secrets {
		res, err := stmt.Exec(hex)
		if err != nil {
			return 0, fmt.Errorf("statsdb: import secret %q: %w", hex, err)
		}
		n, _ := res.RowsAffected()
		count += int(n)
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("statsdb: commit import secrets: %w", err)
	}
	return count, nil
}

// ListSecretUpstreamGroups returns a map of secret_hex -> upstream_group for all secrets.
func (s *Store) ListSecretUpstreamGroups() (map[string]string, error) {
	rows, err := s.db.Query(`SELECT secret_hex, upstream_group FROM mtproxy_secrets WHERE upstream_group != ''`)
	if err != nil {
		return nil, fmt.Errorf("statsdb: list secret upstream groups: %w", err)
	}
	defer rows.Close()

	out := make(map[string]string)
	for rows.Next() {
		var hex, group string
		if err := rows.Scan(&hex, &group); err != nil {
			return nil, fmt.Errorf("statsdb: scan secret upstream group: %w", err)
		}
		out[hex] = group
	}
	return out, rows.Err()
}

// SetSecretUpstreamGroup updates the upstream_group for an MTProxy secret.
func (s *Store) SetSecretUpstreamGroup(secretHex, group string) error {
	res, err := s.db.Exec(`UPDATE mtproxy_secrets SET upstream_group = ? WHERE secret_hex = ?`, group, secretHex)
	if err != nil {
		return fmt.Errorf("statsdb: set secret upstream group %q: %w", secretHex, err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("secret %q not found", secretHex)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Proxy Server CRUD
// ---------------------------------------------------------------------------

// ListProxyServers returns all proxy server configs from the database.
func (s *Store) ListProxyServers() ([]config.ProxyServerConfig, error) {
	rows, err := s.db.Query(
		`SELECT name, type, listen, username, password,
		        tls_cert_file, tls_key_file, tls_domain, tls_acme_email, upstream_group
		 FROM proxy_servers`)
	if err != nil {
		return nil, fmt.Errorf("statsdb: list proxy servers: %w", err)
	}
	defer rows.Close()

	var out []config.ProxyServerConfig
	for rows.Next() {
		var p config.ProxyServerConfig
		if err := rows.Scan(&p.Name, &p.Type, &p.Listen,
			&p.Username, &p.Password,
			&p.TLS.CertFile, &p.TLS.KeyFile, &p.TLS.Domain, &p.TLS.ACMEEmail, &p.UpstreamGroup); err != nil {
			return nil, fmt.Errorf("statsdb: scan proxy server: %w", err)
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statsdb: iterate proxy servers: %w", err)
	}
	return out, nil
}

// AddProxyServer inserts a new proxy server config.
func (s *Store) AddProxyServer(p config.ProxyServerConfig) error {
	_, err := s.db.Exec(
		`INSERT INTO proxy_servers (name, type, listen, username, password,
		                            tls_cert_file, tls_key_file, tls_domain, tls_acme_email, upstream_group)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		p.Name, p.Type, p.Listen, p.Username, p.Password,
		p.TLS.CertFile, p.TLS.KeyFile, p.TLS.Domain, p.TLS.ACMEEmail, p.UpstreamGroup,
	)
	if err != nil {
		return fmt.Errorf("statsdb: add proxy server %q: %w", p.Name, err)
	}
	return nil
}

// SetProxyUpstreamGroup updates the upstream_group for a proxy server.
func (s *Store) SetProxyUpstreamGroup(name, group string) error {
	res, err := s.db.Exec(`UPDATE proxy_servers SET upstream_group = ? WHERE name = ?`, group, name)
	if err != nil {
		return fmt.Errorf("statsdb: set proxy upstream group %q: %w", name, err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("proxy server %q not found", name)
	}
	return nil
}

// SetProxyAuth updates the username and password for a proxy server.
func (s *Store) SetProxyAuth(name, username, password string) error {
	res, err := s.db.Exec(`UPDATE proxy_servers SET username = ?, password = ? WHERE name = ?`, username, password, name)
	if err != nil {
		return fmt.Errorf("statsdb: set proxy auth %q: %w", name, err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("proxy server %q not found", name)
	}
	return nil
}

// DeleteProxyServer deletes a proxy server by name.
func (s *Store) DeleteProxyServer(name string) (bool, error) {
	res, err := s.db.Exec(`DELETE FROM proxy_servers WHERE name = ?`, name)
	if err != nil {
		return false, fmt.Errorf("statsdb: delete proxy server %q: %w", name, err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// ImportProxyServers inserts proxy servers from a list, skipping names that already exist.
func (s *Store) ImportProxyServers(proxies []config.ProxyServerConfig) (int, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, fmt.Errorf("statsdb: begin tx: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(
		`INSERT OR IGNORE INTO proxy_servers (name, type, listen, username, password,
		                                      tls_cert_file, tls_key_file, tls_domain, tls_acme_email, upstream_group)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return 0, fmt.Errorf("statsdb: prepare import proxy servers: %w", err)
	}
	defer stmt.Close()

	var count int
	for _, p := range proxies {
		res, err := stmt.Exec(p.Name, p.Type, p.Listen, p.Username, p.Password,
			p.TLS.CertFile, p.TLS.KeyFile, p.TLS.Domain, p.TLS.ACMEEmail, p.UpstreamGroup)
		if err != nil {
			return 0, fmt.Errorf("statsdb: import proxy server %q: %w", p.Name, err)
		}
		n, _ := res.RowsAffected()
		count += int(n)
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("statsdb: commit import proxy servers: %w", err)
	}
	return count, nil
}

// ---------------------------------------------------------------------------
// Upstream CRUD
// ---------------------------------------------------------------------------

// ListUpstreams returns all upstream configs from the database.
func (s *Store) ListUpstreams() ([]config.UpstreamConfig, error) {
	rows, err := s.db.Query(
		`SELECT name, type, enabled, is_default, groups, transport,
		        health_check_enabled, health_check_interval, health_check_target
		 FROM upstreams`)
	if err != nil {
		return nil, fmt.Errorf("statsdb: list upstreams: %w", err)
	}
	defer rows.Close()

	var out []config.UpstreamConfig
	for rows.Next() {
		var u config.UpstreamConfig
		var enabled, isDefault, hcEnabled, hcInterval int
		var groups, hcTarget string
		if err := rows.Scan(&u.Name, &u.Type, &enabled, &isDefault, &groups, &u.Transport,
			&hcEnabled, &hcInterval, &hcTarget); err != nil {
			return nil, fmt.Errorf("statsdb: scan upstream: %w", err)
		}
		if enabled == 0 {
			f := false
			u.Enabled = &f
		}
		u.Default = isDefault == 1
		if groups != "" {
			u.Groups = strings.Split(groups, ",")
		}
		u.HealthCheck.Enabled = hcEnabled == 1
		u.HealthCheck.Interval = hcInterval
		u.HealthCheck.Target = hcTarget
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statsdb: iterate upstreams: %w", err)
	}
	return out, nil
}

// AddUpstream inserts a new upstream config.
func (s *Store) AddUpstream(u config.UpstreamConfig) error {
	enabled := 0
	if u.IsEnabled() {
		enabled = 1
	}
	isDefault := 0
	if u.Default {
		isDefault = 1
	}
	hcEnabled := 0
	if u.HealthCheck.Enabled {
		hcEnabled = 1
	}
	_, err := s.db.Exec(
		`INSERT INTO upstreams (name, type, enabled, is_default, groups, transport,
		                        health_check_enabled, health_check_interval, health_check_target)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		u.Name, u.Type, enabled, isDefault, strings.Join(u.Groups, ","), u.Transport,
		hcEnabled, u.HealthCheck.Interval, u.HealthCheck.Target,
	)
	if err != nil {
		return fmt.Errorf("statsdb: add upstream %q: %w", u.Name, err)
	}
	return nil
}

// UpdateUpstream updates an existing upstream config.
func (s *Store) UpdateUpstream(u config.UpstreamConfig) error {
	enabled := 0
	if u.IsEnabled() {
		enabled = 1
	}
	isDefault := 0
	if u.Default {
		isDefault = 1
	}
	hcEnabled := 0
	if u.HealthCheck.Enabled {
		hcEnabled = 1
	}
	res, err := s.db.Exec(
		`UPDATE upstreams SET type = ?, enabled = ?, is_default = ?, groups = ?, transport = ?,
		        health_check_enabled = ?, health_check_interval = ?, health_check_target = ?,
		        updated_unix = unixepoch()
		 WHERE name = ?`,
		u.Type, enabled, isDefault, strings.Join(u.Groups, ","), u.Transport,
		hcEnabled, u.HealthCheck.Interval, u.HealthCheck.Target,
		u.Name,
	)
	if err != nil {
		return fmt.Errorf("statsdb: update upstream %q: %w", u.Name, err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("statsdb: update upstream %q: not found", u.Name)
	}
	return nil
}

// DeleteUpstream deletes an upstream by name.
func (s *Store) DeleteUpstream(name string) (bool, error) {
	res, err := s.db.Exec(`DELETE FROM upstreams WHERE name = ?`, name)
	if err != nil {
		return false, fmt.Errorf("statsdb: delete upstream %q: %w", name, err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// ImportUpstreams inserts upstreams from a list, skipping names that already exist.
func (s *Store) ImportUpstreams(upstreams []config.UpstreamConfig) (int, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, fmt.Errorf("statsdb: begin tx: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(
		`INSERT OR IGNORE INTO upstreams (name, type, enabled, is_default, groups, transport,
		                                  health_check_enabled, health_check_interval, health_check_target)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return 0, fmt.Errorf("statsdb: prepare import upstreams: %w", err)
	}
	defer stmt.Close()

	var count int
	for _, u := range upstreams {
		enabled := 0
		if u.IsEnabled() {
			enabled = 1
		}
		isDefault := 0
		if u.Default {
			isDefault = 1
		}
		hcEnabled := 0
		if u.HealthCheck.Enabled {
			hcEnabled = 1
		}
		res, err := stmt.Exec(u.Name, u.Type, enabled, isDefault, strings.Join(u.Groups, ","), u.Transport,
			hcEnabled, u.HealthCheck.Interval, u.HealthCheck.Target)
		if err != nil {
			return 0, fmt.Errorf("statsdb: import upstream %q: %w", u.Name, err)
		}
		n, _ := res.RowsAffected()
		count += int(n)
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("statsdb: commit import upstreams: %w", err)
	}
	return count, nil
}

// ---------------------------------------------------------------------------
// Upstream Groups CRUD
// ---------------------------------------------------------------------------

// ListGroups returns all explicitly created group names.
func (s *Store) ListGroups() ([]string, error) {
	rows, err := s.db.Query(`SELECT name FROM upstream_groups ORDER BY created_unix ASC`)
	if err != nil {
		return nil, fmt.Errorf("statsdb: list groups: %w", err)
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("statsdb: scan group: %w", err)
		}
		out = append(out, name)
	}
	return out, rows.Err()
}

// CreateGroup creates a named upstream group.
func (s *Store) CreateGroup(name string) error {
	_, err := s.db.Exec(
		`INSERT INTO upstream_groups (name) VALUES (?)`, name)
	if err != nil {
		return fmt.Errorf("statsdb: create group %q: %w", name, err)
	}
	return nil
}

// DeleteGroup removes a named upstream group. Returns true if a row was deleted.
func (s *Store) DeleteGroup(name string) (bool, error) {
	res, err := s.db.Exec(`DELETE FROM upstream_groups WHERE name = ?`, name)
	if err != nil {
		return false, fmt.Errorf("statsdb: delete group %q: %w", name, err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// RemoveGroupFromUpstreams removes the given group name from the groups column
// of all upstreams that reference it.
func (s *Store) RemoveGroupFromUpstreams(group string) (int, error) {
	rows, err := s.db.Query(`SELECT name, groups FROM upstreams WHERE groups LIKE '%' || ? || '%'`, group)
	if err != nil {
		return 0, fmt.Errorf("statsdb: query upstreams for group %q: %w", group, err)
	}
	defer rows.Close()

	type upd struct {
		name   string
		groups string
	}
	var updates []upd
	for rows.Next() {
		var name, groups string
		if err := rows.Scan(&name, &groups); err != nil {
			return 0, fmt.Errorf("statsdb: scan upstream: %w", err)
		}
		parts := strings.Split(groups, ",")
		var filtered []string
		for _, p := range parts {
			if p != group {
				filtered = append(filtered, p)
			}
		}
		updates = append(updates, upd{name: name, groups: strings.Join(filtered, ",")})
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}

	var count int
	for _, u := range updates {
		if _, err := s.db.Exec(`UPDATE upstreams SET groups = ?, updated_unix = unixepoch() WHERE name = ?`, u.groups, u.name); err != nil {
			return count, fmt.Errorf("statsdb: update upstream %q groups: %w", u.name, err)
		}
		count++
	}
	return count, nil
}

// ---------------------------------------------------------------------------
// Allowed Users CRUD
// ---------------------------------------------------------------------------

// ListAllowedUsers returns all authorized Telegram users.
func (s *Store) ListAllowedUsers() ([]AllowedUser, error) {
	rows, err := s.db.Query(
		`SELECT user_id, username, first_name, last_name, photo_url, custom_name, disabled, role, created_unix, max_peers, max_secrets
		 FROM allowed_users ORDER BY created_unix DESC`)
	if err != nil {
		return nil, fmt.Errorf("statsdb: list allowed users: %w", err)
	}
	defer rows.Close()

	var out []AllowedUser
	for rows.Next() {
		var u AllowedUser
		var disabled int
		var maxPeers, maxSecrets sql.NullInt64
		if err := rows.Scan(&u.UserID, &u.Username, &u.FirstName, &u.LastName, &u.PhotoURL, &u.CustomName, &disabled, &u.Role, &u.CreatedAt, &maxPeers, &maxSecrets); err != nil {
			return nil, fmt.Errorf("statsdb: scan allowed user: %w", err)
		}
		u.Disabled = disabled != 0
		if maxPeers.Valid {
			v := int(maxPeers.Int64)
			u.MaxPeers = &v
		}
		if maxSecrets.Valid {
			v := int(maxSecrets.Int64)
			u.MaxSecrets = &v
		}
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statsdb: iterate allowed users: %w", err)
	}
	return out, nil
}

// AddAllowedUser adds a new authorized user. Upserts to update profile info.
func (s *Store) AddAllowedUser(u AllowedUser) error {
	role := u.Role
	if role == "" {
		role = RoleGuest
	}
	_, err := s.db.Exec(
		`INSERT INTO allowed_users (user_id, username, first_name, last_name, photo_url, custom_name, role)
		 VALUES (?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(user_id) DO UPDATE SET
		   username = excluded.username,
		   first_name = excluded.first_name,
		   last_name = excluded.last_name,
		   photo_url = excluded.photo_url,
		   custom_name = CASE WHEN excluded.custom_name != '' THEN excluded.custom_name ELSE allowed_users.custom_name END,
		   role = excluded.role`,
		u.UserID, u.Username, u.FirstName, u.LastName, u.PhotoURL, u.CustomName, role,
	)
	if err != nil {
		return fmt.Errorf("statsdb: add allowed user %d: %w", u.UserID, err)
	}
	return nil
}

// GetUserRole returns the role of a user, or empty string if not found.
func (s *Store) GetUserRole(userID int64) (string, error) {
	var role string
	var disabled int
	err := s.db.QueryRow(`SELECT role, disabled FROM allowed_users WHERE user_id = ?`, userID).Scan(&role, &disabled)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("statsdb: get user role %d: %w", userID, err)
	}
	if disabled != 0 {
		return "", nil
	}
	return role, nil
}

// SetUserRole updates the role of an existing user.
func (s *Store) SetUserRole(userID int64, role string) (bool, error) {
	res, err := s.db.Exec(`UPDATE allowed_users SET role = ? WHERE user_id = ?`, role, userID)
	if err != nil {
		return false, fmt.Errorf("statsdb: set user role %d: %w", userID, err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// DeleteAllowedUser removes an authorized user by ID.
func (s *Store) DeleteAllowedUser(userID int64) (bool, error) {
	res, err := s.db.Exec(`DELETE FROM allowed_users WHERE user_id = ?`, userID)
	if err != nil {
		return false, fmt.Errorf("statsdb: delete allowed user %d: %w", userID, err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// UpdateAllowedUser updates fields of an existing user. Only non-nil fields are updated.
func (s *Store) UpdateAllowedUser(userID int64, customName *string, role *string, disabled *bool, maxPeers *int, maxSecrets *int) (bool, error) {
	var sets []string
	var args []any
	if customName != nil {
		sets = append(sets, "custom_name = ?")
		args = append(args, *customName)
	}
	if role != nil {
		sets = append(sets, "role = ?")
		args = append(args, *role)
	}
	if disabled != nil {
		d := 0
		if *disabled {
			d = 1
		}
		sets = append(sets, "disabled = ?")
		args = append(args, d)
	}
	if maxPeers != nil {
		sets = append(sets, "max_peers = ?")
		args = append(args, *maxPeers)
	}
	if maxSecrets != nil {
		sets = append(sets, "max_secrets = ?")
		args = append(args, *maxSecrets)
	}
	if len(sets) == 0 {
		return false, nil
	}
	args = append(args, userID)
	query := "UPDATE allowed_users SET " + strings.Join(sets, ", ") + " WHERE user_id = ?"
	res, err := s.db.Exec(query, args...)
	if err != nil {
		return false, fmt.Errorf("statsdb: update allowed user %d: %w", userID, err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// GetUserLimits returns the per-user limits for peers and secrets.
// Returns nil values when no custom limit is set.
func (s *Store) GetUserLimits(userID int64) (maxPeers *int, maxSecrets *int, err error) {
	var mp, ms sql.NullInt64
	err = s.db.QueryRow(`SELECT max_peers, max_secrets FROM allowed_users WHERE user_id = ?`, userID).Scan(&mp, &ms)
	if err == sql.ErrNoRows {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("statsdb: get user limits %d: %w", userID, err)
	}
	if mp.Valid {
		v := int(mp.Int64)
		maxPeers = &v
	}
	if ms.Valid {
		v := int(ms.Int64)
		maxSecrets = &v
	}
	return maxPeers, maxSecrets, nil
}

// GetUserDisplayNames returns a map of user_id → display name for the given IDs.
// Display name priority: custom_name > first_name last_name > username > "User {id}".
func (s *Store) GetUserDisplayNames(userIDs []int64) (map[int64]string, error) {
	if len(userIDs) == 0 {
		return nil, nil
	}
	placeholders := make([]string, len(userIDs))
	args := make([]any, len(userIDs))
	for i, id := range userIDs {
		placeholders[i] = "?"
		args[i] = id
	}
	query := "SELECT user_id, username, first_name, last_name, custom_name FROM allowed_users WHERE user_id IN (" + strings.Join(placeholders, ",") + ")"
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("statsdb: get user display names: %w", err)
	}
	defer rows.Close()

	out := make(map[int64]string)
	for rows.Next() {
		var id int64
		var username, firstName, lastName, customName string
		if err := rows.Scan(&id, &username, &firstName, &lastName, &customName); err != nil {
			return nil, fmt.Errorf("statsdb: scan user display name: %w", err)
		}
		name := customName
		if name == "" {
			name = strings.TrimSpace(firstName + " " + lastName)
		}
		if name == "" {
			name = username
		}
		if name == "" {
			name = fmt.Sprintf("User %d", id)
		}
		out[id] = name
	}
	return out, rows.Err()
}

// ListPeerOwners returns a map of peer_name → owner_user_id for all owned peers.
func (s *Store) ListPeerOwners() (map[string]int64, error) {
	rows, err := s.db.Query(`SELECT name, owner_user_id FROM wg_peers WHERE owner_user_id IS NOT NULL`)
	if err != nil {
		return nil, fmt.Errorf("statsdb: list peer owners: %w", err)
	}
	defer rows.Close()

	out := make(map[string]int64)
	for rows.Next() {
		var name string
		var ownerID int64
		if err := rows.Scan(&name, &ownerID); err != nil {
			return nil, fmt.Errorf("statsdb: scan peer owner: %w", err)
		}
		out[name] = ownerID
	}
	return out, rows.Err()
}

// ListSecretOwners returns a map of secret_hex → owner_user_id for all owned secrets.
func (s *Store) ListSecretOwners() (map[string]int64, error) {
	rows, err := s.db.Query(`SELECT secret_hex, owner_user_id FROM mtproxy_secrets WHERE owner_user_id IS NOT NULL`)
	if err != nil {
		return nil, fmt.Errorf("statsdb: list secret owners: %w", err)
	}
	defer rows.Close()

	out := make(map[string]int64)
	for rows.Next() {
		var hex string
		var ownerID int64
		if err := rows.Scan(&hex, &ownerID); err != nil {
			return nil, fmt.Errorf("statsdb: scan secret owner: %w", err)
		}
		out[hex] = ownerID
	}
	return out, rows.Err()
}

// IsAllowedUser checks if a user ID exists in the allowed_users table.
func (s *Store) IsAllowedUser(userID int64) (bool, error) {
	var count int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM allowed_users WHERE user_id = ?`, userID).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("statsdb: check allowed user %d: %w", userID, err)
	}
	return count > 0, nil
}

// ---------------------------------------------------------------------------
// DNS Rule CRUD
// ---------------------------------------------------------------------------

// ListDNSRules returns all DNS rules ordered by priority.
func (s *Store) ListDNSRules() ([]config.DNSRuleConfig, error) {
	rows, err := s.db.Query(
		`SELECT name, action, upstream, domains_json, lists_json, peers_json
		 FROM dns_rules ORDER BY priority ASC, created_unix ASC`)
	if err != nil {
		return nil, fmt.Errorf("statsdb: list dns rules: %w", err)
	}
	defer rows.Close()

	var out []config.DNSRuleConfig
	for rows.Next() {
		var r config.DNSRuleConfig
		var domainsJSON, listsJSON, peersJSON string
		if err := rows.Scan(&r.Name, &r.Action, &r.Upstream, &domainsJSON, &listsJSON, &peersJSON); err != nil {
			return nil, fmt.Errorf("statsdb: scan dns rule: %w", err)
		}
		if domainsJSON != "" && domainsJSON != "[]" {
			if err := json.Unmarshal([]byte(domainsJSON), &r.Domains); err != nil {
				return nil, fmt.Errorf("statsdb: unmarshal domains for %q: %w", r.Name, err)
			}
		}
		if listsJSON != "" && listsJSON != "[]" {
			if err := json.Unmarshal([]byte(listsJSON), &r.Lists); err != nil {
				return nil, fmt.Errorf("statsdb: unmarshal lists for %q: %w", r.Name, err)
			}
		}
		if peersJSON != "" && peersJSON != "[]" {
			if err := json.Unmarshal([]byte(peersJSON), &r.Peers); err != nil {
				return nil, fmt.Errorf("statsdb: unmarshal peers for %q: %w", r.Name, err)
			}
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statsdb: iterate dns rules: %w", err)
	}
	return out, nil
}

// UpsertDNSRecord inserts or updates a DNS record.
func (s *Store) UpsertDNSRecord(name string, rec config.DNSRecordConfig) error {
	aJSON, err := json.Marshal(rec.A)
	if err != nil {
		return fmt.Errorf("statsdb: marshal A records: %w", err)
	}
	aaaaJSON, err := json.Marshal(rec.AAAA)
	if err != nil {
		return fmt.Errorf("statsdb: marshal AAAA records: %w", err)
	}
	_, err = s.db.Exec(
		`INSERT INTO dns_records (name, a_json, aaaa_json, ttl)
		 VALUES (?, ?, ?, ?)
		 ON CONFLICT(name) DO UPDATE SET
		   a_json = excluded.a_json,
		   aaaa_json = excluded.aaaa_json,
		   ttl = excluded.ttl,
		   updated_unix = unixepoch()`,
		name, string(aJSON), string(aaaaJSON), rec.TTL,
	)
	if err != nil {
		return fmt.Errorf("statsdb: upsert dns record %q: %w", name, err)
	}
	return nil
}

// DeleteDNSRecord deletes a DNS record by name.
func (s *Store) DeleteDNSRecord(name string) (bool, error) {
	res, err := s.db.Exec(`DELETE FROM dns_records WHERE name = ?`, name)
	if err != nil {
		return false, fmt.Errorf("statsdb: delete dns record %q: %w", name, err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// ListDNSRecords returns all DNS records from the database.
func (s *Store) ListDNSRecords() (map[string]config.DNSRecordConfig, error) {
	rows, err := s.db.Query(`SELECT name, a_json, aaaa_json, ttl FROM dns_records ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("statsdb: list dns records: %w", err)
	}
	defer rows.Close()

	out := make(map[string]config.DNSRecordConfig)
	for rows.Next() {
		var name, aJSON, aaaaJSON string
		var ttl uint32
		if err := rows.Scan(&name, &aJSON, &aaaaJSON, &ttl); err != nil {
			return nil, fmt.Errorf("statsdb: scan dns record: %w", err)
		}
		var rec config.DNSRecordConfig
		rec.TTL = ttl
		if err := json.Unmarshal([]byte(aJSON), &rec.A); err != nil {
			return nil, fmt.Errorf("statsdb: unmarshal A for %q: %w", name, err)
		}
		if err := json.Unmarshal([]byte(aaaaJSON), &rec.AAAA); err != nil {
			return nil, fmt.Errorf("statsdb: unmarshal AAAA for %q: %w", name, err)
		}
		out[name] = rec
	}
	return out, rows.Err()
}

// ImportDNSRecords inserts DNS records from a map, skipping names that already exist.
func (s *Store) ImportDNSRecords(records map[string]config.DNSRecordConfig) (int, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, fmt.Errorf("statsdb: begin tx: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(
		`INSERT OR IGNORE INTO dns_records (name, a_json, aaaa_json, ttl) VALUES (?, ?, ?, ?)`,
	)
	if err != nil {
		return 0, fmt.Errorf("statsdb: prepare: %w", err)
	}
	defer stmt.Close()

	imported := 0
	for name, rec := range records {
		aJSON, _ := json.Marshal(rec.A)
		aaaaJSON, _ := json.Marshal(rec.AAAA)
		res, err := stmt.Exec(name, string(aJSON), string(aaaaJSON), rec.TTL)
		if err != nil {
			return imported, fmt.Errorf("statsdb: import dns record %q: %w", name, err)
		}
		if n, _ := res.RowsAffected(); n > 0 {
			imported++
		}
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("statsdb: commit: %w", err)
	}
	return imported, nil
}

// AddDNSRule inserts a new DNS rule with the next available priority.
func (s *Store) AddDNSRule(r config.DNSRuleConfig) error {
	domainsJSON, err := json.Marshal(r.Domains)
	if err != nil {
		return fmt.Errorf("statsdb: marshal domains: %w", err)
	}
	listsJSON, err := json.Marshal(r.Lists)
	if err != nil {
		return fmt.Errorf("statsdb: marshal lists: %w", err)
	}
	peersJSON, err := json.Marshal(r.Peers)
	if err != nil {
		return fmt.Errorf("statsdb: marshal peers: %w", err)
	}

	_, err = s.db.Exec(
		`INSERT INTO dns_rules (name, action, upstream, domains_json, lists_json, peers_json, priority)
		 VALUES (?, ?, ?, ?, ?, ?, COALESCE((SELECT MAX(priority) FROM dns_rules), -1) + 1)`,
		r.Name, r.Action, r.Upstream, string(domainsJSON), string(listsJSON), string(peersJSON),
	)
	if err != nil {
		return fmt.Errorf("statsdb: add dns rule %q: %w", r.Name, err)
	}
	return nil
}

// DeleteDNSRule deletes a DNS rule by name.
func (s *Store) DeleteDNSRule(name string) (bool, error) {
	res, err := s.db.Exec(`DELETE FROM dns_rules WHERE name = ?`, name)
	if err != nil {
		return false, fmt.Errorf("statsdb: delete dns rule %q: %w", name, err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// UpdateDNSRule updates an existing DNS rule by name.
func (s *Store) UpdateDNSRule(r config.DNSRuleConfig) error {
	domainsJSON, err := json.Marshal(r.Domains)
	if err != nil {
		return fmt.Errorf("statsdb: marshal domains: %w", err)
	}
	listsJSON, err := json.Marshal(r.Lists)
	if err != nil {
		return fmt.Errorf("statsdb: marshal lists: %w", err)
	}
	peersJSON, err := json.Marshal(r.Peers)
	if err != nil {
		return fmt.Errorf("statsdb: marshal peers: %w", err)
	}

	res, err := s.db.Exec(
		`UPDATE dns_rules SET action = ?, upstream = ?, domains_json = ?, lists_json = ?, peers_json = ?, updated_unix = unixepoch()
		 WHERE name = ?`,
		r.Action, r.Upstream, string(domainsJSON), string(listsJSON), string(peersJSON), r.Name,
	)
	if err != nil {
		return fmt.Errorf("statsdb: update dns rule %q: %w", r.Name, err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("statsdb: dns rule %q not found", r.Name)
	}
	return nil
}

// ImportDNSRules inserts DNS rules from a list, skipping names that already exist.
// Rules are assigned incrementing priorities starting from the current max.
func (s *Store) ImportDNSRules(rules []config.DNSRuleConfig) (int, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, fmt.Errorf("statsdb: begin tx: %w", err)
	}
	defer tx.Rollback()

	// Get current max priority.
	var maxPriority int
	err = tx.QueryRow(`SELECT COALESCE(MAX(priority), -1) FROM dns_rules`).Scan(&maxPriority)
	if err != nil {
		return 0, fmt.Errorf("statsdb: get max priority: %w", err)
	}

	stmt, err := tx.Prepare(
		`INSERT OR IGNORE INTO dns_rules (name, action, upstream, domains_json, lists_json, peers_json, priority)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return 0, fmt.Errorf("statsdb: prepare import dns rules: %w", err)
	}
	defer stmt.Close()

	var count int
	for _, r := range rules {
		domainsJSON, err := json.Marshal(r.Domains)
		if err != nil {
			return 0, fmt.Errorf("statsdb: marshal domains for %q: %w", r.Name, err)
		}
		listsJSON, err := json.Marshal(r.Lists)
		if err != nil {
			return 0, fmt.Errorf("statsdb: marshal lists for %q: %w", r.Name, err)
		}
		peersJSON, err := json.Marshal(r.Peers)
		if err != nil {
			return 0, fmt.Errorf("statsdb: marshal peers for %q: %w", r.Name, err)
		}
		maxPriority++
		res, err := stmt.Exec(r.Name, r.Action, r.Upstream, string(domainsJSON), string(listsJSON), string(peersJSON), maxPriority)
		if err != nil {
			return 0, fmt.Errorf("statsdb: import dns rule %q: %w", r.Name, err)
		}
		n, _ := res.RowsAffected()
		count += int(n)
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("statsdb: commit import dns rules: %w", err)
	}
	return count, nil
}

// ---------------------------------------------------------------------------
// Routing CIDRs
// ---------------------------------------------------------------------------

// ListRoutingCIDRs returns all routing CIDRs ordered by priority.
func (s *Store) ListRoutingCIDRs() ([]config.CIDREntry, error) {
	rows, err := s.db.Query(`SELECT cidr, mode FROM routing_cidrs ORDER BY priority ASC, created_unix ASC`)
	if err != nil {
		return nil, fmt.Errorf("statsdb: list routing cidrs: %w", err)
	}
	defer rows.Close()

	var out []config.CIDREntry
	for rows.Next() {
		var entry config.CIDREntry
		if err := rows.Scan(&entry.CIDR, &entry.Mode); err != nil {
			return nil, fmt.Errorf("statsdb: scan routing cidr: %w", err)
		}
		out = append(out, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statsdb: iterate routing cidrs: %w", err)
	}
	return out, nil
}

// AddRoutingCIDR inserts a routing CIDR with the next available priority.
func (s *Store) AddRoutingCIDR(entry config.CIDREntry) error {
	_, err := s.db.Exec(
		`INSERT INTO routing_cidrs (cidr, mode, priority)
		 VALUES (?, ?, COALESCE((SELECT MAX(priority) FROM routing_cidrs), -1) + 1)`,
		entry.CIDR, entry.Mode,
	)
	if err != nil {
		return fmt.Errorf("statsdb: add routing cidr %q: %w", entry.CIDR, err)
	}
	return nil
}

// DeleteRoutingCIDR deletes a routing CIDR by value.
func (s *Store) DeleteRoutingCIDR(cidr string) (bool, error) {
	res, err := s.db.Exec(`DELETE FROM routing_cidrs WHERE cidr = ?`, cidr)
	if err != nil {
		return false, fmt.Errorf("statsdb: delete routing cidr %q: %w", cidr, err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// ImportRoutingCIDRs inserts routing CIDRs from a list, skipping those that already exist.
func (s *Store) ImportRoutingCIDRs(entries []config.CIDREntry) (int, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, fmt.Errorf("statsdb: begin tx: %w", err)
	}
	defer tx.Rollback()

	var maxPriority int
	err = tx.QueryRow(`SELECT COALESCE(MAX(priority), -1) FROM routing_cidrs`).Scan(&maxPriority)
	if err != nil {
		return 0, fmt.Errorf("statsdb: get max priority: %w", err)
	}

	stmt, err := tx.Prepare(`INSERT OR IGNORE INTO routing_cidrs (cidr, mode, priority) VALUES (?, ?, ?)`)
	if err != nil {
		return 0, fmt.Errorf("statsdb: prepare import routing cidrs: %w", err)
	}
	defer stmt.Close()

	var count int
	for _, entry := range entries {
		maxPriority++
		res, err := stmt.Exec(entry.CIDR, entry.Mode, maxPriority)
		if err != nil {
			return 0, fmt.Errorf("statsdb: import routing cidr %q: %w", entry.CIDR, err)
		}
		n, _ := res.RowsAffected()
		count += int(n)
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("statsdb: commit import routing cidrs: %w", err)
	}
	return count, nil
}

// ReorderRoutingCIDRs updates priority values so CIDRs appear in the given order.
func (s *Store) ReorderRoutingCIDRs(cidrs []string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("statsdb: begin tx: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`UPDATE routing_cidrs SET priority = ? WHERE cidr = ?`)
	if err != nil {
		return fmt.Errorf("statsdb: prepare reorder routing cidrs: %w", err)
	}
	defer stmt.Close()

	for i, cidr := range cidrs {
		if _, err := stmt.Exec(i, cidr); err != nil {
			return fmt.Errorf("statsdb: reorder routing cidr %q: %w", cidr, err)
		}
	}

	return tx.Commit()
}

// UpdateRoutingCIDR replaces a CIDR entry, preserving its priority.
func (s *Store) UpdateRoutingCIDR(oldCIDR string, entry config.CIDREntry) error {
	res, err := s.db.Exec(
		`UPDATE routing_cidrs SET cidr = ?, mode = ? WHERE cidr = ?`,
		entry.CIDR, entry.Mode, oldCIDR,
	)
	if err != nil {
		return fmt.Errorf("statsdb: update routing cidr %q: %w", oldCIDR, err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("statsdb: routing cidr %q not found", oldCIDR)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Routing IP Rules
// ---------------------------------------------------------------------------

// ListIPRules returns all IP routing rules ordered by priority.
func (s *Store) ListIPRules() ([]config.IPRuleConfig, error) {
	rows, err := s.db.Query(
		`SELECT name, action, upstream_group, cidrs_json, asns_json, lists_json
		 FROM routing_ip_rules ORDER BY priority ASC, created_unix ASC`)
	if err != nil {
		return nil, fmt.Errorf("statsdb: list ip rules: %w", err)
	}
	defer rows.Close()

	var out []config.IPRuleConfig
	for rows.Next() {
		var r config.IPRuleConfig
		var cidrsJSON, asnsJSON, listsJSON string
		if err := rows.Scan(&r.Name, &r.Action, &r.UpstreamGroup, &cidrsJSON, &asnsJSON, &listsJSON); err != nil {
			return nil, fmt.Errorf("statsdb: scan ip rule: %w", err)
		}
		if cidrsJSON != "" && cidrsJSON != "[]" {
			if err := json.Unmarshal([]byte(cidrsJSON), &r.CIDRs); err != nil {
				return nil, fmt.Errorf("statsdb: unmarshal cidrs for %q: %w", r.Name, err)
			}
		}
		if asnsJSON != "" && asnsJSON != "[]" {
			if err := json.Unmarshal([]byte(asnsJSON), &r.ASNs); err != nil {
				return nil, fmt.Errorf("statsdb: unmarshal asns for %q: %w", r.Name, err)
			}
		}
		if listsJSON != "" && listsJSON != "[]" {
			if err := json.Unmarshal([]byte(listsJSON), &r.Lists); err != nil {
				return nil, fmt.Errorf("statsdb: unmarshal lists for %q: %w", r.Name, err)
			}
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statsdb: iterate ip rules: %w", err)
	}
	return out, nil
}

// AddIPRule inserts a new IP routing rule with the next available priority.
func (s *Store) AddIPRule(r config.IPRuleConfig) error {
	cidrsJSON, err := json.Marshal(r.CIDRs)
	if err != nil {
		return fmt.Errorf("statsdb: marshal cidrs: %w", err)
	}
	asnsJSON, err := json.Marshal(r.ASNs)
	if err != nil {
		return fmt.Errorf("statsdb: marshal asns: %w", err)
	}
	listsJSON, err := json.Marshal(r.Lists)
	if err != nil {
		return fmt.Errorf("statsdb: marshal lists: %w", err)
	}

	_, err = s.db.Exec(
		`INSERT INTO routing_ip_rules (name, action, upstream_group, cidrs_json, asns_json, lists_json, priority)
		 VALUES (?, ?, ?, ?, ?, ?, COALESCE((SELECT MAX(priority) FROM routing_ip_rules), -1) + 1)`,
		r.Name, r.Action, r.UpstreamGroup, string(cidrsJSON), string(asnsJSON), string(listsJSON),
	)
	if err != nil {
		return fmt.Errorf("statsdb: add ip rule %q: %w", r.Name, err)
	}
	return nil
}

// DeleteIPRule deletes an IP routing rule by name.
func (s *Store) DeleteIPRule(name string) (bool, error) {
	res, err := s.db.Exec(`DELETE FROM routing_ip_rules WHERE name = ?`, name)
	if err != nil {
		return false, fmt.Errorf("statsdb: delete ip rule %q: %w", name, err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// ImportIPRules inserts IP routing rules from a list, skipping names that already exist.
func (s *Store) ImportIPRules(rules []config.IPRuleConfig) (int, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, fmt.Errorf("statsdb: begin tx: %w", err)
	}
	defer tx.Rollback()

	var maxPriority int
	err = tx.QueryRow(`SELECT COALESCE(MAX(priority), -1) FROM routing_ip_rules`).Scan(&maxPriority)
	if err != nil {
		return 0, fmt.Errorf("statsdb: get max priority: %w", err)
	}

	stmt, err := tx.Prepare(
		`INSERT OR IGNORE INTO routing_ip_rules (name, action, upstream_group, cidrs_json, asns_json, lists_json, priority)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return 0, fmt.Errorf("statsdb: prepare import ip rules: %w", err)
	}
	defer stmt.Close()

	var count int
	for _, r := range rules {
		cidrsJSON, err := json.Marshal(r.CIDRs)
		if err != nil {
			return 0, fmt.Errorf("statsdb: marshal cidrs for %q: %w", r.Name, err)
		}
		asnsJSON, err := json.Marshal(r.ASNs)
		if err != nil {
			return 0, fmt.Errorf("statsdb: marshal asns for %q: %w", r.Name, err)
		}
		listsJSON, err := json.Marshal(r.Lists)
		if err != nil {
			return 0, fmt.Errorf("statsdb: marshal lists for %q: %w", r.Name, err)
		}
		maxPriority++
		res, err := stmt.Exec(r.Name, r.Action, r.UpstreamGroup, string(cidrsJSON), string(asnsJSON), string(listsJSON), maxPriority)
		if err != nil {
			return 0, fmt.Errorf("statsdb: import ip rule %q: %w", r.Name, err)
		}
		n, _ := res.RowsAffected()
		count += int(n)
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("statsdb: commit import ip rules: %w", err)
	}
	return count, nil
}

// ReorderIPRules updates priority values so IP rules appear in the given order.
func (s *Store) ReorderIPRules(names []string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("statsdb: begin tx: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`UPDATE routing_ip_rules SET priority = ? WHERE name = ?`)
	if err != nil {
		return fmt.Errorf("statsdb: prepare reorder ip rules: %w", err)
	}
	defer stmt.Close()

	for i, name := range names {
		if _, err := stmt.Exec(i, name); err != nil {
			return fmt.Errorf("statsdb: reorder ip rule %q: %w", name, err)
		}
	}

	return tx.Commit()
}

// UpdateIPRule updates an existing IP rule by name.
func (s *Store) UpdateIPRule(r config.IPRuleConfig) error {
	cidrsJSON, err := json.Marshal(r.CIDRs)
	if err != nil {
		return fmt.Errorf("statsdb: marshal cidrs: %w", err)
	}
	asnsJSON, err := json.Marshal(r.ASNs)
	if err != nil {
		return fmt.Errorf("statsdb: marshal asns: %w", err)
	}
	listsJSON, err := json.Marshal(r.Lists)
	if err != nil {
		return fmt.Errorf("statsdb: marshal lists: %w", err)
	}

	res, err := s.db.Exec(
		`UPDATE routing_ip_rules SET action = ?, upstream_group = ?, cidrs_json = ?, asns_json = ?, lists_json = ?, updated_unix = unixepoch()
		 WHERE name = ?`,
		r.Action, r.UpstreamGroup, string(cidrsJSON), string(asnsJSON), string(listsJSON), r.Name,
	)
	if err != nil {
		return fmt.Errorf("statsdb: update ip rule %q: %w", r.Name, err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("statsdb: ip rule %q not found", r.Name)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Routing SNI Rules
// ---------------------------------------------------------------------------

// ListSNIRules returns all SNI routing rules ordered by priority.
func (s *Store) ListSNIRules() ([]config.SNIRuleConfig, error) {
	rows, err := s.db.Query(
		`SELECT name, action, upstream_group, domains_json
		 FROM routing_sni_rules ORDER BY priority ASC, created_unix ASC`)
	if err != nil {
		return nil, fmt.Errorf("statsdb: list sni rules: %w", err)
	}
	defer rows.Close()

	var out []config.SNIRuleConfig
	for rows.Next() {
		var r config.SNIRuleConfig
		var domainsJSON string
		if err := rows.Scan(&r.Name, &r.Action, &r.UpstreamGroup, &domainsJSON); err != nil {
			return nil, fmt.Errorf("statsdb: scan sni rule: %w", err)
		}
		if domainsJSON != "" && domainsJSON != "[]" {
			if err := json.Unmarshal([]byte(domainsJSON), &r.Domains); err != nil {
				return nil, fmt.Errorf("statsdb: unmarshal domains for %q: %w", r.Name, err)
			}
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statsdb: iterate sni rules: %w", err)
	}
	return out, nil
}

// AddSNIRule inserts a new SNI routing rule with the next available priority.
func (s *Store) AddSNIRule(r config.SNIRuleConfig) error {
	domainsJSON, err := json.Marshal(r.Domains)
	if err != nil {
		return fmt.Errorf("statsdb: marshal domains: %w", err)
	}

	_, err = s.db.Exec(
		`INSERT INTO routing_sni_rules (name, action, upstream_group, domains_json, priority)
		 VALUES (?, ?, ?, ?, COALESCE((SELECT MAX(priority) FROM routing_sni_rules), -1) + 1)`,
		r.Name, r.Action, r.UpstreamGroup, string(domainsJSON),
	)
	if err != nil {
		return fmt.Errorf("statsdb: add sni rule %q: %w", r.Name, err)
	}
	return nil
}

// DeleteSNIRule deletes an SNI routing rule by name.
func (s *Store) DeleteSNIRule(name string) (bool, error) {
	res, err := s.db.Exec(`DELETE FROM routing_sni_rules WHERE name = ?`, name)
	if err != nil {
		return false, fmt.Errorf("statsdb: delete sni rule %q: %w", name, err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// UpdateSNIRule updates an existing SNI rule by name.
func (s *Store) UpdateSNIRule(r config.SNIRuleConfig) error {
	domainsJSON, err := json.Marshal(r.Domains)
	if err != nil {
		return fmt.Errorf("statsdb: marshal domains: %w", err)
	}

	res, err := s.db.Exec(
		`UPDATE routing_sni_rules SET action = ?, upstream_group = ?, domains_json = ?, updated_unix = unixepoch()
		 WHERE name = ?`,
		r.Action, r.UpstreamGroup, string(domainsJSON), r.Name,
	)
	if err != nil {
		return fmt.Errorf("statsdb: update sni rule %q: %w", r.Name, err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("statsdb: sni rule %q not found", r.Name)
	}
	return nil
}

// ImportSNIRules inserts SNI routing rules from a list, skipping names that already exist.
func (s *Store) ImportSNIRules(rules []config.SNIRuleConfig) (int, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, fmt.Errorf("statsdb: begin tx: %w", err)
	}
	defer tx.Rollback()

	var maxPriority int
	err = tx.QueryRow(`SELECT COALESCE(MAX(priority), -1) FROM routing_sni_rules`).Scan(&maxPriority)
	if err != nil {
		return 0, fmt.Errorf("statsdb: get max priority: %w", err)
	}

	stmt, err := tx.Prepare(
		`INSERT OR IGNORE INTO routing_sni_rules (name, action, upstream_group, domains_json, priority)
		 VALUES (?, ?, ?, ?, ?)`)
	if err != nil {
		return 0, fmt.Errorf("statsdb: prepare import sni rules: %w", err)
	}
	defer stmt.Close()

	var count int
	for _, r := range rules {
		domainsJSON, err := json.Marshal(r.Domains)
		if err != nil {
			return 0, fmt.Errorf("statsdb: marshal domains for %q: %w", r.Name, err)
		}
		maxPriority++
		res, err := stmt.Exec(r.Name, r.Action, r.UpstreamGroup, string(domainsJSON), maxPriority)
		if err != nil {
			return 0, fmt.Errorf("statsdb: import sni rule %q: %w", r.Name, err)
		}
		n, _ := res.RowsAffected()
		count += int(n)
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("statsdb: commit import sni rules: %w", err)
	}
	return count, nil
}

// ---------------------------------------------------------------------------
// Ownership helpers
// ---------------------------------------------------------------------------

// SetPeerOwner sets the owner_user_id for a peer.
func (s *Store) SetPeerOwner(name string, ownerID int64) error {
	_, err := s.db.Exec(`UPDATE wg_peers SET owner_user_id = ? WHERE name = ?`, ownerID, name)
	if err != nil {
		return fmt.Errorf("statsdb: set peer owner %q: %w", name, err)
	}
	return nil
}

// GetPeerOwner returns the owner_user_id for a peer. Returns nil if unowned or not found.
func (s *Store) GetPeerOwner(name string) (*int64, error) {
	var ownerID sql.NullInt64
	err := s.db.QueryRow(`SELECT owner_user_id FROM wg_peers WHERE name = ?`, name).Scan(&ownerID)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("statsdb: get peer owner %q: %w", name, err)
	}
	if !ownerID.Valid {
		return nil, nil
	}
	return &ownerID.Int64, nil
}

// CountPeersByOwner returns the number of peers owned by a user.
func (s *Store) CountPeersByOwner(ownerID int64) (int, error) {
	var count int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM wg_peers WHERE owner_user_id = ?`, ownerID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("statsdb: count peers by owner %d: %w", ownerID, err)
	}
	return count, nil
}

// ListPeerNamesByOwner returns the set of peer names owned by a user.
func (s *Store) ListPeerNamesByOwner(ownerID int64) (map[string]struct{}, error) {
	rows, err := s.db.Query(`SELECT name FROM wg_peers WHERE owner_user_id = ?`, ownerID)
	if err != nil {
		return nil, fmt.Errorf("statsdb: list peers by owner %d: %w", ownerID, err)
	}
	defer rows.Close()

	out := make(map[string]struct{})
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("statsdb: scan peer name: %w", err)
		}
		out[name] = struct{}{}
	}
	return out, rows.Err()
}

// SetSecretOwner sets the owner_user_id for a secret.
func (s *Store) SetSecretOwner(secretHex string, ownerID int64) error {
	_, err := s.db.Exec(`UPDATE mtproxy_secrets SET owner_user_id = ? WHERE secret_hex = ?`, ownerID, secretHex)
	if err != nil {
		return fmt.Errorf("statsdb: set secret owner %q: %w", secretHex, err)
	}
	return nil
}

// GetSecretOwner returns the owner_user_id for a secret. Returns nil if unowned or not found.
func (s *Store) GetSecretOwner(secretHex string) (*int64, error) {
	var ownerID sql.NullInt64
	err := s.db.QueryRow(`SELECT owner_user_id FROM mtproxy_secrets WHERE secret_hex = ?`, secretHex).Scan(&ownerID)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("statsdb: get secret owner %q: %w", secretHex, err)
	}
	if !ownerID.Valid {
		return nil, nil
	}
	return &ownerID.Int64, nil
}

// CountSecretsByOwner returns the number of secrets owned by a user.
func (s *Store) CountSecretsByOwner(ownerID int64) (int, error) {
	var count int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM mtproxy_secrets WHERE owner_user_id = ?`, ownerID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("statsdb: count secrets by owner %d: %w", ownerID, err)
	}
	return count, nil
}

// ListSecretHexByOwner returns the set of secret hex strings owned by a user.
func (s *Store) ListSecretHexByOwner(ownerID int64) (map[string]struct{}, error) {
	rows, err := s.db.Query(`SELECT secret_hex FROM mtproxy_secrets WHERE owner_user_id = ?`, ownerID)
	if err != nil {
		return nil, fmt.Errorf("statsdb: list secrets by owner %d: %w", ownerID, err)
	}
	defer rows.Close()

	out := make(map[string]struct{})
	for rows.Next() {
		var hex string
		if err := rows.Scan(&hex); err != nil {
			return nil, fmt.Errorf("statsdb: scan secret hex: %w", err)
		}
		out[hex] = struct{}{}
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------------
// Invite Links
// ---------------------------------------------------------------------------

// CreateInviteLink creates a new one-time invite link.
func (s *Store) CreateInviteLink(token, role string, createdBy int64) error {
	_, err := s.db.Exec(
		`INSERT INTO invite_links (token, role, created_by) VALUES (?, ?, ?)`,
		token, role, createdBy,
	)
	if err != nil {
		return fmt.Errorf("statsdb: create invite link: %w", err)
	}
	return nil
}

// ListInviteLinks returns all invite links ordered by creation time.
func (s *Store) ListInviteLinks() ([]InviteLink, error) {
	rows, err := s.db.Query(
		`SELECT token, role, created_by, created_unix FROM invite_links ORDER BY created_unix DESC`)
	if err != nil {
		return nil, fmt.Errorf("statsdb: list invite links: %w", err)
	}
	defer rows.Close()

	var out []InviteLink
	for rows.Next() {
		var l InviteLink
		if err := rows.Scan(&l.Token, &l.Role, &l.CreatedBy, &l.CreatedAt); err != nil {
			return nil, fmt.Errorf("statsdb: scan invite link: %w", err)
		}
		out = append(out, l)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statsdb: iterate invite links: %w", err)
	}
	return out, nil
}

// UseInviteLink atomically retrieves and deletes an invite link. Returns the link and true if found.
func (s *Store) UseInviteLink(token string) (*InviteLink, bool, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, false, fmt.Errorf("statsdb: begin tx: %w", err)
	}
	defer tx.Rollback()

	var l InviteLink
	err = tx.QueryRow(
		`SELECT token, role, created_by, created_unix FROM invite_links WHERE token = ?`, token,
	).Scan(&l.Token, &l.Role, &l.CreatedBy, &l.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("statsdb: get invite link: %w", err)
	}

	if _, err := tx.Exec(`DELETE FROM invite_links WHERE token = ?`, token); err != nil {
		return nil, false, fmt.Errorf("statsdb: delete invite link: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, false, fmt.Errorf("statsdb: commit: %w", err)
	}
	return &l, true, nil
}

// RedeemInvite atomically uses an invite token and adds the user as allowed.
// Returns the granted role.
func (s *Store) RedeemInvite(token string, userID int64, username, firstName, lastName string) (string, error) {
	invite, found, err := s.UseInviteLink(token)
	if err != nil {
		return "", err
	}
	if !found {
		return "", fmt.Errorf("invite not found or already used")
	}

	u := AllowedUser{
		UserID:    userID,
		Role:      invite.Role,
		Username:  username,
		FirstName: firstName,
		LastName:  lastName,
	}
	if err := s.AddAllowedUser(u); err != nil {
		return "", err
	}

	return invite.Role, nil
}

// DeleteInviteLink deletes an invite link by token.
func (s *Store) DeleteInviteLink(token string) (bool, error) {
	res, err := s.db.Exec(`DELETE FROM invite_links WHERE token = ?`, token)
	if err != nil {
		return false, fmt.Errorf("statsdb: delete invite link: %w", err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// ---------------------------------------------------------------------------
// Creation-order helpers
// ---------------------------------------------------------------------------

// namesOrdered runs a query that returns a single TEXT column and collects the
// results into an ordered slice.
func (s *Store) namesOrdered(query string) ([]string, error) {
	rows, err := s.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		out = append(out, name)
	}
	return out, rows.Err()
}

// PeerNamesOrdered returns peer names sorted by creation time (oldest first).
func (s *Store) PeerNamesOrdered() ([]string, error) {
	return s.namesOrdered(`SELECT name FROM wg_peers ORDER BY created_unix ASC`)
}

// UpstreamNamesOrdered returns upstream names sorted by creation time (oldest first).
func (s *Store) UpstreamNamesOrdered() ([]string, error) {
	return s.namesOrdered(`SELECT name FROM upstreams ORDER BY created_unix ASC`)
}

// ProxyNamesOrdered returns proxy server names sorted by creation time (oldest first).
func (s *Store) ProxyNamesOrdered() ([]string, error) {
	return s.namesOrdered(`SELECT name FROM proxy_servers ORDER BY created_unix ASC`)
}

// SecretHexOrdered returns secret hex strings sorted by creation time (oldest first).
func (s *Store) SecretHexOrdered() ([]string, error) {
	return s.namesOrdered(`SELECT secret_hex FROM mtproxy_secrets ORDER BY created_unix ASC`)
}

// DNSRecordNamesOrdered returns DNS record names sorted by creation time (oldest first).
func (s *Store) DNSRecordNamesOrdered() ([]string, error) {
	return s.namesOrdered(`SELECT name FROM dns_records ORDER BY created_unix ASC`)
}
