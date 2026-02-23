package statsdb

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/bigbes/wireguard-outline-bridge/internal/config"
)

// Store is a SQLite-backed persistent stats store.
type Store struct {
	db     *sql.DB
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

	s := &Store{db: db, logger: logger}
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
  outline TEXT NOT NULL DEFAULT '',
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
		`SELECT name, private_key, public_key, preshared_key, allowed_ips, disabled
		 FROM wg_peers`)
	if err != nil {
		return nil, fmt.Errorf("statsdb: list peers: %w", err)
	}
	defer rows.Close()

	out := make(map[string]config.PeerConfig)
	for rows.Next() {
		var name string
		var p config.PeerConfig
		var disabled int
		if err := rows.Scan(&name, &p.PrivateKey, &p.PublicKey, &p.PresharedKey, &p.AllowedIPs, &disabled); err != nil {
			return nil, fmt.Errorf("statsdb: scan peer: %w", err)
		}
		p.Disabled = disabled != 0
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
	_, err := s.db.Exec(
		`INSERT INTO wg_peers (name, private_key, public_key, preshared_key, allowed_ips, disabled)
		 VALUES (?, ?, ?, ?, ?, ?)
		 ON CONFLICT(name) DO UPDATE SET
		   private_key = excluded.private_key,
		   public_key = excluded.public_key,
		   preshared_key = excluded.preshared_key,
		   allowed_ips = excluded.allowed_ips,
		   disabled = excluded.disabled,
		   updated_unix = unixepoch()`,
		name, peer.PrivateKey, peer.PublicKey, peer.PresharedKey, peer.AllowedIPs, disabled,
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

// ImportPeers inserts peers from a map, skipping names that already exist.
func (s *Store) ImportPeers(peers map[string]config.PeerConfig) (int, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, fmt.Errorf("statsdb: begin tx: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(
		`INSERT OR IGNORE INTO wg_peers (name, private_key, public_key, preshared_key, allowed_ips, disabled)
		 VALUES (?, ?, ?, ?, ?, ?)`)
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
		res, err := stmt.Exec(name, p.PrivateKey, p.PublicKey, p.PresharedKey, p.AllowedIPs, disabled)
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

// ---------------------------------------------------------------------------
// Proxy Server CRUD
// ---------------------------------------------------------------------------

// ListProxyServers returns all proxy server configs from the database.
func (s *Store) ListProxyServers() ([]config.ProxyServerConfig, error) {
	rows, err := s.db.Query(
		`SELECT name, type, listen, outline, username, password,
		        tls_cert_file, tls_key_file, tls_domain, tls_acme_email
		 FROM proxy_servers`)
	if err != nil {
		return nil, fmt.Errorf("statsdb: list proxy servers: %w", err)
	}
	defer rows.Close()

	var out []config.ProxyServerConfig
	for rows.Next() {
		var p config.ProxyServerConfig
		if err := rows.Scan(&p.Name, &p.Type, &p.Listen, &p.Outline,
			&p.Username, &p.Password,
			&p.TLS.CertFile, &p.TLS.KeyFile, &p.TLS.Domain, &p.TLS.ACMEEmail); err != nil {
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
		`INSERT INTO proxy_servers (name, type, listen, outline, username, password,
		                            tls_cert_file, tls_key_file, tls_domain, tls_acme_email)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		p.Name, p.Type, p.Listen, p.Outline, p.Username, p.Password,
		p.TLS.CertFile, p.TLS.KeyFile, p.TLS.Domain, p.TLS.ACMEEmail,
	)
	if err != nil {
		return fmt.Errorf("statsdb: add proxy server %q: %w", p.Name, err)
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
		`INSERT OR IGNORE INTO proxy_servers (name, type, listen, outline, username, password,
		                                      tls_cert_file, tls_key_file, tls_domain, tls_acme_email)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return 0, fmt.Errorf("statsdb: prepare import proxy servers: %w", err)
	}
	defer stmt.Close()

	var count int
	for _, p := range proxies {
		res, err := stmt.Exec(p.Name, p.Type, p.Listen, p.Outline, p.Username, p.Password,
			p.TLS.CertFile, p.TLS.KeyFile, p.TLS.Domain, p.TLS.ACMEEmail)
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
		`SELECT user_id, username, first_name, last_name, photo_url, role, created_unix
		 FROM allowed_users ORDER BY created_unix DESC`)
	if err != nil {
		return nil, fmt.Errorf("statsdb: list allowed users: %w", err)
	}
	defer rows.Close()

	var out []AllowedUser
	for rows.Next() {
		var u AllowedUser
		if err := rows.Scan(&u.UserID, &u.Username, &u.FirstName, &u.LastName, &u.PhotoURL, &u.Role, &u.CreatedAt); err != nil {
			return nil, fmt.Errorf("statsdb: scan allowed user: %w", err)
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
		`INSERT INTO allowed_users (user_id, username, first_name, last_name, photo_url, role)
		 VALUES (?, ?, ?, ?, ?, ?)
		 ON CONFLICT(user_id) DO UPDATE SET
		   username = excluded.username,
		   first_name = excluded.first_name,
		   last_name = excluded.last_name,
		   photo_url = excluded.photo_url,
		   role = excluded.role`,
		u.UserID, u.Username, u.FirstName, u.LastName, u.PhotoURL, role,
	)
	if err != nil {
		return fmt.Errorf("statsdb: add allowed user %d: %w", u.UserID, err)
	}
	return nil
}

// GetUserRole returns the role of a user, or empty string if not found.
func (s *Store) GetUserRole(userID int64) (string, error) {
	var role string
	err := s.db.QueryRow(`SELECT role FROM allowed_users WHERE user_id = ?`, userID).Scan(&role)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("statsdb: get user role %d: %w", userID, err)
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
		`SELECT name, action, upstream, domains_json, lists_json
		 FROM dns_rules ORDER BY priority ASC, created_unix ASC`)
	if err != nil {
		return nil, fmt.Errorf("statsdb: list dns rules: %w", err)
	}
	defer rows.Close()

	var out []config.DNSRuleConfig
	for rows.Next() {
		var r config.DNSRuleConfig
		var domainsJSON, listsJSON string
		if err := rows.Scan(&r.Name, &r.Action, &r.Upstream, &domainsJSON, &listsJSON); err != nil {
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

	_, err = s.db.Exec(
		`INSERT INTO dns_rules (name, action, upstream, domains_json, lists_json, priority)
		 VALUES (?, ?, ?, ?, ?, COALESCE((SELECT MAX(priority) FROM dns_rules), -1) + 1)`,
		r.Name, r.Action, r.Upstream, string(domainsJSON), string(listsJSON),
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
		`INSERT OR IGNORE INTO dns_rules (name, action, upstream, domains_json, lists_json, priority)
		 VALUES (?, ?, ?, ?, ?, ?)`)
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
		maxPriority++
		res, err := stmt.Exec(r.Name, r.Action, r.Upstream, string(domainsJSON), string(listsJSON), maxPriority)
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
