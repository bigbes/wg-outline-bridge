package statsdb

import (
	"database/sql"
	"fmt"
	"log/slog"
	"time"

	_ "modernc.org/sqlite"

	"github.com/blikh/wireguard-outline-bridge/internal/config"
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
);`
	if _, err := s.db.Exec(ddl); err != nil {
		return fmt.Errorf("statsdb: init schema: %w", err)
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

		lastConn := dbLastConn
		if p.LastConnectionUnix > dbLastConn {
			lastConn = p.LastConnectionUnix
		}

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
