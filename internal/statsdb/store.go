package statsdb

import (
	"database/sql"
	"fmt"
	"log/slog"
	"time"

	_ "modernc.org/sqlite"
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
