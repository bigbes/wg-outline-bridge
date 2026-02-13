package geoip

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/oschwald/maxminddb-golang/v2"
)

// countryRecord is a minimal struct for fast MMDB decoding.
type countryRecord struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
}

// StreamDialer dials TCP connections, used for downloading MMDB via proxy.
type StreamDialer interface {
	DialStream(ctx context.Context, addr string) (net.Conn, error)
}

// DB holds a single GeoIP MMDB database with thread-safe reload support.
type DB struct {
	name    string
	source  string // local path or URL
	refresh time.Duration
	logger  *slog.Logger
	isURL   bool

	httpClient *http.Client

	mu     sync.RWMutex
	reader *maxminddb.Reader
}

func isURL(s string) bool {
	return strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")
}

func openDB(name, source string, refresh time.Duration, httpClient *http.Client, logger *slog.Logger) (*DB, error) {
	db := &DB{
		name:       name,
		source:     source,
		refresh:    refresh,
		logger:     logger,
		isURL:      isURL(source),
		httpClient: httpClient,
	}

	if err := db.load(); err != nil {
		return nil, err
	}

	return db, nil
}

func (db *DB) load() error {
	if db.isURL {
		return db.loadFromURL()
	}
	return db.loadFromFile()
}

func (db *DB) loadFromFile() error {
	reader, err := maxminddb.Open(db.source)
	if err != nil {
		return fmt.Errorf("opening geoip database %s: %w", db.source, err)
	}
	db.setReader(reader)
	db.logger.Info("geoip: database loaded", "name", db.name, "source", db.source, "type", reader.Metadata.DatabaseType)
	return nil
}

func (db *DB) loadFromURL() error {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, db.source, nil)
	if err != nil {
		return fmt.Errorf("creating request for geoip %s: %w", db.name, err)
	}

	resp, err := db.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("downloading geoip database %s: %w", db.name, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("downloading geoip database %s: HTTP %d", db.name, resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading geoip database %s: %w", db.name, err)
	}

	// Write to a temp file so maxminddb can mmap it.
	tmpFile, err := os.CreateTemp("", "geoip-*.mmdb")
	if err != nil {
		return fmt.Errorf("creating temp file for geoip %s: %w", db.name, err)
	}
	tmpPath := tmpFile.Name()

	if _, err := tmpFile.Write(data); err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("writing temp geoip file %s: %w", db.name, err)
	}
	tmpFile.Close()

	reader, err := maxminddb.Open(tmpPath)
	if err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("opening downloaded geoip database %s: %w", db.name, err)
	}

	db.setReader(reader)
	// Clean up the temp file after mmap (the reader holds a reference).
	os.Remove(tmpPath)

	db.logger.Info("geoip: database downloaded", "name", db.name, "source", db.source, "type", reader.Metadata.DatabaseType)
	return nil
}

func (db *DB) setReader(r *maxminddb.Reader) {
	db.mu.Lock()
	old := db.reader
	db.reader = r
	db.mu.Unlock()

	if old != nil {
		old.Close()
	}
}

// LookupCountry returns the ISO country code for the given IP address.
// Returns empty string if the IP is not found.
func (db *DB) LookupCountry(addr netip.Addr) string {
	db.mu.RLock()
	defer db.mu.RUnlock()

	var record countryRecord
	if err := db.reader.Lookup(addr).Decode(&record); err != nil {
		return ""
	}
	return record.Country.ISOCode
}

func (db *DB) reload() {
	if err := db.load(); err != nil {
		db.logger.Error("geoip: failed to reload database", "name", db.name, "err", err)
	}
}

// Close releases resources held by the database.
func (db *DB) Close() error {
	db.mu.Lock()
	defer db.mu.Unlock()
	if db.reader != nil {
		return db.reader.Close()
	}
	return nil
}

// Manager holds multiple named GeoIP databases and runs periodic refresh.
type Manager struct {
	dbs    map[string]*DB
	first  *DB // first database, used as default
	logger *slog.Logger
}

// NewManager creates a Manager and loads all configured GeoIP databases.
// The dialer is used for downloading URL-based databases via proxy.
func NewManager(cfgs []GeoIPEntry, dialer StreamDialer, logger *slog.Logger) (*Manager, error) {
	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				if dialer != nil {
					return dialer.DialStream(ctx, addr)
				}
				var d net.Dialer
				return d.DialContext(ctx, network, addr)
			},
		},
	}

	m := &Manager{
		dbs:    make(map[string]*DB),
		logger: logger,
	}

	for _, cfg := range cfgs {
		db, err := openDB(cfg.Name, cfg.Path, time.Duration(cfg.Refresh)*time.Second, httpClient, logger)
		if err != nil {
			m.Close()
			return nil, err
		}
		m.dbs[cfg.Name] = db
		if m.first == nil {
			m.first = db
		}
	}

	return m, nil
}

// GeoIPEntry represents a single GeoIP database configuration.
type GeoIPEntry struct {
	Name    string
	Path    string
	Refresh int // seconds
}

// LookupCountry looks up the country for addr using the named database.
// If dbName is empty, uses the first (default) database.
func (m *Manager) LookupCountry(dbName string, addr netip.Addr) string {
	if m == nil {
		return ""
	}
	var db *DB
	if dbName == "" {
		db = m.first
	} else {
		db = m.dbs[dbName]
	}
	if db == nil {
		return ""
	}
	return db.LookupCountry(addr)
}

// StartRefresh starts background refresh goroutines for all databases.
func (m *Manager) StartRefresh(ctx context.Context) {
	if m == nil {
		return
	}
	for _, db := range m.dbs {
		if db.refresh <= 0 {
			continue
		}
		go func(db *DB) {
			ticker := time.NewTicker(db.refresh)
			defer ticker.Stop()

			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					db.reload()
				}
			}
		}(db)
	}
}

// Close releases all database resources.
func (m *Manager) Close() error {
	if m == nil {
		return nil
	}
	var firstErr error
	for _, db := range m.dbs {
		if err := db.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
