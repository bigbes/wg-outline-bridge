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
	"path/filepath"
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
	name      string
	source    string // local path or URL
	cachePath string // persistent cache file path for URL sources
	refresh   time.Duration
	logger    *slog.Logger
	isURL     bool

	httpClient *http.Client

	mu     sync.RWMutex
	reader *maxminddb.Reader
}

func isURL(s string) bool {
	return strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")
}

func openDB(name, source, cacheDir string, refresh time.Duration, httpClient *http.Client, logger *slog.Logger) (*DB, error) {
	db := &DB{
		name:       name,
		source:     source,
		refresh:    refresh,
		logger:     logger,
		isURL:      isURL(source),
		httpClient: httpClient,
	}

	if db.isURL && cacheDir != "" {
		db.cachePath = filepath.Join(cacheDir, name+".mmdb")
	}

	if err := db.load(); err != nil {
		return nil, err
	}

	return db, nil
}

func (db *DB) load() error {
	if db.isURL {
		return db.loadFromURL(false)
	}
	return db.loadFromFile(db.source)
}

func (db *DB) loadFromFile(path string) error {
	reader, err := maxminddb.Open(path)
	if err != nil {
		return fmt.Errorf("opening geoip database %s: %w", path, err)
	}
	db.setReader(reader)
	db.logger.Info("geoip: database loaded", "name", db.name, "path", path, "type", reader.Metadata.DatabaseType)
	return nil
}

func (db *DB) loadFromURL(isRefresh bool) error {
	// On initial load, try cached file first.
	if !isRefresh && db.cachePath != "" {
		if _, err := os.Stat(db.cachePath); err == nil {
			if err := db.loadFromFile(db.cachePath); err == nil {
				db.logger.Info("geoip: loaded from cache", "name", db.name, "cache", db.cachePath)
				return nil
			}
			db.logger.Warn("geoip: cached file invalid, will download", "name", db.name, "cache", db.cachePath)
		}
	}

	data, err := db.download()
	if err != nil {
		return err
	}

	return db.openAndCache(data)
}

func (db *DB) download() ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, db.source, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request for geoip %s: %w", db.name, err)
	}

	resp, err := db.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("downloading geoip database %s: %w", db.name, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("downloading geoip database %s: HTTP %d", db.name, resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading geoip database %s: %w", db.name, err)
	}

	return data, nil
}

func (db *DB) openAndCache(data []byte) error {
	// If we have a cache path, write there persistently.
	if db.cachePath != "" {
		if err := os.MkdirAll(filepath.Dir(db.cachePath), 0755); err != nil {
			return fmt.Errorf("creating cache dir for geoip %s: %w", db.name, err)
		}
		if err := atomicWriteFile(db.cachePath, data); err != nil {
			return fmt.Errorf("writing cache file for geoip %s: %w", db.name, err)
		}
		if err := db.loadFromFile(db.cachePath); err != nil {
			return fmt.Errorf("opening cached geoip database %s: %w", db.name, err)
		}
		db.logger.Info("geoip: database downloaded and cached", "name", db.name, "source", db.source, "cache", db.cachePath)
		return nil
	}

	// No cache path — use a temp file (deleted after mmap).
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
	os.Remove(tmpPath)

	db.logger.Info("geoip: database downloaded", "name", db.name, "source", db.source)
	return nil
}

// atomicWriteFile writes data to path atomically using a temp file + rename.
func atomicWriteFile(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".geoip-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return err
	}
	return os.Rename(tmpPath, path)
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
	var err error
	if db.isURL {
		err = db.loadFromURL(true)
	} else {
		err = db.loadFromFile(db.source)
	}
	if err != nil {
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
// cacheDir is used to persist downloaded MMDB files across restarts.
func NewManager(cfgs []GeoIPEntry, cacheDir string, dialer StreamDialer, logger *slog.Logger) (*Manager, error) {
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
		db, err := openDB(cfg.Name, cfg.Path, cacheDir, time.Duration(cfg.Refresh)*time.Second, httpClient, logger)
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
