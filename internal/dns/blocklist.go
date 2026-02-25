package dns

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

type ListEntry struct {
	URL       string
	Format    string // "hosts", "domains", or "auto" (default: auto-detect)
	Refresh   time.Duration
	lastFetch time.Time
}

type BlocklistLoader struct {
	httpClient *http.Client
	lists      []ListEntry
	logger     *slog.Logger

	mu      sync.RWMutex
	domains map[string]bool // blocked domain FQDNs (lowercased, with trailing dot)
}

func NewBlocklistLoader(lists []ListEntry, logger *slog.Logger) *BlocklistLoader {
	return &BlocklistLoader{
		httpClient: &http.Client{Timeout: 30 * time.Second},
		lists:      lists,
		logger:     logger,
		domains:    make(map[string]bool),
	}
}

// IsBlocked checks if a domain (FQDN with trailing dot, lowercased) is in the blocklist.
func (bl *BlocklistLoader) IsBlocked(fqdn string) bool {
	bl.mu.RLock()
	defer bl.mu.RUnlock()
	return bl.domains[fqdn]
}

// Start begins fetching all lists asynchronously, then starts a refresh goroutine.
// The initial download runs in a background goroutine so the caller is never
// blocked on network I/O.
func (bl *BlocklistLoader) Start(ctx context.Context) {
	if len(bl.lists) == 0 {
		return
	}
	go func() {
		bl.fetchAll(ctx)
		bl.refreshLoop(ctx)
	}()
}

func (bl *BlocklistLoader) fetchAll(ctx context.Context) {
	allDomains := make(map[string]bool)
	for i := range bl.lists {
		entry := &bl.lists[i]
		domains, err := bl.fetchList(ctx, entry.URL, entry.Format)
		if err != nil {
			bl.logger.Error("dns: failed to fetch blocklist", "url", entry.URL, "err", err)
			continue
		}
		for _, d := range domains {
			allDomains[d] = true
		}
		bl.logger.Info("dns: loaded blocklist", "url", entry.URL, "domains", len(domains))
		entry.lastFetch = time.Now()
	}

	bl.mu.Lock()
	bl.domains = allDomains
	bl.mu.Unlock()
}

func (bl *BlocklistLoader) refreshLoop(ctx context.Context) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()
			needsRefresh := false
			for i := range bl.lists {
				if now.Sub(bl.lists[i].lastFetch) >= bl.lists[i].Refresh {
					needsRefresh = true
					break
				}
			}
			if !needsRefresh {
				continue
			}

			allDomains := make(map[string]bool)
			for i := range bl.lists {
				entry := &bl.lists[i]
				domains, err := bl.fetchList(ctx, entry.URL, entry.Format)
				if err != nil {
					bl.logger.Error("dns: failed to refresh blocklist", "url", entry.URL, "err", err)
					continue
				}
				for _, d := range domains {
					allDomains[d] = true
				}
				bl.logger.Info("dns: refreshed blocklist", "url", entry.URL, "domains", len(domains))
				entry.lastFetch = now
			}

			bl.mu.Lock()
			bl.domains = allDomains
			bl.mu.Unlock()
		}
	}
}

func (bl *BlocklistLoader) fetchList(ctx context.Context, url, format string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	resp, err := bl.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching blocklist: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var domains []string
	detected := format
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}

		// Auto-detect format from the first meaningful line.
		if detected == "" || detected == "auto" {
			detected = detectBlocklistFormat(line)
			bl.logger.Debug("dns: auto-detected blocklist format", "url", url, "format", detected)
		}

		var domain string
		if detected == "hosts" {
			// Hosts format: "0.0.0.0 domain.com" or "127.0.0.1 domain.com"
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			domain = fields[1]
			// Skip localhost entries
			if domain == "localhost" || domain == "localhost.localdomain" ||
				domain == "local" || domain == "broadcasthost" {
				continue
			}
		} else {
			// Domain list format: one domain per line
			// Handle wildcard entries like "*.example.com" -> "example.com"
			domain = strings.TrimPrefix(line, "*.")
		}

		domain = strings.ToLower(domain)
		if !strings.HasSuffix(domain, ".") {
			domain += "."
		}
		domains = append(domains, domain)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	return domains, nil
}

// detectBlocklistFormat guesses the format from the first non-comment line.
// If the first field is an IP address (e.g. 0.0.0.0, 127.0.0.1, ::1), it's a hosts file.
func detectBlocklistFormat(line string) string {
	fields := strings.Fields(line)
	if len(fields) >= 2 {
		if _, err := netip.ParseAddr(fields[0]); err == nil {
			return "hosts"
		}
	}
	return "domains"
}
