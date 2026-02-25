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
	Format    string // "hosts", "domains", "domains-wildcards", "adblock", or "auto" (default: auto-detect)
	Refresh   time.Duration
	lastFetch time.Time
}

type BlocklistLoader struct {
	httpClient *http.Client
	lists      []ListEntry
	logger     *slog.Logger

	mu       sync.RWMutex
	domains  map[string]bool // blocked domain FQDNs (lowercased, with trailing dot)
	suffixes []string        // blocked domain suffixes for wildcard matching (e.g. ".example.com.")
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
	if bl.domains[fqdn] {
		return true
	}
	for _, suffix := range bl.suffixes {
		if strings.HasSuffix(fqdn, suffix) {
			return true
		}
	}
	return false
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
	var allSuffixes []string
	for i := range bl.lists {
		entry := &bl.lists[i]
		domains, suffixes, err := bl.fetchList(ctx, entry.URL, entry.Format)
		if err != nil {
			bl.logger.Error("dns: failed to fetch blocklist", "url", entry.URL, "err", err)
			continue
		}
		for _, d := range domains {
			allDomains[d] = true
		}
		allSuffixes = append(allSuffixes, suffixes...)
		bl.logger.Info("dns: loaded blocklist", "url", entry.URL, "domains", len(domains), "suffixes", len(suffixes))
		entry.lastFetch = time.Now()
	}

	bl.mu.Lock()
	bl.domains = allDomains
	bl.suffixes = allSuffixes
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
			var allSuffixes []string
			for i := range bl.lists {
				entry := &bl.lists[i]
				domains, suffixes, err := bl.fetchList(ctx, entry.URL, entry.Format)
				if err != nil {
					bl.logger.Error("dns: failed to refresh blocklist", "url", entry.URL, "err", err)
					continue
				}
				for _, d := range domains {
					allDomains[d] = true
				}
				allSuffixes = append(allSuffixes, suffixes...)
				bl.logger.Info("dns: refreshed blocklist", "url", entry.URL, "domains", len(domains), "suffixes", len(suffixes))
				entry.lastFetch = now
			}

			bl.mu.Lock()
			bl.domains = allDomains
			bl.suffixes = allSuffixes
			bl.mu.Unlock()
		}
	}
}

func (bl *BlocklistLoader) fetchList(ctx context.Context, url, format string) ([]string, []string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("creating request: %w", err)
	}

	resp, err := bl.httpClient.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("fetching blocklist: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var domains []string
	var suffixes []string
	detected := format
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Parse header comments for format hints before skipping them.
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			if detected == "" || detected == "auto" {
				if hint := detectHeaderSyntax(line); hint != "" {
					detected = hint
					bl.logger.Debug("dns: detected blocklist format from header", "url", url, "format", detected)
				}
			}
			continue
		}
		if line == "[Adblock Plus]" || line == "[Adblock]" {
			if detected == "" || detected == "auto" {
				detected = "adblock"
				bl.logger.Debug("dns: detected blocklist format from header", "url", url, "format", detected)
			}
			continue
		}

		// Auto-detect format from the first meaningful line.
		if detected == "" || detected == "auto" {
			detected = detectBlocklistFormat(line)
			bl.logger.Debug("dns: auto-detected blocklist format", "url", url, "format", detected)
		}

		var domain string
		isWildcard := false
		switch detected {
		case "hosts":
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
		case "adblock":
			domain = parseAdblockLine(line)
			if domain == "" {
				continue
			}
		case "domains-wildcards":
			// Domain list with wildcard support:
			// "*.example.com" blocks all subdomains of example.com
			// "example.com" blocks just that exact domain
			if strings.HasPrefix(line, "*.") {
				domain = line[2:]
				isWildcard = true
			} else {
				domain = line
			}
		default:
			// Domain list format: one domain per line
			// Handle wildcard entries like "*.example.com" -> "example.com"
			domain = strings.TrimPrefix(line, "*.")
		}

		domain = strings.ToLower(domain)
		if !strings.HasSuffix(domain, ".") {
			domain += "."
		}

		if isWildcard {
			// Store as suffix: ".example.com." to match "sub.example.com."
			suffixes = append(suffixes, "."+domain)
		} else {
			domains = append(domains, domain)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, fmt.Errorf("reading response body: %w", err)
	}

	return domains, suffixes, nil
}

// detectHeaderSyntax extracts the format from a comment header line like
// "# Syntax: Domains (including possible subdomains)" or "! Syntax: AdBlock".
func detectHeaderSyntax(line string) string {
	// Strip comment prefix (# or !)
	s := strings.TrimLeft(line, "#! ")
	// Look for "Syntax:" prefix (case-insensitive)
	if !strings.HasPrefix(strings.ToLower(s), "syntax:") {
		return ""
	}
	syntax := strings.ToLower(strings.TrimSpace(s[len("syntax:"):]))

	switch {
	case strings.Contains(syntax, "adblock") || strings.Contains(syntax, "adguard"):
		return "adblock"
	case strings.HasPrefix(syntax, "hosts"):
		return "hosts"
	case strings.HasPrefix(syntax, "domains"):
		if strings.Contains(syntax, "including") || strings.Contains(syntax, "wildcard") {
			return "domains-wildcards"
		}
		return "domains"
	}
	return ""
}

// detectBlocklistFormat guesses the format from the first non-comment line.
// If the line starts with "||", it's adblock format.
// If the first field is an IP address (e.g. 0.0.0.0, 127.0.0.1, ::1), it's a hosts file.
func detectBlocklistFormat(line string) string {
	if strings.HasPrefix(line, "||") {
		return "adblock"
	}
	fields := strings.Fields(line)
	if len(fields) >= 2 {
		if _, err := netip.ParseAddr(fields[0]); err == nil {
			return "hosts"
		}
	}
	return "domains"
}

// parseAdblockLine extracts a domain from an adblock-style rule.
// It handles "||domain.com^" style entries used by Pi-hole and similar tools.
// Returns empty string for unsupported rules (e.g. element hiding, exception rules).
func parseAdblockLine(line string) string {
	// Skip exception rules (@@||...)
	if strings.HasPrefix(line, "@@") {
		return ""
	}

	// Handle "||domain.com^" style blocking rules
	if !strings.HasPrefix(line, "||") {
		return ""
	}

	domain := strings.TrimPrefix(line, "||")

	// Remove trailing "^" and anything after it (e.g. "^$third-party")
	if idx := strings.IndexByte(domain, '^'); idx >= 0 {
		domain = domain[:idx]
	}

	// Skip rules with path separators or wildcards — not pure domain blocks
	if strings.ContainsAny(domain, "/*") {
		return ""
	}

	if domain == "" {
		return ""
	}

	return domain
}
