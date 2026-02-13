package routing

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/blikh/wireguard-outline-bridge/internal/config"
)

type StreamDialer interface {
	DialStream(ctx context.Context, addr string) (net.Conn, error)
}

type listEntry struct {
	url       string
	refresh   time.Duration
	lastFetch time.Time
}

type Downloader struct {
	httpClient *http.Client
	router     *Router
	lists      []listEntry
	logger     *slog.Logger
	mu         sync.Mutex
}

func NewDownloader(dialer StreamDialer, router *Router, cfg config.RoutingConfig, logger *slog.Logger) *Downloader {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.DialStream(ctx, addr)
		},
	}

	d := &Downloader{
		httpClient: &http.Client{Transport: tr},
		router:     router,
		logger:     logger,
	}

	for _, rule := range cfg.IPRules {
		for _, list := range rule.Lists {
			refresh := time.Duration(list.Refresh) * time.Second
			if refresh == 0 {
				refresh = 86400 * time.Second
			}
			d.lists = append(d.lists, listEntry{
				url:     list.URL,
				refresh: refresh,
			})
		}
	}

	return d
}

func (d *Downloader) Start(ctx context.Context) {
	for i := range d.lists {
		entry := &d.lists[i]
		prefixes, err := d.fetchList(ctx, entry.url)
		if err != nil {
			d.logger.Error("routing: failed to fetch IP list", "url", entry.url, "err", err)
			continue
		}
		d.router.UpdateIPList(entry.url, prefixes)
		d.logger.Info("routing: loaded IP list", "url", entry.url, "prefixes", len(prefixes))
		entry.lastFetch = time.Now()
	}

	if len(d.lists) == 0 {
		return
	}

	go d.refreshLoop(ctx)
}

func (d *Downloader) refreshLoop(ctx context.Context) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.mu.Lock()
			now := time.Now()
			for i := range d.lists {
				entry := &d.lists[i]
				if now.Sub(entry.lastFetch) < entry.refresh {
					continue
				}
				prefixes, err := d.fetchList(ctx, entry.url)
				if err != nil {
					d.logger.Error("routing: failed to refresh IP list", "url", entry.url, "err", err)
					continue
				}
				d.router.UpdateIPList(entry.url, prefixes)
				d.logger.Info("routing: refreshed IP list", "url", entry.url, "prefixes", len(prefixes))
				entry.lastFetch = now
			}
			d.mu.Unlock()
		}
	}
}

func (d *Downloader) fetchList(ctx context.Context, url string) ([]netip.Prefix, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching list: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var prefixes []netip.Prefix
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		prefix, err := netip.ParsePrefix(line)
		if err != nil {
			d.logger.Warn("routing: invalid CIDR in list", "url", url, "line", line, "err", err)
			continue
		}
		prefixes = append(prefixes, prefix)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	return prefixes, nil
}
