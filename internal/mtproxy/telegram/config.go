package telegram

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"maps"
	"net/http"
	"strconv"
	"strings"
)

const proxyConfigURL = "https://core.telegram.org/getProxyConfig"

// FetchEndpoints downloads proxy-multi.conf from Telegram and returns
// DC ID -> addresses mapping.
func FetchEndpoints(ctx context.Context) (map[int][]string, error) {
	return fetchEndpoints(ctx)
}

func fetchEndpoints(ctx context.Context) (map[int][]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, proxyConfigURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sending request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	return parseProxyConfig(resp.Body)
}

func parseProxyConfig(r io.Reader) (map[int][]string, error) {
	endpoints := make(map[int][]string)
	scanner := bufio.NewScanner(r)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if !strings.HasPrefix(line, "proxy_for ") {
			continue
		}

		// proxy_for <dc_id> <addr:port>;
		line = strings.TrimSuffix(line, ";")
		parts := strings.Fields(line)
		if len(parts) != 3 {
			continue
		}

		dcID, err := strconv.Atoi(parts[1])
		if err != nil {
			continue
		}

		addr := parts[2]
		endpoints[dcID] = append(endpoints[dcID], addr)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanning config: %w", err)
	}

	return endpoints, nil
}

// Update replaces the endpoint map (merges with defaults, configured takes priority).
func (m *EndpointManager) Update(endpoints map[int][]string) {
	merged := make(map[int][]string)
	maps.Copy(merged, DefaultEndpoints)
	maps.Copy(merged, endpoints)

	m.mu.Lock()
	m.endpoints = merged
	m.mu.Unlock()
}
