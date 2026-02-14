package telegram

import (
	"fmt"
	"math/rand/v2"
	"sync"
)

// DefaultEndpoints contains the well-known Telegram DC endpoints.
var DefaultEndpoints = map[int][]string{
	1:  {"149.154.175.50:443"},
	2:  {"149.154.167.51:443"},
	3:  {"149.154.175.100:443"},
	4:  {"149.154.167.91:443"},
	5:  {"91.108.56.100:443"},
	-1: {"149.154.175.50:443"},
	-2: {"149.154.167.51:443"},
	-3: {"149.154.175.100:443"},
}

// EndpointManager resolves DC IDs to backend addresses.
type EndpointManager struct {
	mu        sync.RWMutex
	endpoints map[int][]string
}

// NewEndpointManager creates an endpoint manager with the given DC endpoints.
// Merges provided endpoints with defaults (provided takes priority).
func NewEndpointManager(configured map[int][]string) *EndpointManager {
	merged := make(map[int][]string)
	for dc, addrs := range DefaultEndpoints {
		merged[dc] = addrs
	}
	for dc, addrs := range configured {
		merged[dc] = addrs
	}
	return &EndpointManager{endpoints: merged}
}

// Resolve picks a random backend address for the given DC ID.
func (m *EndpointManager) Resolve(dcID int) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	addrs, ok := m.endpoints[dcID]
	if !ok || len(addrs) == 0 {
		if dcID < 0 {
			addrs, ok = m.endpoints[-dcID]
		}
		if !ok || len(addrs) == 0 {
			return "", fmt.Errorf("no endpoints for DC %d", dcID)
		}
	}

	return addrs[rand.IntN(len(addrs))], nil
}
