package telegram

import (
	"fmt"
	"maps"
	"math/rand/v2"
	"sync"
)

// Source: https://github.com/telegramdesktop/tdesktop/blob/master/Telegram/SourceFiles/mtproto/mtproto_dc_options.cpp

// DefaultEndpoints contains the well-known Telegram DC IPv4 endpoints (production).
var DefaultEndpoints = map[int][]string{
	1:  {"149.154.175.50:443"},
	2:  {"149.154.167.51:443", "95.161.76.100:443"},
	3:  {"149.154.175.100:443"},
	4:  {"149.154.167.91:443"},
	5:  {"149.154.171.5:443"},
	-1: {"149.154.175.50:443"},
	-2: {"149.154.167.51:443", "95.161.76.100:443"},
	-3: {"149.154.175.100:443"},
}

// DefaultEndpointsIPv6 contains the well-known Telegram DC IPv6 endpoints (production).
var DefaultEndpointsIPv6 = map[int][]string{
	1: {"[2001:0b28:f23d:f001::a]:443"},
	2: {"[2001:067c:04e8:f002::a]:443"},
	3: {"[2001:0b28:f23d:f003::a]:443"},
	4: {"[2001:067c:04e8:f004::a]:443"},
	5: {"[2001:0b28:f23f:f005::a]:443"},
}

// TestEndpoints contains the Telegram DC IPv4 endpoints for test environment.
var TestEndpoints = map[int][]string{
	1: {"149.154.175.10:443"},
	2: {"149.154.167.40:443"},
	3: {"149.154.175.117:443"},
}

// TestEndpointsIPv6 contains the Telegram DC IPv6 endpoints for test environment.
var TestEndpointsIPv6 = map[int][]string{
	1: {"[2001:0b28:f23d:f001::e]:443"},
	2: {"[2001:067c:04e8:f002::e]:443"},
	3: {"[2001:0b28:f23d:f003::e]:443"},
}

// PublicRSAKey is the production Telegram RSA public key.
var PublicRSAKey = `-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEA6LszBcC1LGzyr992NzE0ieY+BSaOW622Aa9Bd4ZHLl+TuFQ4lo4g
5nKaMBwK/BIb9xUfg0Q29/2mgIR6Zr9krM7HjuIcCzFvDtr+L0GQjae9H0pRB2OO
62cECs5HKhT5DZ98K33vmWiLowc621dQuwKWSQKjWf50XYFw42h21P2KXUGyp2y/
+aEyZ+uVgLLQbRA1dEjSDZ2iGRy12Mk5gpYc397aYp438fsJoHIgJ2lgMv5h7WY9
t6N/byY9Nw9p21Og3AoXSL2q/2IJ1WRUhebgAdGVMlV1fkuOQoEzR7EdpqtQD9Cs
5+bfo3Nhmcyvk5ftB0WkJ9z6bNZ7yxrP8wIDAQAB
-----END RSA PUBLIC KEY-----`

// TestRSAKey is the Telegram RSA public key for test environment.
var TestRSAKey = `-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAyMEdY1aR+sCR3ZSJrtztKTKqigvO/vBfqACJLZtS7QMgCGXJ6XIR
yy7mx66W0/sOFa7/1mAZtEoIokDP3ShoqF4fVNb6XeqgQfaUHd8wJpDWHcR2OFwv
plUUI1PLTktZ9uW2WE23b+ixNwJjJGwBDJPQEQFBE+vfmH0JP503wr5INS1poWg/
j25sIWeYPHYeOrFp/eXaqhISP6G+q2IeTaWTXpwZj4LzXq5YOpk4bYEQ6mvRq7D1
aHWfYmlEGepfaYR8Q0YqvvhYtMte3ITnuSJs171+GDqpdKcSwHnd6FudwGO4pcCO
j4WcDuXc2CTHgH8gFTNhp/Y8/SpDOhvn9QIDAQAB
-----END RSA PUBLIC KEY-----`

// EndpointManager resolves DC IDs to backend addresses.
type EndpointManager struct {
	mu        sync.RWMutex
	endpoints map[int][]string
}

// NewEndpointManager creates an endpoint manager with the given DC endpoints.
// Merges provided endpoints with defaults (provided takes priority).
func NewEndpointManager(configured map[int][]string) *EndpointManager {
	merged := make(map[int][]string)
	maps.Copy(merged, DefaultEndpoints)
	maps.Copy(merged, configured)
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
