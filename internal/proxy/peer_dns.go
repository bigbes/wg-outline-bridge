package proxy

import (
	"net/netip"
	"strings"
	"sync"

	"github.com/bigbes/wireguard-outline-bridge/internal/config"
)

// PeerDNSNameResolver maps peer VPN IPs to peer names for DNS rule filtering.
type PeerDNSNameResolver struct {
	mu    sync.RWMutex
	names map[netip.Addr]string
}

// NewPeerDNSNameResolver creates a new resolver.
func NewPeerDNSNameResolver() *PeerDNSNameResolver {
	return &PeerDNSNameResolver{
		names: make(map[netip.Addr]string),
	}
}

// Set sets the peer name for a VPN IP.
func (r *PeerDNSNameResolver) Set(ip netip.Addr, name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.names[ip] = name
}

// Delete removes the mapping for a VPN IP.
func (r *PeerDNSNameResolver) Delete(ip netip.Addr) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.names, ip)
}

// NameFor returns the peer name for a VPN IP.
// Returns "" if no mapping exists.
func (r *PeerDNSNameResolver) NameFor(ip netip.Addr) string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.names[ip]
}

// PopulateFromPeers rebuilds the resolver from the current peer config.
func (r *PeerDNSNameResolver) PopulateFromPeers(peers map[string]config.PeerConfig) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.names = make(map[netip.Addr]string)
	for name, peer := range peers {
		if peer.Disabled {
			continue
		}
		for prefix := range strings.SplitSeq(peer.AllowedIPs, ",") {
			prefix = strings.TrimSpace(prefix)
			if p, err := netip.ParsePrefix(prefix); err == nil {
				r.names[p.Addr()] = name
			} else if addr, err := netip.ParseAddr(prefix); err == nil {
				r.names[addr] = name
			}
		}
	}
}
