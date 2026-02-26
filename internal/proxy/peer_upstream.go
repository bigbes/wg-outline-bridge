package proxy

import (
	"net/netip"
	"strings"
	"sync"

	"github.com/bigbes/wireguard-outline-bridge/internal/config"
)

// PeerUpstreamResolver maps peer VPN IPs to upstream group overrides.
type PeerUpstreamResolver struct {
	mu     sync.RWMutex
	groups map[netip.Addr]string
}

// NewPeerUpstreamResolver creates a new resolver.
func NewPeerUpstreamResolver() *PeerUpstreamResolver {
	return &PeerUpstreamResolver{
		groups: make(map[netip.Addr]string),
	}
}

// Set sets the upstream group for a peer IP. Empty group means "use default".
func (r *PeerUpstreamResolver) Set(ip netip.Addr, group string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if group == "" {
		delete(r.groups, ip)
	} else {
		r.groups[ip] = group
	}
}

// Delete removes the upstream group override for a peer IP.
func (r *PeerUpstreamResolver) Delete(ip netip.Addr) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.groups, ip)
}

// GroupFor returns the upstream group for a peer IP.
// Returns "" if no override is set (meaning "use default").
func (r *PeerUpstreamResolver) GroupFor(ip netip.Addr) string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.groups[ip]
}

// PopulateFromPeers rebuilds the resolver from the current peer config.
func (r *PeerUpstreamResolver) PopulateFromPeers(peers map[int]config.PeerConfig) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.groups = make(map[netip.Addr]string)
	for _, peer := range peers {
		if peer.UpstreamGroup == "" || peer.Disabled {
			continue
		}
		for prefix := range strings.SplitSeq(peer.AllowedIPs, ",") {
			prefix = strings.TrimSpace(prefix)
			if p, err := netip.ParsePrefix(prefix); err == nil {
				r.groups[p.Addr()] = peer.UpstreamGroup
			} else if addr, err := netip.ParseAddr(prefix); err == nil {
				r.groups[addr] = peer.UpstreamGroup
			}
		}
	}
}
