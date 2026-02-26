package proxy

import (
	"net/netip"
	"strings"
	"sync"

	"github.com/bigbes/wireguard-outline-bridge/internal/config"
)

type peerRef struct {
	name string
	id   int
}

// PeerDNSNameResolver maps peer VPN IPs to peer names and IDs for
// DNS/routing rule filtering.
type PeerDNSNameResolver struct {
	mu    sync.RWMutex
	peers map[netip.Addr]peerRef
}

// NewPeerDNSNameResolver creates a new resolver.
func NewPeerDNSNameResolver() *PeerDNSNameResolver {
	return &PeerDNSNameResolver{
		peers: make(map[netip.Addr]peerRef),
	}
}

// Set sets the peer name and ID for a VPN IP.
func (r *PeerDNSNameResolver) Set(ip netip.Addr, name string, id int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.peers[ip] = peerRef{name: name, id: id}
}

// Delete removes the mapping for a VPN IP.
func (r *PeerDNSNameResolver) Delete(ip netip.Addr) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.peers, ip)
}

// NameFor returns the peer name for a VPN IP.
// Returns "" if no mapping exists.
func (r *PeerDNSNameResolver) NameFor(ip netip.Addr) string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.peers[ip].name
}

// IDFor returns the peer ID for a VPN IP.
// Returns 0, false if no mapping exists.
func (r *PeerDNSNameResolver) IDFor(ip netip.Addr) (int, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.peers[ip]
	return p.id, ok
}

// PopulateFromPeers rebuilds the resolver from the current peer config.
func (r *PeerDNSNameResolver) PopulateFromPeers(peers map[int]config.PeerConfig) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.peers = make(map[netip.Addr]peerRef)
	for _, peer := range peers {
		if peer.Disabled {
			continue
		}
		ref := peerRef{name: peer.Name, id: peer.ID}
		for prefix := range strings.SplitSeq(peer.AllowedIPs, ",") {
			prefix = strings.TrimSpace(prefix)
			if p, err := netip.ParsePrefix(prefix); err == nil {
				r.peers[p.Addr()] = ref
			} else if addr, err := netip.ParseAddr(prefix); err == nil {
				r.peers[addr] = ref
			}
		}
	}
}
