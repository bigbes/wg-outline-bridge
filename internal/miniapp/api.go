package miniapp

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	qrcode "github.com/skip2/go-qrcode"

	"github.com/bigbes/wireguard-outline-bridge/internal/config"
	"github.com/bigbes/wireguard-outline-bridge/internal/dns"
	"github.com/bigbes/wireguard-outline-bridge/internal/porttracker"
	"github.com/bigbes/wireguard-outline-bridge/internal/statsdb"
)

// sanitizeFilename returns a lowercase version of s with spaces replaced by underscores.
func sanitizeFilename(s string) string {
	return strings.ToLower(strings.ReplaceAll(s, " ", "_"))
}

const defaultGuestMaxPeers = 5
const defaultGuestMaxSecrets = 5

// sortByCreationOrder reorders items so that names appearing in order come
// first (in the given order) and unknown names are appended at the end.
func sortByCreationOrder[T any](items []T, nameFunc func(T) string, order []string) {
	orderMap := make(map[string]int, len(order))
	for i, name := range order {
		orderMap[name] = i
	}
	sort.SliceStable(items, func(i, j int) bool {
		oi, oki := orderMap[nameFunc(items[i])]
		oj, okj := orderMap[nameFunc(items[j])]
		if !oki {
			oi = len(order)
		}
		if !okj {
			oj = len(order)
		}
		return oi < oj
	})
}

type statusResponse struct {
	Daemon    daemonInfo             `json:"daemon"`
	Peers     []peerInfo             `json:"peers"`
	Upstreams []upstreamInfo         `json:"upstreams"`
	MTProxy   mtproxyInfo            `json:"mtproxy"`
	Proxies   []proxyInfo            `json:"proxies"`
	UsedPorts []porttracker.PortInfo `json:"used_ports"`
}

type daemonInfo struct {
	UptimeSeconds int64  `json:"uptime_seconds"`
	Version       string `json:"version"`
	Dirty         bool   `json:"dirty"`
}

type peerInfo struct {
	Name              string `json:"name"`
	PublicKey         string `json:"public_key"`
	AllowedIPs        string `json:"allowed_ips"`
	LastHandshake     int64  `json:"last_handshake_unix"`
	RxBytes           int64  `json:"rx_bytes"`
	TxBytes           int64  `json:"tx_bytes"`
	RxTotal           int64  `json:"rx_total"`
	TxTotal           int64  `json:"tx_total"`
	ActiveConnections int    `json:"active_connections"`
	ConnectionsTotal  int64  `json:"connections_total"`
	Disabled          bool   `json:"disabled"`
	ExcludePrivate    bool   `json:"exclude_private"`
	ExcludeServer     bool   `json:"exclude_server"`
	UpstreamGroup     string `json:"upstream_group"`
	OwnerID           int64  `json:"owner_id,omitempty"`
	OwnerName         string `json:"owner_name,omitempty"`
}

type mtproxyInfo struct {
	Enabled           bool               `json:"enabled"`
	Connections       int64              `json:"connections"`
	ActiveConnections int64              `json:"active_connections"`
	UniqueUsers       int64              `json:"unique_users"`
	BytesC2B          int64              `json:"bytes_c2b"`
	BytesB2C          int64              `json:"bytes_b2c"`
	BytesC2BTotal     int64              `json:"bytes_c2b_total"`
	BytesB2CTotal     int64              `json:"bytes_b2c_total"`
	Secrets           []secretInfo       `json:"secrets"`
	Links             []config.ProxyLink `json:"links"`
}

type secretInfo struct {
	Secret            string `json:"secret"`
	LastConnection    int64  `json:"last_connection_unix"`
	Connections       int64  `json:"connections"`
	ActiveConnections int64  `json:"active_connections"`
	UniqueUsers       int64  `json:"unique_users"`
	ConnectionsTotal  int64  `json:"connections_total"`
	BytesC2B          int64  `json:"bytes_c2b"`
	BytesB2C          int64  `json:"bytes_b2c"`
	UpstreamGroup     string `json:"upstream_group"`
	OwnerID           int64  `json:"owner_id,omitempty"`
	OwnerName         string `json:"owner_name,omitempty"`
}

type upstreamInfo struct {
	Name              string   `json:"name"`
	Type              string   `json:"type"`
	Enabled           bool     `json:"enabled"`
	Default           bool     `json:"default"`
	State             string   `json:"state"`
	Groups            []string `json:"groups"`
	RxBytes           int64    `json:"rx_bytes"`
	TxBytes           int64    `json:"tx_bytes"`
	ActiveConnections int64    `json:"active_connections"`
	LastError         string   `json:"last_error,omitempty"`
}

type proxyInfo struct {
	Name          string `json:"name"`
	Type          string `json:"type"`
	Listen        string `json:"listen"`
	UpstreamGroup string `json:"upstream_group,omitempty"`
	HasAuth       bool   `json:"has_auth"`
	Username      string `json:"username,omitempty"`
	Password      string `json:"password,omitempty"`
	Link          string `json:"link"`
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"user_id": requestUserID(r),
		"role":    requestUserRole(r),
	})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	peers := s.provider.PeerStatuses()
	daemon := s.provider.DaemonStatus()
	mt := s.provider.MTProxyStatus()
	cfg := s.cfgProv.CurrentConfig()

	var uptimeSec int64
	if !daemon.StartTime.IsZero() {
		uptimeSec = int64(time.Since(daemon.StartTime).Seconds())
	}

	// For guests, load owned resources to filter visibility.
	admin := isAdminRequest(r)
	var ownedPeers map[string]struct{}
	var ownedSecrets map[string]struct{}
	if !admin && s.store != nil {
		uid := requestUserID(r)
		ownedPeers, _ = s.store.ListPeerNamesByOwner(uid)
		ownedSecrets, _ = s.store.ListSecretHexByOwner(uid)
	}

	resp := statusResponse{
		Daemon: daemonInfo{
			UptimeSeconds: uptimeSec,
			Version:       daemon.Version,
			Dirty:         daemon.Dirty,
		},
	}

	// Peers.
	allPeers := cfg.Peers
	for _, p := range peers {
		if !admin {
			if _, ok := ownedPeers[p.Name]; !ok {
				continue
			}
		}
		pi := peerInfo{
			Name:              p.Name,
			PublicKey:         p.PublicKey,
			LastHandshake:     p.LastHandshake.Unix(),
			RxBytes:           p.RxBytes,
			TxBytes:           p.TxBytes,
			RxTotal:           p.RxTotal,
			TxTotal:           p.TxTotal,
			ActiveConnections: p.ActiveConnections,
			ConnectionsTotal:  p.ConnectionsTotal,
		}
		if pc, ok := allPeers[p.Name]; ok {
			pi.AllowedIPs = pc.AllowedIPs
			pi.Disabled = pc.Disabled
			pi.ExcludePrivate = pc.ExcludePrivate
			pi.ExcludeServer = pc.ExcludeServer
			pi.UpstreamGroup = pc.UpstreamGroup
		}
		resp.Peers = append(resp.Peers, pi)
	}

	// Upstreams.
	for _, u := range s.provider.UpstreamStatuses() {
		resp.Upstreams = append(resp.Upstreams, upstreamInfo{
			Name:              u.Name,
			Type:              u.Type,
			Enabled:           u.Enabled,
			Default:           u.Default,
			State:             u.State,
			Groups:            u.Groups,
			RxBytes:           u.RxBytes,
			TxBytes:           u.TxBytes,
			ActiveConnections: u.ActiveConnections,
			LastError:         u.LastError,
		})
	}

	// MTProxy.
	resp.MTProxy = mtproxyInfo{
		Enabled:           mt.Enabled,
		Connections:       mt.Connections,
		ActiveConnections: mt.ActiveConnections,
		UniqueUsers:       mt.UniqueUsers,
		BytesC2B:          mt.BytesC2B,
		BytesB2C:          mt.BytesB2C,
		BytesC2BTotal:     mt.BytesC2BTotal,
		BytesB2CTotal:     mt.BytesB2CTotal,
		Links:             s.proxyLinksFiltered(cfg, ownedSecrets),
	}
	var secretUpstreamGroups map[string]string
	if s.store != nil {
		secretUpstreamGroups, _ = s.store.ListSecretUpstreamGroups()
	}
	for _, c := range mt.Clients {
		if !admin {
			if _, ok := ownedSecrets[c.Secret]; !ok {
				continue
			}
		}
		resp.MTProxy.Secrets = append(resp.MTProxy.Secrets, secretInfo{
			Secret:            c.Secret,
			LastConnection:    c.LastConnection.Unix(),
			Connections:       c.Connections,
			ActiveConnections: c.ActiveConnections,
			UniqueUsers:       c.UniqueUsers,
			ConnectionsTotal:  c.ConnectionsTotal,
			BytesC2B:          c.BytesC2B,
			BytesB2C:          c.BytesB2C,
			UpstreamGroup:     secretUpstreamGroups[c.Secret],
		})
	}

	// Proxy servers.
	serverIP := cfg.ServerPublicIP()
	if serverIP == "" {
		serverIP = "<SERVER_IP>"
	}
	for _, p := range cfg.Proxies {
		pi := proxyInfo{
			Name:          p.Name,
			Type:          p.Type,
			Listen:        p.Listen,
			UpstreamGroup: p.UpstreamGroup,
			HasAuth:       p.Username != "",
			Username:      p.Username,
			Password:      p.Password,
			Link:          buildProxyLink(p, serverIP),
		}
		resp.Proxies = append(resp.Proxies, pi)
	}

	// Used ports.
	if admin {
		resp.UsedPorts = porttracker.UsedPorts(cfg)
	}

	// Sort all lists by creation time.
	if s.store != nil {
		if order, err := s.store.PeerNamesOrdered(); err == nil {
			sortByCreationOrder(resp.Peers, func(p peerInfo) string { return p.Name }, order)
		}
		if order, err := s.store.UpstreamNamesOrdered(); err == nil {
			sortByCreationOrder(resp.Upstreams, func(u upstreamInfo) string { return u.Name }, order)
		}
		if order, err := s.store.ProxyNamesOrdered(); err == nil {
			sortByCreationOrder(resp.Proxies, func(p proxyInfo) string { return p.Name }, order)
		}
		if order, err := s.store.SecretHexOrdered(); err == nil {
			sortByCreationOrder(resp.MTProxy.Secrets, func(s secretInfo) string { return s.Secret }, order)
		}
	}

	// Resolve owner display names for peers and secrets.
	if admin && s.store != nil {
		ownerIDs := make(map[int64]struct{})
		peerOwners, _ := s.store.ListPeerOwners()
		secretOwners, _ := s.store.ListSecretOwners()
		for _, id := range peerOwners {
			ownerIDs[id] = struct{}{}
		}
		for _, id := range secretOwners {
			ownerIDs[id] = struct{}{}
		}
		for i := range resp.Peers {
			if ownerID, ok := peerOwners[resp.Peers[i].Name]; ok {
				resp.Peers[i].OwnerID = ownerID
			}
		}
		for i := range resp.MTProxy.Secrets {
			if ownerID, ok := secretOwners[resp.MTProxy.Secrets[i].Secret]; ok {
				resp.MTProxy.Secrets[i].OwnerID = ownerID
			}
		}
		if len(ownerIDs) > 0 {
			ids := make([]int64, 0, len(ownerIDs))
			for id := range ownerIDs {
				ids = append(ids, id)
			}
			if names, err := s.store.GetUserDisplayNames(ids); err == nil {
				for i := range resp.Peers {
					if ownerID, ok := peerOwners[resp.Peers[i].Name]; ok {
						resp.Peers[i].OwnerName = names[ownerID]
					}
				}
				for i := range resp.MTProxy.Secrets {
					if ownerID, ok := secretOwners[resp.MTProxy.Secrets[i].Secret]; ok {
						resp.MTProxy.Secrets[i].OwnerName = names[ownerID]
					}
				}
			}
		}
	}

	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleAddPeer(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if req.Name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name is required"})
		return
	}

	uid := requestUserID(r)
	guest := !isAdminRequest(r)

	// Enforce guest limit.
	if guest && s.store != nil {
		maxPeers := defaultGuestMaxPeers
		if mp, _, err := s.store.GetUserLimits(uid); err == nil && mp != nil {
			maxPeers = *mp
		}
		count, err := s.store.CountPeersByOwner(uid)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		if count >= maxPeers {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": fmt.Sprintf("peer limit reached (max %d)", maxPeers)})
			return
		}
	}

	peer, err := s.manager.AddPeer(req.Name)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	// Enable exclude_server by default.
	if err := s.manager.SetPeerExcludeServer(req.Name, true); err != nil {
		s.logger.Error("miniapp: failed to set exclude_server", "peer", req.Name, "err", err)
	}

	// Set ownership.
	if s.store != nil {
		if err := s.store.SetPeerOwner(req.Name, uid); err != nil {
			s.logger.Error("miniapp: failed to set peer owner", "peer", req.Name, "user_id", uid, "err", err)
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"name":        req.Name,
		"public_key":  peer.PublicKey,
		"allowed_ips": peer.AllowedIPs,
	})
}

func (s *Server) handleDeletePeer(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	name := strings.TrimPrefix(r.URL.Path, "/api/peers/")
	if name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "peer name is required"})
		return
	}

	// Guests can only delete their own peers.
	if !isAdminRequest(r) && s.store != nil {
		owner, err := s.store.GetPeerOwner(name)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		if owner == nil || *owner != requestUserID(r) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "peer not found"})
			return
		}
	}

	if err := s.manager.DeletePeer(name); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleUpdatePeer(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/api/peers/")
	if name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "peer name is required"})
		return
	}

	// Guests can only update their own peers.
	if !isAdminRequest(r) && s.store != nil {
		owner, err := s.store.GetPeerOwner(name)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		if owner == nil || *owner != requestUserID(r) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "peer not found"})
			return
		}
	}

	var req struct {
		Name           *string `json:"name"`
		Disabled       *bool   `json:"disabled"`
		ExcludePrivate *bool   `json:"exclude_private"`
		ExcludeServer  *bool   `json:"exclude_server"`
		UpstreamGroup  *string `json:"upstream_group"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	if req.Disabled != nil {
		if err := s.manager.SetPeerDisabled(name, *req.Disabled); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
	}

	if req.ExcludePrivate != nil {
		if err := s.manager.SetPeerExcludePrivate(name, *req.ExcludePrivate); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
	}

	if req.ExcludeServer != nil {
		if err := s.manager.SetPeerExcludeServer(name, *req.ExcludeServer); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
	}

	if req.UpstreamGroup != nil {
		if err := s.manager.SetPeerUpstreamGroup(name, *req.UpstreamGroup); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
	}

	if req.Name != nil {
		newName := strings.TrimSpace(*req.Name)
		if newName == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "peer name must not be empty"})
			return
		}
		if newName != name {
			if err := s.manager.RenamePeer(name, newName); err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
				return
			}
			name = newName
		}
	}

	writeJSON(w, http.StatusOK, map[string]string{"name": name, "status": "ok"})
}

// buildPeerConfText generates a WireGuard/AmneziaWG client config text for the given peer.
func buildPeerConfText(cfg *config.Config, peer config.PeerConfig) string {
	clientIP := strings.Split(peer.AllowedIPs, "/")[0]

	serverIP := cfg.ServerPublicIP()
	endpoint := fmt.Sprintf("<SERVER_IP>:%d", cfg.WireGuard.ListenPort)
	if serverIP != "" {
		endpoint = fmt.Sprintf("%s:%d", serverIP, cfg.WireGuard.ListenPort)
	}

	allowedIPs := "0.0.0.0/0"
	cidrVars := map[string]string{"server_ip": serverIP}
	cidrs := cfg.Routing.CIDRs
	if peer.ExcludePrivate {
		cidrs = append(config.PrivateNetworkCIDRs(cfg.WireGuard.Address), cidrs...)
	}
	cidrRules, err := config.ParseCIDRRules(config.ExpandCIDRRuleVars(cidrs, cidrVars))
	if err == nil {
		excludeIP := ""
		if peer.ExcludeServer {
			excludeIP = serverIP
		}
		if computed := config.ComputeAllowedIPs(cidrRules, excludeIP); computed != "" {
			allowedIPs = computed
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", peer.PrivateKey)
	fmt.Fprintf(&b, "Address = %s/24\n", clientIP)
	fmt.Fprintf(&b, "DNS = %s\n", cfg.WireGuard.DNS)
	if cfg.WireGuard.IsAmneziaWG() && cfg.WireGuard.AmneziaWG != nil {
		awg := cfg.WireGuard.AmneziaWG
		if awg.Jc != 0 {
			fmt.Fprintf(&b, "Jc = %d\n", awg.Jc)
		}
		if awg.Jmin != 0 {
			fmt.Fprintf(&b, "Jmin = %d\n", awg.Jmin)
		}
		if awg.Jmax != 0 {
			fmt.Fprintf(&b, "Jmax = %d\n", awg.Jmax)
		}
		if awg.S1 != 0 {
			fmt.Fprintf(&b, "S1 = %d\n", awg.S1)
		}
		if awg.S2 != 0 {
			fmt.Fprintf(&b, "S2 = %d\n", awg.S2)
		}
		if awg.S3 != 0 {
			fmt.Fprintf(&b, "S3 = %d\n", awg.S3)
		}
		if awg.S4 != 0 {
			fmt.Fprintf(&b, "S4 = %d\n", awg.S4)
		}
		if awg.H1 != "" {
			fmt.Fprintf(&b, "H1 = %s\n", awg.H1)
		}
		if awg.H2 != "" {
			fmt.Fprintf(&b, "H2 = %s\n", awg.H2)
		}
		if awg.H3 != "" {
			fmt.Fprintf(&b, "H3 = %s\n", awg.H3)
		}
		if awg.H4 != "" {
			fmt.Fprintf(&b, "H4 = %s\n", awg.H4)
		}
		if awg.I1 != "" {
			fmt.Fprintf(&b, "I1 = %s\n", awg.I1)
		}
		if awg.I2 != "" {
			fmt.Fprintf(&b, "I2 = %s\n", awg.I2)
		}
		if awg.I3 != "" {
			fmt.Fprintf(&b, "I3 = %s\n", awg.I3)
		}
		if awg.I4 != "" {
			fmt.Fprintf(&b, "I4 = %s\n", awg.I4)
		}
		if awg.I5 != "" {
			fmt.Fprintf(&b, "I5 = %s\n", awg.I5)
		}
	}
	fmt.Fprintf(&b, "\n[Peer]\n")
	if serverPublicKey, err := config.DerivePublicKey(cfg.WireGuard.PrivateKey); err == nil {
		fmt.Fprintf(&b, "PublicKey = %s\n", serverPublicKey)
	} else {
		fmt.Fprintf(&b, "PublicKey = <failed to derive>\n")
	}
	if peer.PresharedKey != "" {
		fmt.Fprintf(&b, "PresharedKey = %s\n", peer.PresharedKey)
	}
	fmt.Fprintf(&b, "Endpoint = %s\n", endpoint)
	fmt.Fprintf(&b, "AllowedIPs = %s\n", allowedIPs)
	fmt.Fprintf(&b, "PersistentKeepalive = 25\n")
	return b.String()
}

func (s *Server) handlePeerConf(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract peer name from path: /api/peers/<name>/conf
	path := strings.TrimPrefix(r.URL.Path, "/api/peers/")
	name := strings.TrimSuffix(path, "/conf")
	if name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "peer name is required"})
		return
	}

	// Guests can only view their own peer configs.
	if !isAdminRequest(r) && s.store != nil {
		owner, err := s.store.GetPeerOwner(name)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		if owner == nil || *owner != requestUserID(r) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "peer not found"})
			return
		}
	}

	cfg := s.cfgProv.CurrentConfig()

	peer, ok := cfg.Peers[name]
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "peer not found"})
		return
	}

	confText := buildPeerConfText(cfg, peer)

	// Return raw file download when ?download=1 is set (for tg.downloadFile).
	if r.URL.Query().Get("download") == "1" {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s.conf", sanitizeFilename(name)))
		w.Header().Set("Access-Control-Allow-Origin", "https://web.telegram.org")
		w.Write([]byte(confText))
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"config": confText})
}

func (s *Server) handlePeerQR(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract peer name from path: /api/peers/<name>/qr
	path := strings.TrimPrefix(r.URL.Path, "/api/peers/")
	name := strings.TrimSuffix(path, "/qr")
	if name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "peer name is required"})
		return
	}

	// Guests can only view their own peer configs.
	if !isAdminRequest(r) && s.store != nil {
		owner, err := s.store.GetPeerOwner(name)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		if owner == nil || *owner != requestUserID(r) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "peer not found"})
			return
		}
	}

	cfg := s.cfgProv.CurrentConfig()

	peer, ok := cfg.Peers[name]
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "peer not found"})
		return
	}

	confText := buildPeerConfText(cfg, peer)

	png, err := qrcode.Encode(confText, qrcode.Medium, 512)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to generate QR code"})
		return
	}

	w.Header().Set("Content-Type", "image/png")
	w.Write(png)
}

func (s *Server) handlePeerSendConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract peer name from path: /api/peers/<name>/send
	path := strings.TrimPrefix(r.URL.Path, "/api/peers/")
	name := strings.TrimSuffix(path, "/send")
	if name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "peer name is required"})
		return
	}

	userID := requestUserID(r)

	// Guests can only send their own peer configs.
	if !isAdminRequest(r) && s.store != nil {
		owner, err := s.store.GetPeerOwner(name)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		if owner == nil || *owner != userID {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "peer not found"})
			return
		}
	}

	cfg := s.cfgProv.CurrentConfig()

	peer, ok := cfg.Peers[name]
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "peer not found"})
		return
	}

	if s.bot == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "telegram bot is not configured"})
		return
	}

	confText := buildPeerConfText(cfg, peer)
	filename := sanitizeFilename(name) + ".conf"

	if err := s.bot.SendDocument(r.Context(), userID, filename, []byte(confText), "🔐 WireGuard config: "+name); err != nil {
		s.logger.Error("miniapp: failed to send config to telegram", "peer", name, "user_id", userID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to send config"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleAddSecret(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Type    string `json:"type"`
		Comment string `json:"comment"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if req.Type == "" {
		req.Type = "faketls"
	}

	uid := requestUserID(r)
	guest := !isAdminRequest(r)

	// Enforce guest limit.
	if guest && s.store != nil {
		maxSecrets := defaultGuestMaxSecrets
		if _, ms, err := s.store.GetUserLimits(uid); err == nil && ms != nil {
			maxSecrets = *ms
		}
		count, err := s.store.CountSecretsByOwner(uid)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		if count >= maxSecrets {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": fmt.Sprintf("secret limit reached (max %d)", maxSecrets)})
			return
		}
	}

	secretHex, err := s.manager.AddSecret(req.Type, req.Comment)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	// Set ownership.
	if s.store != nil {
		if err := s.store.SetSecretOwner(secretHex, uid); err != nil {
			s.logger.Error("miniapp: failed to set secret owner", "secret", secretHex, "user_id", uid, "err", err)
		}
	}

	writeJSON(w, http.StatusOK, map[string]string{"secret": secretHex})
}

func (s *Server) handleSecretsRoute(w http.ResponseWriter, r *http.Request) {
	if strings.HasSuffix(r.URL.Path, "/name") {
		// Only admins can rename secrets.
		if !isAdminRequest(r) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "admin access required"})
			return
		}
		s.handleRenameSecret(w, r)
		return
	}
	if r.Method == http.MethodPut {
		s.handleUpdateSecret(w, r)
		return
	}
	s.handleDeleteSecret(w, r)
}

func (s *Server) handleDeleteSecret(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	secretHex := strings.TrimPrefix(r.URL.Path, "/api/secrets/")
	if secretHex == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "secret hex is required"})
		return
	}

	// Guests can only delete their own secrets.
	if !isAdminRequest(r) && s.store != nil {
		owner, err := s.store.GetSecretOwner(secretHex)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		if owner == nil || *owner != requestUserID(r) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "secret not found"})
			return
		}
	}

	if err := s.manager.DeleteSecret(secretHex); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) proxyLinks(cfg *config.Config) []config.ProxyLink {
	var names map[string]string
	if s.store != nil {
		names, _ = s.store.SecretNames(cfg.MTProxy.Secrets)
	}
	return config.ProxyLinks(cfg, names)
}

// proxyLinksFiltered returns proxy links filtered by the allowed set.
// If allowedSecrets is nil, all links are returned (admin path).
func (s *Server) proxyLinksFiltered(cfg *config.Config, allowedSecrets map[string]struct{}) []config.ProxyLink {
	all := s.proxyLinks(cfg)
	if allowedSecrets == nil {
		return all
	}
	var filtered []config.ProxyLink
	for _, l := range all {
		if _, ok := allowedSecrets[l.Secret]; ok {
			filtered = append(filtered, l)
		}
	}
	return filtered
}

func (s *Server) handleRenameSecret(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	secretHex := strings.TrimPrefix(r.URL.Path, "/api/secrets/")
	secretHex = strings.TrimSuffix(secretHex, "/name")
	if secretHex == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "secret hex is required"})
		return
	}

	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	if s.store == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "database not available"})
		return
	}

	if err := s.store.RenameSecret(secretHex, req.Name); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleUpdateSecret(w http.ResponseWriter, r *http.Request) {
	secretHex := strings.TrimPrefix(r.URL.Path, "/api/secrets/")
	if secretHex == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "secret hex is required"})
		return
	}

	// Guests can only update their own secrets.
	if !isAdminRequest(r) && s.store != nil {
		owner, err := s.store.GetSecretOwner(secretHex)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		if owner == nil || *owner != requestUserID(r) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "secret not found"})
			return
		}
	}

	var req struct {
		UpstreamGroup *string `json:"upstream_group"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	if req.UpstreamGroup != nil {
		if err := s.manager.SetSecretUpstreamGroup(secretHex, *req.UpstreamGroup); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleProxiesRoute(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPut {
		s.handleUpdateProxy(w, r)
		return
	}
	s.handleDeleteProxy(w, r)
}

func (s *Server) handleUpdateProxy(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/api/proxies/")
	if name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "proxy name is required"})
		return
	}

	var req struct {
		UpstreamGroup *string `json:"upstream_group"`
		Username      *string `json:"username"`
		Password      *string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	if req.UpstreamGroup != nil {
		if err := s.manager.SetProxyUpstreamGroup(name, *req.UpstreamGroup); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
	}

	if req.Username != nil || req.Password != nil {
		u, p := "", ""
		if req.Username != nil {
			u = *req.Username
		}
		if req.Password != nil {
			p = *req.Password
		}
		if err := s.manager.SetProxyAuth(name, u, p); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleAddProxy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Name     string `json:"name"`
		Type     string `json:"type"`
		Listen   string `json:"listen"`
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	if req.Type == "" || req.Listen == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "type and listen are required"})
		return
	}

	p := config.ProxyServerConfig{
		Name:     req.Name,
		Type:     req.Type,
		Listen:   req.Listen,
		Username: req.Username,
		Password: req.Password,
	}
	if p.Name == "" {
		p.Name = fmt.Sprintf("%s-%s", p.Type, strings.ReplaceAll(p.Listen, ":", "-"))
	}

	if err := s.manager.AddProxy(p); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"name": p.Name, "status": "ok"})
}

func (s *Server) handleDeleteProxy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	name := strings.TrimPrefix(r.URL.Path, "/api/proxies/")
	if name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "proxy name is required"})
		return
	}

	if err := s.manager.DeleteProxy(name); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleAddUpstream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Name        string   `json:"name"`
		Type        string   `json:"type"`
		Enabled     *bool    `json:"enabled,omitempty"`
		Default     bool     `json:"default"`
		Groups      []string `json:"groups,omitempty"`
		Transport   string   `json:"transport"`
		HealthCheck struct {
			Enabled  bool   `json:"enabled"`
			Interval int    `json:"interval"`
			Target   string `json:"target"`
		} `json:"health_check"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if req.Name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name is required"})
		return
	}
	if req.Type == "" {
		req.Type = "outline"
	}
	if req.Transport == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "transport is required"})
		return
	}

	u := config.UpstreamConfig{
		Name:      req.Name,
		Type:      req.Type,
		Enabled:   req.Enabled,
		Default:   req.Default,
		Groups:    req.Groups,
		Transport: req.Transport,
		HealthCheck: config.HealthCheckConfig{
			Enabled:  req.HealthCheck.Enabled,
			Interval: req.HealthCheck.Interval,
			Target:   req.HealthCheck.Target,
		},
	}

	if err := s.manager.AddUpstream(u); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"name": u.Name, "status": "ok"})
}

func (s *Server) handleUpdateUpstream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	name := strings.TrimPrefix(r.URL.Path, "/api/upstreams/")
	if name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "upstream name is required"})
		return
	}

	// Find the existing upstream to use as base for merging.
	cfg := s.cfgProv.CurrentConfig()
	var existing *config.UpstreamConfig
	for i := range cfg.Upstreams {
		if cfg.Upstreams[i].Name == name {
			newUpstream := cfg.Upstreams[i]
			existing = &newUpstream
			break
		}
	}
	if existing == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "upstream not found"})
		return
	}

	var req struct {
		Type        *string  `json:"type"`
		Enabled     *bool    `json:"enabled"`
		Default     *bool    `json:"default"`
		Groups      []string `json:"groups"`
		Transport   *string  `json:"transport"`
		HealthCheck *struct {
			Enabled  bool   `json:"enabled"`
			Interval int    `json:"interval"`
			Target   string `json:"target"`
		} `json:"health_check"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	// Merge: only overwrite fields that were provided.
	if req.Type != nil {
		existing.Type = *req.Type
	}
	if req.Enabled != nil {
		existing.Enabled = req.Enabled
	}
	if req.Default != nil {
		existing.Default = *req.Default
	}
	if req.Groups != nil {
		existing.Groups = req.Groups
	}
	if req.Transport != nil {
		existing.Transport = *req.Transport
	}
	if req.HealthCheck != nil {
		existing.HealthCheck = config.HealthCheckConfig{
			Enabled:  req.HealthCheck.Enabled,
			Interval: req.HealthCheck.Interval,
			Target:   req.HealthCheck.Target,
		}
	}

	if err := s.manager.UpdateUpstream(*existing); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"name": name, "status": "ok"})
}

func (s *Server) handleDeleteUpstream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	name := strings.TrimPrefix(r.URL.Path, "/api/upstreams/")
	if name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "upstream name is required"})
		return
	}

	if err := s.manager.DeleteUpstream(name); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleUpstreamsRoute(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPut:
		s.handleUpdateUpstream(w, r)
	case http.MethodDelete:
		s.handleDeleteUpstream(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

type groupMember struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	State   string `json:"state"`
	Enabled bool   `json:"enabled"`
}

type groupConsumer struct {
	Type string `json:"type"`
	Name string `json:"name"`
}

type groupInfo struct {
	Name      string          `json:"name"`
	Members   []groupMember   `json:"members"`
	Consumers []groupConsumer `json:"consumers"`
}

func (s *Server) handleGroupsRoute(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleGetGroups(w, r)
	case http.MethodPost:
		s.handleCreateGroup(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleGetGroups(w http.ResponseWriter, r *http.Request) {
	groups := make(map[string]*groupInfo)

	ensureGroup := func(name string) *groupInfo {
		g, ok := groups[name]
		if !ok {
			g = &groupInfo{Name: name}
			groups[name] = g
		}
		return g
	}

	// Populate members from upstream statuses.
	// u.Groups already contains all effective groups (implicit, default, explicit)
	// via EffectiveGroups(), so we only need to iterate over it.
	for _, u := range s.provider.UpstreamStatuses() {
		member := groupMember{
			Name:    u.Name,
			Type:    string(u.Type),
			State:   string(u.State),
			Enabled: u.Enabled,
		}

		for _, gName := range u.Groups {
			ensureGroup(gName).Members = append(ensureGroup(gName).Members, member)
		}
	}

	// Populate consumers from config.
	cfg := s.cfgProv.CurrentConfig()

	for _, p := range cfg.Proxies {
		g := p.UpstreamGroup
		if g == "" {
			g = "default"
		}
		if g != "" {
			ensureGroup(g).Consumers = append(ensureGroup(g).Consumers, groupConsumer{Type: "proxy", Name: p.Name})
		}
	}
	for _, r := range cfg.Routing.IPRules {
		g := r.UpstreamGroup
		if g == "" {
			g = "default"
		}
		if g != "" {
			ensureGroup(g).Consumers = append(ensureGroup(g).Consumers, groupConsumer{Type: "ip_rule", Name: r.Name})
		}
	}
	for _, r := range cfg.Routing.SNIRules {
		g := r.UpstreamGroup
		if g == "" {
			g = "default"
		}
		if g != "" {
			ensureGroup(g).Consumers = append(ensureGroup(g).Consumers, groupConsumer{Type: "sni_rule", Name: r.Name})
		}
	}
	if cfg.MTProxy.UpstreamGroup != "" {
		ensureGroup(cfg.MTProxy.UpstreamGroup).Consumers = append(
			ensureGroup(cfg.MTProxy.UpstreamGroup).Consumers,
			groupConsumer{Type: "mtproxy", Name: "mtproxy"},
		)
	}

	// Merge in explicitly created groups from DB (may have no members).
	if s.store != nil {
		dbGroups, _ := s.store.ListGroups()
		for _, name := range dbGroups {
			ensureGroup(name)
		}
	}

	result := make([]groupInfo, 0, len(groups))
	for _, g := range groups {
		result = append(result, *g)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Name < result[j].Name
	})

	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleCreateGroup(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if req.Name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name is required"})
		return
	}

	if err := s.manager.CreateGroup(req.Name); err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"name": req.Name, "status": "ok"})
}

func (s *Server) handleGroupsItemRoute(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	name := strings.TrimPrefix(r.URL.Path, "/api/groups/")
	if name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "group name is required"})
		return
	}

	if err := s.manager.DeleteGroup(name); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleListUsers(w, r)
	case http.MethodPost:
		s.handleAddUser(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) isConfigAdmin(userID int64) bool {
	return slices.Contains(s.allowedUsers, userID)
}

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	type userResp struct {
		UserID        int64  `json:"user_id"`
		Username      string `json:"username"`
		FirstName     string `json:"first_name"`
		LastName      string `json:"last_name"`
		PhotoURL      string `json:"photo_url"`
		CustomName    string `json:"custom_name"`
		CreatedAt     int64  `json:"created_at"`
		Role          string `json:"role"`
		IsAdmin       bool   `json:"is_admin"`
		IsConfigAdmin bool   `json:"is_config_admin"`
		Disabled      bool   `json:"disabled"`
		MaxPeers      *int   `json:"max_peers"`
		MaxSecrets    *int   `json:"max_secrets"`
	}

	var out []userResp

	// Config admins are always listed first and cannot be deleted.
	configAdminSet := make(map[int64]bool)
	for _, uid := range s.allowedUsers {
		configAdminSet[uid] = true
		out = append(out, userResp{
			UserID:        uid,
			Role:          statsdb.RoleAdmin,
			IsAdmin:       true,
			IsConfigAdmin: true,
		})
	}

	// Resolve profile info for config admins from the DB if available.
	if s.store != nil {
		users, err := s.store.ListAllowedUsers()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		for _, u := range users {
			if configAdminSet[u.UserID] {
				// Update the config admin entry with profile info.
				for i := range out {
					if out[i].UserID == u.UserID {
						out[i].Username = u.Username
						out[i].FirstName = u.FirstName
						out[i].LastName = u.LastName
						out[i].PhotoURL = u.PhotoURL
						out[i].CustomName = u.CustomName
						out[i].CreatedAt = u.CreatedAt
						break
					}
				}
				continue
			}
			out = append(out, userResp{
				UserID:     u.UserID,
				Username:   u.Username,
				FirstName:  u.FirstName,
				LastName:   u.LastName,
				PhotoURL:   u.PhotoURL,
				CustomName: u.CustomName,
				CreatedAt:  u.CreatedAt,
				Role:       u.Role,
				IsAdmin:    u.Role == statsdb.RoleAdmin,
				Disabled:   u.Disabled,
				MaxPeers:   u.MaxPeers,
				MaxSecrets: u.MaxSecrets,
			})
		}
	}

	if out == nil {
		out = []userResp{}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleAddUser(w http.ResponseWriter, r *http.Request) {
	if s.store == nil || s.bot == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "not configured"})
		return
	}

	var req struct {
		User       string `json:"user"`
		Role       string `json:"role"`        // "admin" or "guest" (default: "guest")
		CustomName string `json:"custom_name"` // optional display name
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if req.User == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "user is required (@username or numeric ID)"})
		return
	}
	if req.Role == "" {
		req.Role = statsdb.RoleGuest
	}
	if req.Role != statsdb.RoleAdmin && req.Role != statsdb.RoleGuest {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "role must be 'admin' or 'guest'"})
		return
	}

	input := strings.TrimPrefix(req.User, "@")
	numericID, parseErr := strconv.ParseInt(input, 10, 64)
	isNumeric := parseErr == nil

	// Try to resolve profile info via Telegram API.
	chatID := req.User
	if !isNumeric && !strings.HasPrefix(chatID, "@") {
		chatID = "@" + chatID
	}

	var u statsdb.AllowedUser
	info, err := s.bot.GetChat(r.Context(), chatID)
	if err != nil {
		// getChat only works for users who have interacted with the bot.
		// For numeric IDs, allow adding without profile info.
		if !isNumeric {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": "user not found — the user must message the bot first, or use their numeric ID",
			})
			return
		}
		u = statsdb.AllowedUser{UserID: numericID, Role: req.Role, CustomName: req.CustomName}
	} else {
		var photoURL string
		if info.Photo != nil && info.Photo.SmallFileID != "" {
			if fileURL, err := s.bot.GetFileURL(r.Context(), info.Photo.SmallFileID); err == nil {
				photoURL = fileURL
			}
		}
		u = statsdb.AllowedUser{
			UserID:     info.ID,
			Username:   info.Username,
			FirstName:  info.FirstName,
			LastName:   info.LastName,
			PhotoURL:   photoURL,
			CustomName: req.CustomName,
			Role:       req.Role,
		}
	}

	if err := s.store.AddAllowedUser(u); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"user_id":     u.UserID,
		"username":    u.Username,
		"first_name":  u.FirstName,
		"last_name":   u.LastName,
		"photo_url":   u.PhotoURL,
		"custom_name": u.CustomName,
		"role":        u.Role,
	})
}

func (s *Server) handleUserRoute(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPut:
		s.handleUpdateUser(w, r)
	case http.MethodDelete:
		s.handleDeleteUser(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/api/users/")
	if idStr == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "user ID is required"})
		return
	}

	userID, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid user ID"})
		return
	}

	if s.isConfigAdmin(userID) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "cannot modify main admin user"})
		return
	}

	var req struct {
		Role       *string `json:"role"`
		CustomName *string `json:"custom_name"`
		Disabled   *bool   `json:"disabled"`
		MaxPeers   *int    `json:"max_peers"`
		MaxSecrets *int    `json:"max_secrets"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if req.Role != nil && *req.Role != statsdb.RoleAdmin && *req.Role != statsdb.RoleGuest {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "role must be 'admin' or 'guest'"})
		return
	}

	if s.store == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "not configured"})
		return
	}

	updated, err := s.store.UpdateAllowedUser(userID, req.CustomName, req.Role, req.Disabled, req.MaxPeers, req.MaxSecrets)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if !updated {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/api/users/")
	if idStr == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "user ID is required"})
		return
	}

	userID, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid user ID"})
		return
	}

	if s.isConfigAdmin(userID) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "cannot delete main admin user"})
		return
	}

	if s.store == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "not configured"})
		return
	}

	// Collect owned peers and secrets before deleting the user.
	ownedPeers, err := s.store.ListPeerNamesByOwner(userID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	ownedSecrets, err := s.store.ListSecretHexByOwner(userID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	deleted, err := s.store.DeleteAllowedUser(userID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if !deleted {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
		return
	}

	// Cascade-delete owned peers.
	for name := range ownedPeers {
		_ = s.manager.DeletePeer(name)
	}
	// Cascade-delete owned MTProxy secrets.
	for hex := range ownedSecrets {
		_ = s.manager.DeleteSecret(hex)
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ---------------------------------------------------------------------------
// Invite Links
// ---------------------------------------------------------------------------

func (s *Server) handleInvites(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleListInvites(w, r)
	case http.MethodPost:
		s.handleCreateInvite(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleInviteItem(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	token := strings.TrimPrefix(r.URL.Path, "/api/invites/")
	if token == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "token is required"})
		return
	}

	if s.store == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "not configured"})
		return
	}

	deleted, err := s.store.DeleteInviteLink(token)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if !deleted {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "invite not found"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleListInvites(w http.ResponseWriter, r *http.Request) {
	if s.store == nil {
		writeJSON(w, http.StatusOK, []any{})
		return
	}

	invites, err := s.store.ListInviteLinks()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	type inviteResp struct {
		Token     string `json:"token"`
		Role      string `json:"role"`
		Link      string `json:"link,omitempty"`
		CreatedBy int64  `json:"created_by"`
		CreatedAt int64  `json:"created_at"`
	}

	out := make([]inviteResp, 0, len(invites))
	for _, inv := range invites {
		out = append(out, inviteResp{
			Token:     inv.Token,
			Role:      inv.Role,
			Link:      s.inviteDeepLink(inv.Token),
			CreatedBy: inv.CreatedBy,
			CreatedAt: inv.CreatedAt,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleCreateInvite(w http.ResponseWriter, r *http.Request) {
	if s.store == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "not configured"})
		return
	}

	var req struct {
		Role string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if req.Role == "" {
		req.Role = statsdb.RoleGuest
	}
	if req.Role != statsdb.RoleAdmin && req.Role != statsdb.RoleGuest {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "role must be 'admin' or 'guest'"})
		return
	}

	tokenBytes := make([]byte, 16)
	if _, err := rand.Read(tokenBytes); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to generate token"})
		return
	}
	token := hex.EncodeToString(tokenBytes)

	if err := s.store.CreateInviteLink(token, req.Role, requestUserID(r)); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	resp := map[string]string{"token": token, "role": req.Role}
	if link := s.inviteDeepLink(token); link != "" {
		resp["link"] = link
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleRedeemInvite handles POST /api/invite — validates Telegram init data
// without requiring the user to be in allowed_users, then redeems a one-time invite token.
func (s *Server) handleRedeemInvite(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.store == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "not configured"})
		return
	}

	// Validate Telegram init data (but don't check role).
	initData := r.Header.Get("X-Telegram-Init-Data")
	if initData == "" {
		auth := r.Header.Get("Authorization")
		if after, ok := strings.CutPrefix(auth, "tma "); ok {
			initData = after
		}
	}
	if initData == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing init data"})
		return
	}

	userID, err := ValidateInitData(initData, s.botToken)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid init data"})
		return
	}

	// Check if user is already authorized.
	if existingRole, _ := s.store.GetUserRole(userID); existingRole != "" {
		writeJSON(w, http.StatusOK, map[string]string{"status": "already_authorized"})
		return
	}
	// Also check config admins.
	if s.isConfigAdmin(userID) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "already_authorized"})
		return
	}

	var req struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if req.Token == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "token is required"})
		return
	}

	invite, found, err := s.store.UseInviteLink(req.Token)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if !found {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "invite link not found or already used"})
		return
	}

	// Try to resolve profile info from Telegram init data.
	u := statsdb.AllowedUser{UserID: userID, Role: invite.Role}
	params, _ := parseInitDataUser(initData)
	if params != nil {
		u.Username = params.Username
		u.FirstName = params.FirstName
		u.LastName = params.LastName
	}

	if err := s.store.AddAllowedUser(u); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "role": invite.Role})
}

// parseInitDataUser extracts user profile from Telegram init data user JSON.
func parseInitDataUser(initData string) (*struct {
	Username  string
	FirstName string
	LastName  string
}, error) {
	params, err := parseInitDataParams(initData)
	if err != nil {
		return nil, err
	}
	userJSON := params.Get("user")
	if userJSON == "" {
		return nil, fmt.Errorf("no user field")
	}
	var u struct {
		Username  string `json:"username"`
		FirstName string `json:"first_name"`
		LastName  string `json:"last_name"`
	}
	if err := json.NewDecoder(strings.NewReader(userJSON)).Decode(&u); err != nil {
		return nil, err
	}
	return &struct {
		Username  string
		FirstName string
		LastName  string
	}{u.Username, u.FirstName, u.LastName}, nil
}

func parseInitDataParams(initData string) (interface{ Get(string) string }, error) {
	params, err := url.ParseQuery(initData)
	if err != nil {
		return nil, err
	}
	return params, nil
}

// DNS response types.

type dnsResponse struct {
	Enabled  bool            `json:"enabled"`
	Listen   string          `json:"listen"`
	Upstream string          `json:"upstream"`
	Records  []dnsRecordInfo `json:"records"`
	Rules    []dnsRuleInfo   `json:"rules"`
}

type dnsRecordInfo struct {
	Name string   `json:"name"`
	A    []string `json:"a"`
	AAAA []string `json:"aaaa"`
	TTL  uint32   `json:"ttl"`
}

type dnsRuleInfo struct {
	Name     string        `json:"name"`
	Action   string        `json:"action"`
	Upstream string        `json:"upstream,omitempty"`
	Domains  []string      `json:"domains"`
	Lists    []dnsListInfo `json:"lists"`
	Peers    []string      `json:"peers"`
}

type dnsListInfo struct {
	URL     string `json:"url"`
	Format  string `json:"format"`
	Refresh int    `json:"refresh"`
}

func (s *Server) handleDNSRoute(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleDNS(w, r)
	case http.MethodPut:
		s.handleUpdateDNS(w, r)
	case http.MethodPost:
		s.handleAddDNSRule(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleDNS(w http.ResponseWriter, r *http.Request) {
	cfg := s.cfgProv.CurrentConfig()
	dns := cfg.DNS

	resp := dnsResponse{
		Enabled:  dns.Enabled,
		Listen:   dns.Listen,
		Upstream: dns.Upstream,
	}

	// Convert records map to sorted slice.
	for name, rec := range dns.Records {
		resp.Records = append(resp.Records, dnsRecordInfo{
			Name: name,
			A:    rec.A,
			AAAA: rec.AAAA,
			TTL:  rec.TTL,
		})
	}
	if s.store != nil {
		if order, err := s.store.DNSRecordNamesOrdered(); err == nil {
			sortByCreationOrder(resp.Records, func(r dnsRecordInfo) string { return r.Name }, order)
		}
	} else {
		sort.Slice(resp.Records, func(i, j int) bool {
			return resp.Records[i].Name < resp.Records[j].Name
		})
	}

	// Rules.
	for _, rule := range dns.Rules {
		ri := dnsRuleInfo{
			Name:     rule.Name,
			Action:   rule.Action,
			Upstream: rule.Upstream,
			Domains:  rule.Domains,
			Peers:    rule.Peers,
		}
		for _, l := range rule.Lists {
			ri.Lists = append(ri.Lists, dnsListInfo{
				URL:     l.URL,
				Format:  l.Format,
				Refresh: l.Refresh,
			})
		}
		resp.Rules = append(resp.Rules, ri)
	}

	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleUpdateDNS(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled *bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if req.Enabled == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "enabled is required"})
		return
	}

	if err := s.manager.SetDNSEnabled(*req.Enabled); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleDNSRecordsRoute(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/api/dns/records/")
	if name == "" {
		// /api/dns/records — POST only
		if r.Method == http.MethodPost {
			s.handleAddDNSRecord(w, r)
			return
		}
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// /api/dns/records/<name>
	switch r.Method {
	case http.MethodPut:
		s.handleUpdateDNSRecord(w, r, name)
	case http.MethodDelete:
		s.handleDeleteDNSRecord(w, r, name)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleAddDNSRecord(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string   `json:"name"`
		A    []string `json:"a"`
		AAAA []string `json:"aaaa"`
		TTL  uint32   `json:"ttl"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if req.Name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name is required"})
		return
	}
	if len(req.A) == 0 && len(req.AAAA) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "at least one A or AAAA record is required"})
		return
	}
	if req.TTL == 0 {
		req.TTL = 3600
	}

	rec := config.DNSRecordConfig{A: req.A, AAAA: req.AAAA, TTL: req.TTL}
	if err := s.manager.AddDNSRecord(req.Name, rec); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"name": req.Name, "status": "ok"})
}

func (s *Server) handleUpdateDNSRecord(w http.ResponseWriter, r *http.Request, name string) {
	var req struct {
		A    []string `json:"a"`
		AAAA []string `json:"aaaa"`
		TTL  *uint32  `json:"ttl"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	cfg := s.cfgProv.CurrentConfig()
	existing, ok := cfg.DNS.Records[name]
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "dns record not found"})
		return
	}

	if req.A != nil {
		existing.A = req.A
	}
	if req.AAAA != nil {
		existing.AAAA = req.AAAA
	}
	if req.TTL != nil {
		existing.TTL = *req.TTL
	}

	if err := s.manager.UpdateDNSRecord(name, existing); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"name": name, "status": "ok"})
}

func (s *Server) handleDeleteDNSRecord(w http.ResponseWriter, r *http.Request, name string) {
	if err := s.manager.DeleteDNSRecord(name); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleAddDNSRule(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name     string   `json:"name"`
		Action   string   `json:"action"`
		Upstream string   `json:"upstream"`
		Domains  []string `json:"domains"`
		Lists    []struct {
			URL     string `json:"url"`
			Format  string `json:"format"`
			Refresh int    `json:"refresh"`
		} `json:"lists"`
		Peers []string `json:"peers"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	if req.Name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name is required"})
		return
	}
	if req.Action != "block" && req.Action != "upstream" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "action must be 'block' or 'upstream'"})
		return
	}
	if req.Action == "upstream" && req.Upstream == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "upstream is required for upstream action"})
		return
	}
	if len(req.Domains) == 0 && len(req.Lists) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "at least one domain or list is required"})
		return
	}

	rule := config.DNSRuleConfig{
		Name:     req.Name,
		Action:   req.Action,
		Upstream: req.Upstream,
		Domains:  req.Domains,
		Peers:    req.Peers,
	}
	for _, l := range req.Lists {
		format := l.Format
		if format == "" {
			format = "auto"
		}
		rule.Lists = append(rule.Lists, config.DNSListConfig{
			URL:     l.URL,
			Format:  format,
			Refresh: l.Refresh,
		})
	}

	if err := s.manager.AddDNSRule(rule); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"name": req.Name, "status": "ok"})
}

func (s *Server) handleDeleteDNSRule(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	name := strings.TrimPrefix(r.URL.Path, "/api/dns/rules/")
	if name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "rule name is required"})
		return
	}

	if err := s.manager.DeleteDNSRule(name); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleKnownBlocklists(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	type blocklistEntry struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		URL         string `json:"url"`
		Source      string `json:"source"`
	}

	result := make([]blocklistEntry, len(dns.KnownBlocklists))
	for i, bl := range dns.KnownBlocklists {
		result[i] = blocklistEntry{
			Name:        bl.Name,
			Description: bl.Description,
			URL:         bl.URL,
			Source:      bl.Source,
		}
	}

	writeJSON(w, http.StatusOK, result)
}

// --- Routing API ---

type geoipDBInfo struct {
	Name      string   `json:"name"`
	Countries []string `json:"countries"`
}

type routingResponse struct {
	CIDRs    []config.CIDREntry `json:"cidrs"`
	IPRules  []ipRuleInfo       `json:"ip_rules"`
	SNIRules []sniRuleInfo      `json:"sni_rules"`
	GeoIPDBs []geoipDBInfo      `json:"geoip_dbs"`
}

type ipRuleInfo struct {
	Name          string       `json:"name"`
	Action        string       `json:"action"`
	UpstreamGroup string       `json:"upstream_group,omitempty"`
	CIDRs         []string     `json:"cidrs"`
	ASNs          []int        `json:"asns"`
	Lists         []ipListInfo `json:"lists"`
}

type ipListInfo struct {
	URL     string `json:"url"`
	Refresh int    `json:"refresh"`
}

type sniRuleInfo struct {
	Name          string   `json:"name"`
	Action        string   `json:"action"`
	UpstreamGroup string   `json:"upstream_group,omitempty"`
	Domains       []string `json:"domains"`
}

func (s *Server) handleRoutingRoute(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.handleRouting(w, r)
}

func (s *Server) handleRouting(w http.ResponseWriter, r *http.Request) {
	cfg := s.cfgProv.CurrentConfig()
	routing := cfg.Routing

	resp := routingResponse{
		CIDRs: routing.CIDRs,
	}
	if resp.CIDRs == nil {
		resp.CIDRs = []config.CIDREntry{}
	}

	for _, rule := range routing.IPRules {
		ri := ipRuleInfo{
			Name:          rule.Name,
			Action:        rule.Action,
			UpstreamGroup: rule.UpstreamGroup,
			CIDRs:         rule.CIDRs,
			ASNs:          rule.ASNs,
		}
		if ri.CIDRs == nil {
			ri.CIDRs = []string{}
		}
		if ri.ASNs == nil {
			ri.ASNs = []int{}
		}
		for _, l := range rule.Lists {
			ri.Lists = append(ri.Lists, ipListInfo{
				URL:     l.URL,
				Refresh: l.Refresh,
			})
		}
		if ri.Lists == nil {
			ri.Lists = []ipListInfo{}
		}
		resp.IPRules = append(resp.IPRules, ri)
	}
	if resp.IPRules == nil {
		resp.IPRules = []ipRuleInfo{}
	}

	for _, rule := range routing.SNIRules {
		ri := sniRuleInfo{
			Name:          rule.Name,
			Action:        rule.Action,
			UpstreamGroup: rule.UpstreamGroup,
			Domains:       rule.Domains,
		}
		if ri.Domains == nil {
			ri.Domains = []string{}
		}
		resp.SNIRules = append(resp.SNIRules, ri)
	}
	if resp.SNIRules == nil {
		resp.SNIRules = []sniRuleInfo{}
	}

	for _, g := range cfg.GeoIP {
		countries := s.geoMgr.Countries(g.Name)
		if countries == nil {
			countries = []string{}
		}
		resp.GeoIPDBs = append(resp.GeoIPDBs, geoipDBInfo{
			Name:      g.Name,
			Countries: countries,
		})
	}
	if resp.GeoIPDBs == nil {
		resp.GeoIPDBs = []geoipDBInfo{}
	}

	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleRoutingCIDRsItem(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodDelete:
		s.handleDeleteRoutingCIDR(w, r)
	case http.MethodPut:
		s.handleUpdateRoutingCIDR(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleIPRulesItem(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodDelete:
		s.handleDeleteIPRule(w, r)
	case http.MethodPut:
		s.handleUpdateIPRule(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleUpdateRoutingCIDR(w http.ResponseWriter, r *http.Request) {
	oldCIDR := strings.TrimPrefix(r.URL.Path, "/api/routing/cidrs/")
	if oldCIDR == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "cidr is required"})
		return
	}

	var req struct {
		CIDR string `json:"cidr"`
		Mode string `json:"mode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if req.CIDR == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "new cidr is required"})
		return
	}
	if req.Mode == "" {
		req.Mode = "allow"
	}

	entry := config.CIDREntry{CIDR: req.CIDR, Mode: req.Mode}
	if err := s.manager.UpdateRoutingCIDR(oldCIDR, entry); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleUpdateIPRule(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/api/routing/ip-rules/")
	if name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "rule name is required"})
		return
	}

	var req struct {
		Action        string   `json:"action"`
		UpstreamGroup string   `json:"upstream_group"`
		CIDRs         []string `json:"cidrs"`
		ASNs          []int    `json:"asns"`
		Lists         []struct {
			URL     string `json:"url"`
			Refresh int    `json:"refresh"`
		} `json:"lists"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if req.Action != "direct" && req.Action != "upstream" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "action must be 'direct' or 'upstream'"})
		return
	}
	if req.Action == "upstream" && req.UpstreamGroup == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "upstream_group is required for upstream action"})
		return
	}

	rule := config.IPRuleConfig{
		Name:          name,
		Action:        req.Action,
		UpstreamGroup: req.UpstreamGroup,
		CIDRs:         req.CIDRs,
		ASNs:          req.ASNs,
	}
	for _, l := range req.Lists {
		rule.Lists = append(rule.Lists, config.IPListConfig{
			URL:     l.URL,
			Refresh: l.Refresh,
		})
	}

	if err := s.manager.UpdateIPRule(rule); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleAddRoutingCIDR(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		CIDR string `json:"cidr"`
		Mode string `json:"mode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if req.CIDR == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "cidr is required"})
		return
	}
	if req.Mode == "" {
		req.Mode = "allow"
	}

	entry := config.CIDREntry{CIDR: req.CIDR, Mode: req.Mode}
	if err := s.manager.AddRoutingCIDR(entry); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"cidr": req.CIDR, "mode": req.Mode, "status": "ok"})
}

func (s *Server) handleDeleteRoutingCIDR(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	cidr := strings.TrimPrefix(r.URL.Path, "/api/routing/cidrs/")
	if cidr == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "cidr is required"})
		return
	}

	if err := s.manager.DeleteRoutingCIDR(cidr); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleAddIPRule(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Name          string   `json:"name"`
		Action        string   `json:"action"`
		UpstreamGroup string   `json:"upstream_group"`
		CIDRs         []string `json:"cidrs"`
		ASNs          []int    `json:"asns"`
		Lists         []struct {
			URL     string `json:"url"`
			Refresh int    `json:"refresh"`
		} `json:"lists"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if req.Name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name is required"})
		return
	}
	if req.Action != "direct" && req.Action != "upstream" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "action must be 'direct' or 'upstream'"})
		return
	}
	if req.Action == "upstream" && req.UpstreamGroup == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "upstream_group is required for upstream action"})
		return
	}
	if len(req.CIDRs) == 0 && len(req.Lists) == 0 && len(req.ASNs) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "at least one CIDR, ASN, or list is required"})
		return
	}

	rule := config.IPRuleConfig{
		Name:          req.Name,
		Action:        req.Action,
		UpstreamGroup: req.UpstreamGroup,
		CIDRs:         req.CIDRs,
		ASNs:          req.ASNs,
	}
	for _, l := range req.Lists {
		rule.Lists = append(rule.Lists, config.IPListConfig{
			URL:     l.URL,
			Refresh: l.Refresh,
		})
	}

	if err := s.manager.AddIPRule(rule); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"name": req.Name, "status": "ok"})
}

func (s *Server) handleDeleteIPRule(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	name := strings.TrimPrefix(r.URL.Path, "/api/routing/ip-rules/")
	if name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "rule name is required"})
		return
	}

	if err := s.manager.DeleteIPRule(name); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleAddSNIRule(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Name          string   `json:"name"`
		Action        string   `json:"action"`
		UpstreamGroup string   `json:"upstream_group"`
		Domains       []string `json:"domains"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if req.Name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name is required"})
		return
	}
	if req.Action != "direct" && req.Action != "upstream" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "action must be 'direct' or 'upstream'"})
		return
	}
	if req.Action == "upstream" && req.UpstreamGroup == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "upstream_group is required for upstream action"})
		return
	}
	if len(req.Domains) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "at least one domain is required"})
		return
	}

	rule := config.SNIRuleConfig{
		Name:          req.Name,
		Action:        req.Action,
		UpstreamGroup: req.UpstreamGroup,
		Domains:       req.Domains,
	}

	if err := s.manager.AddSNIRule(rule); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"name": req.Name, "status": "ok"})
}

func (s *Server) handleSNIRulesItem(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodDelete:
		s.handleDeleteSNIRule(w, r)
	case http.MethodPut:
		s.handleUpdateSNIRule(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleDeleteSNIRule(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/api/routing/sni-rules/")
	if name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "rule name is required"})
		return
	}

	if err := s.manager.DeleteSNIRule(name); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleUpdateSNIRule(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/api/routing/sni-rules/")
	if name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "rule name is required"})
		return
	}

	var req struct {
		Action        string   `json:"action"`
		UpstreamGroup string   `json:"upstream_group"`
		Domains       []string `json:"domains"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if req.Action != "direct" && req.Action != "upstream" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "action must be 'direct' or 'upstream'"})
		return
	}
	if req.Action == "upstream" && req.UpstreamGroup == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "upstream_group is required for upstream action"})
		return
	}
	if len(req.Domains) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "at least one domain is required"})
		return
	}

	rule := config.SNIRuleConfig{
		Name:          name,
		Action:        req.Action,
		UpstreamGroup: req.UpstreamGroup,
		Domains:       req.Domains,
	}

	if err := s.manager.UpdateSNIRule(rule); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleReorderRoutingCIDRs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		CIDRs []string `json:"cidrs"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if len(req.CIDRs) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "cidrs list is required"})
		return
	}

	if err := s.manager.ReorderRoutingCIDRs(req.CIDRs); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleReorderIPRules(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Names []string `json:"names"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if len(req.Names) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "names list is required"})
		return
	}

	if err := s.manager.ReorderIPRules(req.Names); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleBackupDB(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.store == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "database not available"})
		return
	}

	password := r.URL.Query().Get("password")

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=bridge-backup-%s.db", time.Now().Format("20060102-150405")))
	w.Header().Set("Access-Control-Allow-Origin", "https://web.telegram.org")

	if password == "" {
		if err := s.store.Backup(w); err != nil {
			s.logger.Error("miniapp: backup failed", "err", err)
		}
		return
	}

	// Encrypt: read backup into buffer, then encrypt to response.
	var buf bytes.Buffer
	if err := s.store.Backup(&buf); err != nil {
		s.logger.Error("miniapp: backup failed", "err", err)
		return
	}
	if err := statsdb.EncryptBackup(w, &buf, password); err != nil {
		s.logger.Error("miniapp: encrypt backup failed", "err", err)
	}
}

func (s *Server) handleRestoreDB(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.store == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "database not available"})
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 100<<20) // 100 MB limit
	file, _, err := r.FormFile("file")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing file"})
		return
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "failed to read file"})
		return
	}

	var reader io.Reader
	if statsdb.IsEncryptedBackup(data) {
		password := r.FormValue("password")
		if password == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "backup is encrypted", "encrypted": true})
			return
		}
		var buf bytes.Buffer
		if err := statsdb.DecryptBackup(&buf, data, password); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "decryption failed — wrong password?"})
			return
		}
		reader = &buf
	} else {
		reader = bytes.NewReader(data)
	}

	if err := s.store.Restore(reader); err != nil {
		s.logger.Error("miniapp: restore failed", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	s.logger.Info("miniapp: database restored", "user_id", requestUserID(r))
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleRestart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.logger.Info("miniapp: restart requested", "user_id", requestUserID(r))
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})

	go func() {
		time.Sleep(500 * time.Millisecond)
		p, err := os.FindProcess(os.Getpid())
		if err != nil {
			s.logger.Error("miniapp: failed to find self process", "err", err)
			return
		}
		if err := p.Signal(syscall.SIGTERM); err != nil {
			s.logger.Error("miniapp: failed to send SIGTERM", "err", err)
		}
	}()
}

func (s *Server) handleResetDB(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := s.manager.ResetConfig(); err != nil {
		s.logger.Error("miniapp: reset failed", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	s.logger.Info("miniapp: instance reset", "user_id", requestUserID(r))
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func buildProxyLink(p config.ProxyServerConfig, serverIP string) string {
	_, port, _ := strings.Cut(p.Listen, ":")
	if port == "" {
		port = p.Listen
	}
	host := serverIP
	if p.Type == "https" && p.TLS.Domain != "" {
		host = p.TLS.Domain
	}
	scheme := p.Type
	if scheme == "socks5" {
		scheme = "socks5"
	}
	if p.Username != "" {
		return fmt.Sprintf("%s://%s:%s@%s:%s", scheme, p.Username, p.Password, host, port)
	}
	return fmt.Sprintf("%s://%s:%s", scheme, host, port)
}
