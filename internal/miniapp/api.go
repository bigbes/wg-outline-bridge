package miniapp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/blikh/wireguard-outline-bridge/internal/config"
	"github.com/blikh/wireguard-outline-bridge/internal/statsdb"
)

type statusResponse struct {
	Daemon    daemonInfo     `json:"daemon"`
	Peers     []peerInfo     `json:"peers"`
	Outlines  []outlineInfo  `json:"outlines"`
	Upstreams []upstreamInfo `json:"upstreams"`
	MTProxy   mtproxyInfo    `json:"mtproxy"`
	Proxies   []proxyInfo    `json:"proxies"`
}

type daemonInfo struct {
	UptimeSeconds int64 `json:"uptime_seconds"`
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
}

type mtproxyInfo struct {
	Enabled           bool               `json:"enabled"`
	Connections       int64              `json:"connections"`
	ActiveConnections int64              `json:"active_connections"`
	BytesC2B          int64              `json:"bytes_c2b"`
	BytesB2C          int64              `json:"bytes_b2c"`
	BytesC2BTotal     int64              `json:"bytes_c2b_total"`
	BytesB2CTotal     int64              `json:"bytes_b2c_total"`
	Secrets           []secretInfo       `json:"secrets"`
	Links             []config.ProxyLink `json:"links"`
}

type secretInfo struct {
	Secret           string `json:"secret"`
	LastConnection   int64  `json:"last_connection_unix"`
	Connections      int64  `json:"connections"`
	ConnectionsTotal int64  `json:"connections_total"`
	BytesC2B         int64  `json:"bytes_c2b"`
	BytesB2C         int64  `json:"bytes_b2c"`
}

type outlineInfo struct {
	Name              string `json:"name"`
	Default           bool   `json:"default"`
	RxBytes           int64  `json:"rx_bytes"`
	TxBytes           int64  `json:"tx_bytes"`
	ActiveConnections int64  `json:"active_connections"`
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
	Outline       string `json:"outline,omitempty"`
	UpstreamGroup string `json:"upstream_group,omitempty"`
	HasAuth       bool   `json:"has_auth"`
	Link          string `json:"link"`
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

	resp := statusResponse{
		Daemon: daemonInfo{
			UptimeSeconds: uptimeSec,
		},
	}

	// Peers.
	allPeers := cfg.Peers
	for _, p := range peers {
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

	// Outlines (backward compat).
	for _, o := range s.provider.OutlineStatuses() {
		resp.Outlines = append(resp.Outlines, outlineInfo{
			Name:              o.Name,
			Default:           o.Default,
			RxBytes:           o.RxBytes,
			TxBytes:           o.TxBytes,
			ActiveConnections: o.ActiveConnections,
		})
	}

	// MTProxy.
	resp.MTProxy = mtproxyInfo{
		Enabled:           mt.Enabled,
		Connections:       mt.Connections,
		ActiveConnections: mt.ActiveConnections,
		BytesC2B:          mt.BytesC2B,
		BytesB2C:          mt.BytesB2C,
		BytesC2BTotal:     mt.BytesC2BTotal,
		BytesB2CTotal:     mt.BytesB2CTotal,
		Links:             s.proxyLinks(cfg),
	}
	for _, c := range mt.Clients {
		resp.MTProxy.Secrets = append(resp.MTProxy.Secrets, secretInfo{
			Secret:           c.Secret,
			LastConnection:   c.LastConnection.Unix(),
			Connections:      c.Connections,
			ConnectionsTotal: c.ConnectionsTotal,
			BytesC2B:         c.BytesC2B,
			BytesB2C:         c.BytesB2C,
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
			Outline:       p.Outline,
			UpstreamGroup: p.UpstreamGroup,
			HasAuth:       p.Username != "",
			Link:          buildProxyLink(p, serverIP),
		}
		resp.Proxies = append(resp.Proxies, pi)
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

	peer, err := s.manager.AddPeer(req.Name)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
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

	if err := s.manager.DeletePeer(name); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
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

	secretHex, err := s.manager.AddSecret(req.Type, req.Comment)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"secret": secretHex})
}

func (s *Server) handleSecretsRoute(w http.ResponseWriter, r *http.Request) {
	if strings.HasSuffix(r.URL.Path, "/name") {
		s.handleRenameSecret(w, r)
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

func (s *Server) handleAddProxy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Name     string `json:"name"`
		Type     string `json:"type"`
		Listen   string `json:"listen"`
		Outline  string `json:"outline"`
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
		Outline:  req.Outline,
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
			copy := cfg.Upstreams[i]
			existing = &copy
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

func (s *Server) handleGroups(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

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
		if g == "" && p.Outline == "" {
			g = "default"
		}
		if g != "" {
			ensureGroup(g).Consumers = append(ensureGroup(g).Consumers, groupConsumer{Type: "proxy", Name: p.Name})
		}
	}
	for _, r := range cfg.Routing.IPRules {
		g := r.UpstreamGroup
		if g == "" && r.Outline == "" {
			g = "default"
		}
		if g != "" {
			ensureGroup(g).Consumers = append(ensureGroup(g).Consumers, groupConsumer{Type: "ip_rule", Name: r.Name})
		}
	}
	for _, r := range cfg.Routing.SNIRules {
		g := r.UpstreamGroup
		if g == "" && r.Outline == "" {
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

	result := make([]groupInfo, 0, len(groups))
	for _, g := range groups {
		result = append(result, *g)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Name < result[j].Name
	})

	writeJSON(w, http.StatusOK, result)
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
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
	for _, uid := range s.allowedUsers {
		if uid == userID {
			return true
		}
	}
	return false
}

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	type userResp struct {
		UserID    int64  `json:"user_id"`
		Username  string `json:"username"`
		FirstName string `json:"first_name"`
		LastName  string `json:"last_name"`
		PhotoURL  string `json:"photo_url"`
		CreatedAt int64  `json:"created_at"`
		IsAdmin   bool   `json:"is_admin"`
	}

	var out []userResp

	// Config admins are always listed first and cannot be deleted.
	configAdminSet := make(map[int64]bool)
	for _, uid := range s.allowedUsers {
		configAdminSet[uid] = true
		out = append(out, userResp{
			UserID:  uid,
			IsAdmin: true,
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
						out[i].CreatedAt = u.CreatedAt
						break
					}
				}
				continue
			}
			out = append(out, userResp{
				UserID:    u.UserID,
				Username:  u.Username,
				FirstName: u.FirstName,
				LastName:  u.LastName,
				PhotoURL:  u.PhotoURL,
				CreatedAt: u.CreatedAt,
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
		User string `json:"user"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if req.User == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "user is required (@username or numeric ID)"})
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
		u = statsdb.AllowedUser{UserID: numericID}
	} else {
		var photoURL string
		if info.Photo != nil && info.Photo.SmallFileID != "" {
			if fileURL, err := s.bot.GetFileURL(r.Context(), info.Photo.SmallFileID); err == nil {
				photoURL = fileURL
			}
		}
		u = statsdb.AllowedUser{
			UserID:    info.ID,
			Username:  info.Username,
			FirstName: info.FirstName,
			LastName:  info.LastName,
			PhotoURL:  photoURL,
		}
	}

	if err := s.store.AddAllowedUser(u); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"user_id":    u.UserID,
		"username":   u.Username,
		"first_name": u.FirstName,
		"last_name":  u.LastName,
		"photo_url":  u.PhotoURL,
	})
}

func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

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

	deleted, err := s.store.DeleteAllowedUser(userID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if !deleted {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
		return
	}

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
		return fmt.Sprintf("%s://%s:***@%s:%s", scheme, p.Username, host, port)
	}
	return fmt.Sprintf("%s://%s:%s", scheme, host, port)
}
