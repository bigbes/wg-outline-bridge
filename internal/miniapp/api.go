package miniapp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/blikh/wireguard-outline-bridge/internal/config"
)

type statusResponse struct {
	Daemon  daemonInfo   `json:"daemon"`
	Peers   []peerInfo   `json:"peers"`
	MTProxy mtproxyInfo  `json:"mtproxy"`
	Proxies []proxyInfo  `json:"proxies"`
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
	Enabled           bool             `json:"enabled"`
	Connections       int64            `json:"connections"`
	ActiveConnections int64            `json:"active_connections"`
	BytesC2B          int64            `json:"bytes_c2b"`
	BytesB2C          int64            `json:"bytes_b2c"`
	BytesC2BTotal     int64            `json:"bytes_c2b_total"`
	BytesB2CTotal     int64            `json:"bytes_b2c_total"`
	Secrets           []secretInfo     `json:"secrets"`
	Links             []string         `json:"links"`
}

type secretInfo struct {
	Secret          string `json:"secret"`
	LastConnection  int64  `json:"last_connection_unix"`
	Connections     int64  `json:"connections"`
	ConnectionsTotal int64 `json:"connections_total"`
	BytesC2B        int64  `json:"bytes_c2b"`
	BytesB2C        int64  `json:"bytes_b2c"`
}

type proxyInfo struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Listen   string `json:"listen"`
	Outline  string `json:"outline"`
	HasAuth  bool   `json:"has_auth"`
	Link     string `json:"link"`
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

	// MTProxy.
	resp.MTProxy = mtproxyInfo{
		Enabled:           mt.Enabled,
		Connections:       mt.Connections,
		ActiveConnections: mt.ActiveConnections,
		BytesC2B:          mt.BytesC2B,
		BytesB2C:          mt.BytesB2C,
		BytesC2BTotal:     mt.BytesC2BTotal,
		BytesB2CTotal:     mt.BytesB2CTotal,
		Links:             config.ProxyLinks(cfg),
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
			Name:    p.Name,
			Type:    p.Type,
			Listen:  p.Listen,
			Outline: p.Outline,
			HasAuth: p.Username != "",
			Link:    buildProxyLink(p, serverIP),
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

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
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
