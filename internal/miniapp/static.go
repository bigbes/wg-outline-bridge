package miniapp

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed web/*
var webFS embed.FS

func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) {
	sub, err := fs.Sub(webFS, "web")
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Try to serve the exact file.
	path := strings.TrimPrefix(r.URL.Path, "/")
	if path == "" {
		path = "index.html"
	}

	if _, err := fs.Stat(sub, path); err == nil {
		http.FileServer(http.FS(sub)).ServeHTTP(w, r)
		return
	}

	// SPA fallback: serve index.html for unknown paths (non-API).
	if !strings.HasPrefix(r.URL.Path, "/api/") {
		r.URL.Path = "/"
		http.FileServer(http.FS(sub)).ServeHTTP(w, r)
		return
	}

	http.NotFound(w, r)
}
