package frontend

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed web/*
var defaultWebFS embed.FS

// newHTTPHandler returns an http.Handler that serves static files.
// If dir is non-empty, files are served from disk; otherwise embedded defaults are used.
// Used by both the HTTP/2 (TCP TLS fallback) and HTTP/3 (QUIC) servers.
func newHTTPHandler(dir string) http.Handler {
	if dir != "" {
		return http.FileServer(http.Dir(dir))
	}
	sub, _ := fs.Sub(defaultWebFS, "web")
	return http.FileServer(http.FS(sub))
}
