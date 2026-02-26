package proxy

import (
	"bufio"
	"bytes"
	"strings"
)

// PeekHTTPHost non-destructively reads the beginning of an HTTP request
// from br and returns the value of the Host header, stripped of any port.
// Returns "" if the data does not look like an HTTP request or no Host
// header is found.
func PeekHTTPHost(br *bufio.Reader) string {
	// Peek enough to cover the request line + headers.
	// Most HTTP requests have Host within the first few hundred bytes.
	peeked, _ := br.Peek(4096)
	if len(peeked) == 0 {
		return ""
	}

	// Quick sanity check: first bytes must be an HTTP method.
	if !looksLikeHTTP(peeked) {
		return ""
	}

	// Find end of request line.
	idx := bytes.IndexByte(peeked, '\n')
	if idx < 0 {
		return ""
	}
	headers := peeked[idx+1:]

	// Scan header lines for "Host:".
	for len(headers) > 0 {
		lineEnd := bytes.IndexByte(headers, '\n')
		var line []byte
		if lineEnd < 0 {
			line = headers
			headers = nil
		} else {
			line = headers[:lineEnd]
			headers = headers[lineEnd+1:]
		}

		line = bytes.TrimRight(line, "\r")

		// Empty line = end of headers.
		if len(line) == 0 {
			break
		}

		colon := bytes.IndexByte(line, ':')
		if colon < 0 {
			continue
		}
		name := string(bytes.TrimSpace(line[:colon]))
		if !strings.EqualFold(name, "Host") {
			continue
		}
		host := strings.TrimSpace(string(line[colon+1:]))
		// Strip port if present (e.g. "example.com:80" -> "example.com").
		if h, _, ok := strings.Cut(host, ":"); ok {
			host = h
		}
		return host
	}

	return ""
}

// looksLikeHTTP returns true if data starts with a known HTTP method.
func looksLikeHTTP(data []byte) bool {
	methods := []string{
		"GET ", "POST ", "PUT ", "DELETE ",
		"HEAD ", "OPTIONS ", "PATCH ", "CONNECT ",
	}
	for _, m := range methods {
		if len(data) >= len(m) && string(data[:len(m)]) == m {
			return true
		}
	}
	return false
}
