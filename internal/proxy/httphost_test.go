package proxy

import (
	"bufio"
	"strings"
	"testing"
)

func TestPeekHTTPHost(t *testing.T) {
	tests := []struct {
		name string
		data string
		want string
	}{
		{
			name: "GET with Host",
			data: "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
			want: "example.com",
		},
		{
			name: "GET with Host and port",
			data: "GET / HTTP/1.1\r\nHost: example.com:80\r\n\r\n",
			want: "example.com",
		},
		{
			name: "POST with Host",
			data: "POST /api HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 0\r\n\r\n",
			want: "api.example.com",
		},
		{
			name: "Host not first header",
			data: "GET / HTTP/1.1\r\nUser-Agent: test\r\nAccept: */*\r\nHost: late.example.com\r\n\r\n",
			want: "late.example.com",
		},
		{
			name: "case insensitive header name",
			data: "GET / HTTP/1.1\r\nhost: lower.example.com\r\n\r\n",
			want: "lower.example.com",
		},
		{
			name: "no Host header",
			data: "GET / HTTP/1.1\r\nUser-Agent: test\r\n\r\n",
			want: "",
		},
		{
			name: "not HTTP",
			data: "\x16\x03\x01\x00\x05hello",
			want: "",
		},
		{
			name: "empty input",
			data: "",
			want: "",
		},
		{
			name: "LF line endings",
			data: "GET / HTTP/1.1\nHost: lf.example.com\n\n",
			want: "lf.example.com",
		},
		{
			name: "Host with extra spaces",
			data: "GET / HTTP/1.1\r\nHost:   spaces.example.com  \r\n\r\n",
			want: "spaces.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			br := bufio.NewReaderSize(strings.NewReader(tt.data), 32*1024)
			got := PeekHTTPHost(br)
			if got != tt.want {
				t.Errorf("PeekHTTPHost() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestPeekHTTPHostNonDestructive(t *testing.T) {
	data := "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
	br := bufio.NewReaderSize(strings.NewReader(data), 32*1024)

	host := PeekHTTPHost(br)
	if host != "example.com" {
		t.Fatalf("PeekHTTPHost() = %q, want %q", host, "example.com")
	}

	// All original data should still be readable.
	buf := make([]byte, len(data))
	n, _ := br.Read(buf)
	if string(buf[:n]) != data {
		t.Errorf("data after peek = %q, want %q", string(buf[:n]), data)
	}
}
