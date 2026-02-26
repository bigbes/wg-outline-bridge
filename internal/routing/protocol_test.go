package routing

import "testing"

func TestDetectTCPProtocol(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{
			name: "bittorrent handshake",
			data: append([]byte{19}, []byte("BitTorrent protocol")...),
			want: ProtocolBitTorrent,
		},
		{
			name: "bittorrent handshake with extra data",
			data: append(append([]byte{19}, []byte("BitTorrent protocol")...), make([]byte, 48)...),
			want: ProtocolBitTorrent,
		},
		{
			name: "TLS ClientHello",
			data: []byte{0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00},
			want: "",
		},
		{
			name: "HTTP GET",
			data: []byte("GET / HTTP/1.1\r\n"),
			want: "",
		},
		{
			name: "too short",
			data: []byte{19, 'B'},
			want: "",
		},
		{
			name: "empty",
			data: nil,
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DetectTCPProtocol(tt.data)
			if got != tt.want {
				t.Errorf("DetectTCPProtocol() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDetectUDPProtocol(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{
			name: "DHT query",
			data: []byte("d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe"),
			want: ProtocolBitTorrent,
		},
		{
			name: "DHT response",
			data: []byte("d1:rd2:id20:mnopqrstuvwxyz123456e1:t2:aa1:y1:re"),
			want: ProtocolBitTorrent,
		},
		{
			name: "UDP tracker connect",
			data: []byte{
				0x00, 0x00, 0x04, 0x17, 0x27, 0x10, 0x19, 0x80, // protocol_id = 0x41727101980
				0x00, 0x00, 0x00, 0x00, // action = 0 (connect)
				0x12, 0x34, 0x56, 0x78, // transaction_id
			},
			want: ProtocolBitTorrent,
		},
		{
			name: "DNS query",
			data: []byte{0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			want: "",
		},
		{
			name: "random data",
			data: []byte{0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa},
			want: "",
		},
		{
			name: "empty",
			data: nil,
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DetectUDPProtocol(tt.data)
			if got != tt.want {
				t.Errorf("DetectUDPProtocol() = %q, want %q", got, tt.want)
			}
		})
	}
}
