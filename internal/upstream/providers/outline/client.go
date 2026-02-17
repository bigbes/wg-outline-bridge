package outline

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"

	"golang.getoutline.org/sdk/transport"
	"golang.getoutline.org/sdk/x/configurl"
)

// Client wraps Outline SDK stream and packet dialers.
type Client struct {
	StreamDialer transport.StreamDialer
	PacketDialer transport.PacketDialer
}

// NewClient creates a new Outline client from a transport config URI.
func NewClient(transportConfig string) (*Client, error) {
	providers := configurl.NewDefaultProviders()
	ctx := context.Background()

	streamDialer, err := providers.NewStreamDialer(ctx, transportConfig)
	if err != nil {
		return nil, fmt.Errorf("creating stream dialer: %w", err)
	}

	packetDialer, err := providers.NewPacketDialer(ctx, transportConfig)
	if err != nil {
		return nil, fmt.Errorf("creating packet dialer: %w", err)
	}

	return &Client{
		StreamDialer: streamDialer,
		PacketDialer: packetDialer,
	}, nil
}

// DialStream connects via the stream dialer.
func (c *Client) DialStream(ctx context.Context, addr string) (net.Conn, error) {
	return c.StreamDialer.DialStream(ctx, addr)
}

// DialPacket connects via the packet dialer.
func (c *Client) DialPacket(ctx context.Context, addr string) (net.Conn, error) {
	return c.PacketDialer.DialPacket(ctx, addr)
}

// SwappableClient wraps an atomically-swappable Client.
type SwappableClient struct {
	client atomic.Pointer[Client]
}

// NewSwappableClient creates a SwappableClient with an initial client.
func NewSwappableClient(c *Client) *SwappableClient {
	s := &SwappableClient{}
	s.client.Store(c)
	return s
}

// Swap atomically replaces the underlying client.
func (s *SwappableClient) Swap(c *Client) {
	s.client.Store(c)
}

// Get returns the current client.
func (s *SwappableClient) Get() *Client {
	return s.client.Load()
}

// DialStream delegates to the current client.
func (s *SwappableClient) DialStream(ctx context.Context, addr string) (net.Conn, error) {
	return s.Get().DialStream(ctx, addr)
}

// DialPacket delegates to the current client.
func (s *SwappableClient) DialPacket(ctx context.Context, addr string) (net.Conn, error) {
	return s.Get().DialPacket(ctx, addr)
}
