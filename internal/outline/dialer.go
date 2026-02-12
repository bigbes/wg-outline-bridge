package outline

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"

	"golang.getoutline.org/sdk/transport"
	"golang.getoutline.org/sdk/x/configurl"
)

type Client struct {
	StreamDialer transport.StreamDialer
	PacketDialer transport.PacketDialer
}

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

func (c *Client) DialStream(ctx context.Context, addr string) (net.Conn, error) {
	return c.StreamDialer.DialStream(ctx, addr)
}

func (c *Client) DialPacket(ctx context.Context, addr string) (net.Conn, error) {
	return c.PacketDialer.DialPacket(ctx, addr)
}

type SwappableClient struct {
	client atomic.Pointer[Client]
}

func NewSwappableClient(c *Client) *SwappableClient {
	s := &SwappableClient{}
	s.client.Store(c)
	return s
}

func (s *SwappableClient) Swap(c *Client) {
	s.client.Store(c)
}

func (s *SwappableClient) Get() *Client {
	return s.client.Load()
}

func (s *SwappableClient) DialStream(ctx context.Context, addr string) (net.Conn, error) {
	return s.Get().DialStream(ctx, addr)
}

func (s *SwappableClient) DialPacket(ctx context.Context, addr string) (net.Conn, error) {
	return s.Get().DialPacket(ctx, addr)
}
