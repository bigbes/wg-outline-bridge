package outline

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
)

// dialer is the interface satisfied by Client and SwappableClient.
type dialer interface {
	DialStream(ctx context.Context, addr string) (net.Conn, error)
	DialPacket(ctx context.Context, addr string) (net.Conn, error)
}

// StatsSnapshot holds a point-in-time copy of dialer statistics.
type StatsSnapshot struct {
	RxBytes           int64
	TxBytes           int64
	ActiveConnections int64
}

// StatsDialer wraps a dialer and tracks bytes transferred and active connections.
type StatsDialer struct {
	Name  string
	up    dialer
	rx    atomic.Int64
	tx    atomic.Int64
	conns atomic.Int64
}

// NewStatsDialer creates a StatsDialer that delegates to up.
func NewStatsDialer(name string, up dialer) *StatsDialer {
	return &StatsDialer{
		Name: name,
		up:   up,
	}
}

// Snapshot returns a point-in-time snapshot of the stats.
func (s *StatsDialer) Snapshot() StatsSnapshot {
	return StatsSnapshot{
		RxBytes:           s.rx.Load(),
		TxBytes:           s.tx.Load(),
		ActiveConnections: s.conns.Load(),
	}
}

// DialStream dials a stream connection and wraps it with stats tracking.
func (s *StatsDialer) DialStream(ctx context.Context, addr string) (net.Conn, error) {
	conn, err := s.up.DialStream(ctx, addr)
	if err != nil {
		return nil, err
	}
	s.conns.Add(1)
	return &statsConn{Conn: conn, sd: s}, nil
}

// DialPacket dials a packet connection and wraps it with stats tracking.
func (s *StatsDialer) DialPacket(ctx context.Context, addr string) (net.Conn, error) {
	conn, err := s.up.DialPacket(ctx, addr)
	if err != nil {
		return nil, err
	}
	s.conns.Add(1)
	return &statsConn{Conn: conn, sd: s}, nil
}

type statsConn struct {
	net.Conn
	sd        *StatsDialer
	closeOnce sync.Once
}

func (c *statsConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.sd.rx.Add(int64(n))
	}
	return n, err
}

func (c *statsConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.sd.tx.Add(int64(n))
	}
	return n, err
}

func (c *statsConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		c.sd.conns.Add(-1)
		err = c.Conn.Close()
	})
	return err
}
