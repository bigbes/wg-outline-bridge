package wireguard

import (
	"fmt"
	"log/slog"
	"net/netip"
	"sync"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	wgtun "golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// WGBackend implements Backend using standard wireguard-go.
type WGBackend struct{}

func (WGBackend) Name() string { return "wireguard" }

func (WGBackend) CreateTUN(localAddresses []netip.Addr, mtu int, logger *slog.Logger) (any, *stack.Stack, func() error, error) {
	tun, err := createNetTUN(localAddresses, mtu, logger)
	if err != nil {
		return nil, nil, nil, err
	}
	wrapper := &wgTUN{
		netTUNCore: tun,
		wgEvents:   make(chan wgtun.Event, 10),
	}
	wrapper.wgEvents <- wgtun.EventUp
	return wrapper, tun.Stack, wrapper.Close, nil
}

func (WGBackend) CreateDevice(tunDevice any, logger *slog.Logger, logLevel slog.Level) (Device, error) {
	td, ok := tunDevice.(wgtun.Device)
	if !ok {
		return nil, fmt.Errorf("expected wireguard tun.Device, got %T", tunDevice)
	}
	wgLog := newWGLogger(logger, logLevel)
	dev := device.NewDevice(td, conn.NewDefaultBind(), wgLog)
	return &wgDevice{dev: dev}, nil
}

// wgTUN wraps netTUNCore to implement wireguard-go's tun.Device.
type wgTUN struct {
	*netTUNCore
	wgEvents  chan wgtun.Event
	closeOnce sync.Once
}

func (t *wgTUN) Events() <-chan wgtun.Event { return t.wgEvents }

func (t *wgTUN) Close() error {
	t.closeOnce.Do(func() {
		close(t.wgEvents)
	})
	return t.netTUNCore.Close()
}

// wgDevice wraps wireguard-go's device.Device to implement our Device interface.
type wgDevice struct {
	dev *device.Device
}

func (d *wgDevice) IpcSet(config string) error { return d.dev.IpcSet(config) }
func (d *wgDevice) IpcGet() (string, error)    { return d.dev.IpcGet() }
func (d *wgDevice) Up() error                  { return d.dev.Up() }
func (d *wgDevice) Close()                     { d.dev.Close() }

func newWGLogger(logger *slog.Logger, level slog.Level) *device.Logger {
	wgLog := logger.With("component", "wireguard")
	l := &device.Logger{
		Errorf: func(format string, args ...any) {
			wgLog.Error(fmt.Sprintf(format, args...))
		},
	}
	l.Verbosef = func(format string, args ...any) {}
	if level <= slog.LevelDebug {
		l.Verbosef = func(format string, args ...any) {
			wgLog.Debug(fmt.Sprintf(format, args...))
		}
	}
	return l
}
