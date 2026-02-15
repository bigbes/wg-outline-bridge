package wireguard

import (
	"fmt"
	"log/slog"
	"net/netip"
	"sync"

	awgconn "github.com/amnezia-vpn/amneziawg-go/conn"
	awgdevice "github.com/amnezia-vpn/amneziawg-go/device"
	awgtun "github.com/amnezia-vpn/amneziawg-go/tun"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// AWGBackend implements Backend using amneziawg-go.
type AWGBackend struct{}

func (AWGBackend) Name() string { return "amneziawg" }

func (AWGBackend) CreateTUN(localAddresses []netip.Addr, mtu int, logger *slog.Logger) (any, *stack.Stack, func() error, error) {
	tun, err := createNetTUN(localAddresses, mtu, logger)
	if err != nil {
		return nil, nil, nil, err
	}
	wrapper := &awgTUN{
		netTUNCore: tun,
		awgEvents:  make(chan awgtun.Event, 10),
	}
	wrapper.awgEvents <- awgtun.EventUp
	return wrapper, tun.Stack, wrapper.Close, nil
}

func (AWGBackend) CreateDevice(tunDevice any, logger *slog.Logger, logLevel slog.Level) (Device, error) {
	td, ok := tunDevice.(awgtun.Device)
	if !ok {
		return nil, fmt.Errorf("expected amneziawg tun.Device, got %T", tunDevice)
	}
	awgLog := newAWGLogger(logger, logLevel)
	dev := awgdevice.NewDevice(td, awgconn.NewDefaultBind(), awgLog)
	return &awgDev{dev: dev}, nil
}

// awgTUN wraps netTUNCore to implement amneziawg-go's tun.Device.
type awgTUN struct {
	*netTUNCore
	awgEvents chan awgtun.Event
	closeOnce sync.Once
}

func (t *awgTUN) Events() <-chan awgtun.Event { return t.awgEvents }

func (t *awgTUN) Close() error {
	t.closeOnce.Do(func() {
		close(t.awgEvents)
	})
	return t.netTUNCore.Close()
}

// awgDev wraps amneziawg-go's device.Device to implement our Device interface.
type awgDev struct {
	dev *awgdevice.Device
}

func (d *awgDev) IpcSet(config string) error { return d.dev.IpcSet(config) }
func (d *awgDev) IpcGet() (string, error)    { return d.dev.IpcGet() }
func (d *awgDev) Up() error                  { return d.dev.Up() }
func (d *awgDev) Close()                     { d.dev.Close() }

func newAWGLogger(logger *slog.Logger, level slog.Level) *awgdevice.Logger {
	wgLog := logger.With("component", "amneziawg")
	l := &awgdevice.Logger{
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
