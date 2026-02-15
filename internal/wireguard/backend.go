package wireguard

import (
	"log/slog"
	"net/netip"

	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// Device abstracts over wireguard-go and amneziawg-go devices.
type Device interface {
	IpcSet(config string) error
	IpcGet() (string, error)
	Up() error
	Close()
}

// Backend creates WireGuard or AmneziaWG devices and TUN adapters.
type Backend interface {
	// CreateTUN creates a netstack TUN device and returns it along with
	// the gVisor stack. The returned tunDevice must be passed to CreateDevice.
	CreateTUN(localAddresses []netip.Addr, mtu int, logger *slog.Logger) (tunDevice any, netStack *stack.Stack, closer func() error, err error)

	// CreateDevice creates a WireGuard/AmneziaWG device from the TUN device
	// returned by CreateTUN.
	CreateDevice(tunDevice any, logger *slog.Logger, logLevel slog.Level) (Device, error)

	// Name returns "wireguard" or "amneziawg".
	Name() string
}

// NewBackend returns the appropriate Backend for the given mode.
func NewBackend(mode string) Backend {
	switch mode {
	case "amneziawg":
		return AWGBackend{}
	default:
		return WGBackend{}
	}
}
