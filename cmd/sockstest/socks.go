package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

const (
	socks4Version = 0x04
	socks5Version = 0x05
)

const (
	cmdConnect      = 0x01
	cmdBind         = 0x02
	cmdUDPAssociate = 0x03
)

const (
	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04
)

const (
	authNone     = 0x00
	authPassword = 0x02
)

// --- High-level SOCKS4 ---

func socks4Connect(proxyAddr string, targetIP net.IP, targetPort int) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", proxyAddr, tcpTimeout)
	if err != nil {
		return nil, fmt.Errorf("connecting to proxy: %w", err)
	}
	if err := socks4Request(conn, cmdConnect, targetIP, targetPort); err != nil {
		conn.Close()
		return nil, err
	}
	if err := socks4ReadReply(conn); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

// socks4aConnectIP uses SOCKS4 wire format when target is an IP (same as socks4Connect).
func socks4aConnectIP(proxyAddr string, targetIP net.IP, targetPort int) (net.Conn, error) {
	return socks4Connect(proxyAddr, targetIP, targetPort)
}

func socks4aConnectHostname(proxyAddr string, hostname string, targetPort int) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", proxyAddr, tcpTimeout)
	if err != nil {
		return nil, fmt.Errorf("connecting to proxy: %w", err)
	}
	if err := socks4aHostnameRequest(conn, cmdConnect, hostname, targetPort); err != nil {
		conn.Close()
		return nil, err
	}
	if err := socks4ReadReply(conn); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func socks4Bind(proxyAddr string, targetIP net.IP, targetPort int) (net.Conn, net.IP, int, error) {
	conn, err := net.DialTimeout("tcp", proxyAddr, tcpTimeout)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("connecting to proxy: %w", err)
	}
	if err := socks4Request(conn, cmdBind, targetIP, targetPort); err != nil {
		conn.Close()
		return nil, nil, 0, err
	}
	ip, port, err := socks4ReadReplyAddr(conn)
	if err != nil {
		conn.Close()
		return nil, nil, 0, fmt.Errorf("reading bind reply: %w", err)
	}
	if ip.IsUnspecified() {
		proxyHost, _, _ := net.SplitHostPort(proxyAddr)
		ip = net.ParseIP(proxyHost)
	}
	return conn, ip, port, nil
}

func socks4WaitConnect(conn net.Conn) error {
	return socks4ReadReply(conn)
}

// --- High-level SOCKS5 ---

func socks5Connect(proxyAddr string, targetIP net.IP, targetPort int) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", proxyAddr, tcpTimeout)
	if err != nil {
		return nil, fmt.Errorf("connecting to proxy: %w", err)
	}
	if err := socks5Greet(conn, false); err != nil {
		conn.Close()
		return nil, err
	}
	if err := socks5IPRequest(conn, cmdConnect, targetIP, targetPort); err != nil {
		conn.Close()
		return nil, err
	}
	if _, _, _, err := socks5ReadReply(conn); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func socks5ConnectHostname(proxyAddr string, hostname string, targetPort int) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", proxyAddr, tcpTimeout)
	if err != nil {
		return nil, fmt.Errorf("connecting to proxy: %w", err)
	}
	if err := socks5Greet(conn, false); err != nil {
		conn.Close()
		return nil, err
	}
	if err := socks5HostnameRequest(conn, cmdConnect, hostname, targetPort); err != nil {
		conn.Close()
		return nil, err
	}
	if _, _, _, err := socks5ReadReply(conn); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func socks5AuthConnect(proxyAddr string, targetIP net.IP, targetPort int, username, password string) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", proxyAddr, tcpTimeout)
	if err != nil {
		return nil, fmt.Errorf("connecting to proxy: %w", err)
	}
	if err := socks5Greet(conn, true); err != nil {
		conn.Close()
		return nil, err
	}
	if err := socks5Authenticate(conn, username, password); err != nil {
		conn.Close()
		return nil, err
	}
	if err := socks5IPRequest(conn, cmdConnect, targetIP, targetPort); err != nil {
		conn.Close()
		return nil, err
	}
	if _, _, _, err := socks5ReadReply(conn); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func socks5BindRequest(proxyAddr string, targetIP net.IP, targetPort int) (net.Conn, net.IP, int, error) {
	conn, err := net.DialTimeout("tcp", proxyAddr, tcpTimeout)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("connecting to proxy: %w", err)
	}
	if err := socks5Greet(conn, false); err != nil {
		conn.Close()
		return nil, nil, 0, err
	}
	if err := socks5IPRequest(conn, cmdBind, targetIP, targetPort); err != nil {
		conn.Close()
		return nil, nil, 0, err
	}
	_, addr, port, err := socks5ReadReply(conn)
	if err != nil {
		conn.Close()
		return nil, nil, 0, fmt.Errorf("reading bind reply: %w", err)
	}
	if addr.IsUnspecified() {
		proxyHost, _, _ := net.SplitHostPort(proxyAddr)
		addr = net.ParseIP(proxyHost)
	}
	return conn, addr, port, nil
}

func socks5WaitConnect(conn net.Conn) error {
	_, _, _, err := socks5ReadReply(conn)
	return err
}

func socks5UDPAssociate(proxyAddr string) (net.Conn, *net.UDPAddr, *net.UDPConn, error) {
	conn, err := net.DialTimeout("tcp", proxyAddr, tcpTimeout)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("connecting to proxy: %w", err)
	}
	if err := socks5Greet(conn, false); err != nil {
		conn.Close()
		return nil, nil, nil, err
	}
	if err := socks5IPRequest(conn, cmdUDPAssociate, net.IPv4zero, 0); err != nil {
		conn.Close()
		return nil, nil, nil, err
	}
	_, addr, port, err := socks5ReadReply(conn)
	if err != nil {
		conn.Close()
		return nil, nil, nil, fmt.Errorf("reading udp associate reply: %w", err)
	}
	if addr.IsUnspecified() {
		proxyHost, _, _ := net.SplitHostPort(proxyAddr)
		addr = net.ParseIP(proxyHost)
	}
	relayAddr := &net.UDPAddr{IP: addr, Port: port}
	debugf("UDP relay address: %s", relayAddr)

	localUDP, err := net.ListenUDP("udp", nil)
	if err != nil {
		conn.Close()
		return nil, nil, nil, fmt.Errorf("creating local UDP socket: %w", err)
	}
	return conn, relayAddr, localUDP, nil
}

// --- Low-level SOCKS4 protocol ---

func socks4Request(conn net.Conn, cmd byte, ip net.IP, port int) error {
	ip4 := ip.To4()
	if ip4 == nil {
		return fmt.Errorf("SOCKS4 requires IPv4 address")
	}
	buf := make([]byte, 9)
	buf[0] = socks4Version
	buf[1] = cmd
	binary.BigEndian.PutUint16(buf[2:4], uint16(port))
	copy(buf[4:8], ip4)
	buf[8] = 0x00 // null-terminated empty userid
	debugf("socks4: sending request cmd=%d to %s:%d", cmd, ip, port)
	_, err := conn.Write(buf)
	return err
}

func socks4aHostnameRequest(conn net.Conn, cmd byte, hostname string, port int) error {
	buf := make([]byte, 0, 10+len(hostname))
	buf = append(buf, socks4Version, cmd)
	buf = binary.BigEndian.AppendUint16(buf, uint16(port))
	buf = append(buf, 0, 0, 0, 1) // 0.0.0.1 = SOCKS4a marker
	buf = append(buf, 0x00)       // null-terminated empty userid
	buf = append(buf, []byte(hostname)...)
	buf = append(buf, 0x00) // null-terminated hostname
	debugf("socks4a: sending hostname request to %s:%d", hostname, port)
	_, err := conn.Write(buf)
	return err
}

func socks4ReadReply(conn net.Conn) error {
	_, _, err := socks4ReadReplyAddr(conn)
	return err
}

func socks4ReadReplyAddr(conn net.Conn) (net.IP, int, error) {
	var reply [8]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		return nil, 0, fmt.Errorf("reading SOCKS4 reply: %w", err)
	}
	if reply[0] != 0x00 {
		return nil, 0, fmt.Errorf("unexpected SOCKS4 reply version: %d", reply[0])
	}
	if reply[1] != 0x5A {
		return nil, 0, fmt.Errorf("SOCKS4 request rejected, code: %d", reply[1])
	}
	port := int(binary.BigEndian.Uint16(reply[2:4]))
	ip := make(net.IP, 4)
	copy(ip, reply[4:8])
	debugf("socks4: reply addr=%s:%d", ip, port)
	return ip, port, nil
}

// --- Low-level SOCKS5 protocol ---

func socks5Greet(conn net.Conn, useAuth bool) error {
	method := byte(authNone)
	if useAuth {
		method = authPassword
	}
	greeting := []byte{socks5Version, 0x01, method}
	if _, err := conn.Write(greeting); err != nil {
		return fmt.Errorf("sending SOCKS5 greeting: %w", err)
	}
	var reply [2]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		return fmt.Errorf("reading SOCKS5 greeting reply: %w", err)
	}
	if reply[0] != socks5Version {
		return fmt.Errorf("unexpected SOCKS5 version: %d", reply[0])
	}
	if reply[1] != method {
		return fmt.Errorf("proxy selected unexpected auth method: %d (expected %d)", reply[1], method)
	}
	debugf("socks5: greeting ok, method=%d", method)
	return nil
}

func socks5Authenticate(conn net.Conn, username, password string) error {
	buf := make([]byte, 0, 3+len(username)+len(password))
	buf = append(buf, 0x01)                // sub-negotiation version
	buf = append(buf, byte(len(username)))
	buf = append(buf, []byte(username)...)
	buf = append(buf, byte(len(password)))
	buf = append(buf, []byte(password)...)
	if _, err := conn.Write(buf); err != nil {
		return fmt.Errorf("sending SOCKS5 auth: %w", err)
	}
	var reply [2]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		return fmt.Errorf("reading SOCKS5 auth reply: %w", err)
	}
	if reply[1] != 0x00 {
		return fmt.Errorf("SOCKS5 authentication failed, status: %d", reply[1])
	}
	debugf("socks5: auth ok")
	return nil
}

func socks5IPRequest(conn net.Conn, cmd byte, ip net.IP, port int) error {
	ip4 := ip.To4()
	if ip4 != nil {
		buf := make([]byte, 10)
		buf[0] = socks5Version
		buf[1] = cmd
		buf[2] = 0x00
		buf[3] = atypIPv4
		copy(buf[4:8], ip4)
		binary.BigEndian.PutUint16(buf[8:10], uint16(port))
		debugf("socks5: sending request cmd=%d to %s:%d", cmd, ip, port)
		_, err := conn.Write(buf)
		return err
	}
	ip16 := ip.To16()
	if ip16 == nil {
		return fmt.Errorf("invalid IP address")
	}
	buf := make([]byte, 22)
	buf[0] = socks5Version
	buf[1] = cmd
	buf[2] = 0x00
	buf[3] = atypIPv6
	copy(buf[4:20], ip16)
	binary.BigEndian.PutUint16(buf[20:22], uint16(port))
	debugf("socks5: sending request cmd=%d to [%s]:%d", cmd, ip, port)
	_, err := conn.Write(buf)
	return err
}

func socks5HostnameRequest(conn net.Conn, cmd byte, hostname string, port int) error {
	buf := make([]byte, 0, 7+len(hostname))
	buf = append(buf, socks5Version, cmd, 0x00, atypDomain)
	buf = append(buf, byte(len(hostname)))
	buf = append(buf, []byte(hostname)...)
	buf = binary.BigEndian.AppendUint16(buf, uint16(port))
	debugf("socks5: sending hostname request cmd=%d to %s:%d", cmd, hostname, port)
	_, err := conn.Write(buf)
	return err
}

func socks5ReadReply(conn net.Conn) (byte, net.IP, int, error) {
	var header [4]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return 0, nil, 0, fmt.Errorf("reading SOCKS5 reply header: %w", err)
	}
	if header[0] != socks5Version {
		return 0, nil, 0, fmt.Errorf("unexpected SOCKS5 version: %d", header[0])
	}
	if header[1] != 0x00 {
		return 0, nil, 0, fmt.Errorf("SOCKS5 request failed, rep: %d", header[1])
	}
	atyp := header[3]
	var addr net.IP
	switch atyp {
	case atypIPv4:
		buf := make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return 0, nil, 0, fmt.Errorf("reading IPv4 addr: %w", err)
		}
		addr = net.IP(buf)
	case atypIPv6:
		buf := make([]byte, 16)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return 0, nil, 0, fmt.Errorf("reading IPv6 addr: %w", err)
		}
		addr = net.IP(buf)
	case atypDomain:
		var lenBuf [1]byte
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			return 0, nil, 0, fmt.Errorf("reading domain length: %w", err)
		}
		domainBuf := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(conn, domainBuf); err != nil {
			return 0, nil, 0, fmt.Errorf("reading domain: %w", err)
		}
		ips, err := net.LookupIP(string(domainBuf))
		if err != nil || len(ips) == 0 {
			addr = net.IPv4zero
		} else {
			addr = ips[0]
		}
	default:
		return 0, nil, 0, fmt.Errorf("unsupported address type: %d", atyp)
	}
	var portBuf [2]byte
	if _, err := io.ReadFull(conn, portBuf[:]); err != nil {
		return 0, nil, 0, fmt.Errorf("reading port: %w", err)
	}
	port := int(binary.BigEndian.Uint16(portBuf[:]))
	debugf("socks5: reply atyp=%d addr=%s port=%d", atyp, addr, port)
	return atyp, addr, port, nil
}

// --- SOCKS5 UDP relay helpers ---

func buildUDPHeader(targetIP net.IP, targetPort int) []byte {
	ip4 := targetIP.To4()
	if ip4 != nil {
		buf := make([]byte, 10)
		// RSV(2) = 0, FRAG(1) = 0
		buf[3] = atypIPv4
		copy(buf[4:8], ip4)
		binary.BigEndian.PutUint16(buf[8:10], uint16(targetPort))
		return buf
	}
	ip16 := targetIP.To16()
	buf := make([]byte, 22)
	buf[3] = atypIPv6
	copy(buf[4:20], ip16)
	binary.BigEndian.PutUint16(buf[20:22], uint16(targetPort))
	return buf
}

func parseUDPRelay(packet []byte) ([]byte, error) {
	if len(packet) < 10 {
		return nil, fmt.Errorf("UDP relay packet too short: %d bytes", len(packet))
	}
	atyp := packet[3]
	var headerLen int
	switch atyp {
	case atypIPv4:
		headerLen = 4 + 4 + 2
	case atypIPv6:
		headerLen = 4 + 16 + 2
	case atypDomain:
		if len(packet) < 5 {
			return nil, fmt.Errorf("UDP relay packet too short for domain")
		}
		headerLen = 4 + 1 + int(packet[4]) + 2
	default:
		return nil, fmt.Errorf("unsupported address type in UDP relay: %d", atyp)
	}
	if len(packet) < headerLen {
		return nil, fmt.Errorf("UDP relay packet too short: %d < %d", len(packet), headerLen)
	}
	return packet[headerLen:], nil
}
