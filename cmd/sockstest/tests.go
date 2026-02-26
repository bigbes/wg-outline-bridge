package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

func readAll(conn net.Conn) ([]byte, error) {
	var result []byte
	buf := make([]byte, 2048)
	for {
		conn.SetReadDeadline(time.Now().Add(tcpTimeout))
		n, err := conn.Read(buf)
		if n > 0 {
			result = append(result, buf[:n]...)
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return result, nil
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				return result, nil
			}
			return result, err
		}
	}
}

func shutdownWrite(conn net.Conn) {
	if tc, ok := conn.(*net.TCPConn); ok {
		tc.CloseWrite()
	}
}

// runEchoTest is the common pattern for TCP connect tests:
// send payload, half-close write, read all back, compare.
func runEchoTest(name string, conn net.Conn) {
	defer conn.Close()

	payload := []byte(name + "_test\n" + dataPayload)
	debugf("%s: sending %d bytes", name, len(payload))

	if _, err := conn.Write(payload); err != nil {
		failTest(name, fmt.Sprintf("write: %v", err))
		return
	}
	shutdownWrite(conn)

	response, err := readAll(conn)
	if err != nil {
		failTest(name, fmt.Sprintf("read: %v", err))
		return
	}

	debugf("%s: received %d bytes", name, len(response))

	if !bytes.Equal(payload, response) {
		debugf("%s: expected: %q", name, payload)
		debugf("%s: received: %q", name, response)
		failTest(name, fmt.Sprintf("data mismatch: sent %d bytes, received %d bytes", len(payload), len(response)))
		return
	}
	passTest(name)
}

func testSocks4Connect(proxyAddr string, serverIP net.IP, serverPort int) {
	const name = "socks4_connect"
	conn, err := socks4Connect(proxyAddr, serverIP, serverPort)
	if err != nil {
		failTest(name, err.Error())
		return
	}
	runEchoTest(name, conn)
}

func testSocks4aConnect(proxyAddr string, serverIP net.IP, serverPort int) {
	const name = "socks4a_connect"
	conn, err := socks4aConnectIP(proxyAddr, serverIP, serverPort)
	if err != nil {
		failTest(name, err.Error())
		return
	}
	runEchoTest(name, conn)
}

func testSocks5Connect(proxyAddr string, serverIP net.IP, serverPort int) {
	const name = "socks5_connect"
	conn, err := socks5Connect(proxyAddr, serverIP, serverPort)
	if err != nil {
		failTest(name, err.Error())
		return
	}
	runEchoTest(name, conn)
}

func testSocks5AuthConnect(proxyAddr string, serverIP net.IP, serverPort int, username, password string) {
	const name = "socks5_auth_connect"
	conn, err := socks5AuthConnect(proxyAddr, serverIP, serverPort, username, password)
	if err != nil {
		failTest(name, err.Error())
		return
	}
	runEchoTest(name, conn)
}

func testSocks5ConnectHostname(proxyAddr string) {
	const name = "socks5_connect_hostname"
	conn, err := socks5ConnectHostname(proxyAddr, "www.baidu.com", 80)
	if err != nil {
		failTest(name, err.Error())
		return
	}
	defer conn.Close()

	httpReq := "GET / HTTP/1.1\r\nHost: www.baidu.com\r\nConnection: close\r\n\r\n"
	if _, err := conn.Write([]byte(httpReq)); err != nil {
		failTest(name, fmt.Sprintf("write: %v", err))
		return
	}

	response, err := readAll(conn)
	if err != nil {
		failTest(name, fmt.Sprintf("read: %v", err))
		return
	}

	debugf("%s: received %d bytes", name, len(response))

	if strings.HasPrefix(string(response), "HTTP/1.") {
		passTest(name)
	} else {
		failTest(name, "response does not start with HTTP/1.")
	}
}

func testSocks4aConnectHostname(proxyAddr string) {
	const name = "socks4a_connect_hostname"
	conn, err := socks4aConnectHostname(proxyAddr, "www.baidu.com", 80)
	if err != nil {
		failTest(name, err.Error())
		return
	}
	defer conn.Close()

	httpReq := "GET / HTTP/1.1\r\nHost: www.baidu.com\r\nConnection: close\r\n\r\n"
	if _, err := conn.Write([]byte(httpReq)); err != nil {
		failTest(name, fmt.Sprintf("write: %v", err))
		return
	}

	response, err := readAll(conn)
	if err != nil {
		failTest(name, fmt.Sprintf("read: %v", err))
		return
	}

	debugf("%s: received %d bytes", name, len(response))

	if strings.HasPrefix(string(response), "HTTP/1.") {
		passTest(name)
	} else {
		failTest(name, "response does not start with HTTP/1.")
	}
}

func testSocks4Bind(proxyAddr string, bindCh chan<- bindEvent) {
	const name = "socks4_bind"
	conn, ip, port, err := socks4Bind(proxyAddr, net.IPv4zero, 0)
	if err != nil {
		failTest(name, err.Error())
		return
	}
	defer conn.Close()

	payload := []byte(name + "_test\n" + dataPayload)
	boundAddr := fmt.Sprintf("%s:%d", ip, port)
	debugf("%s: bound address: %s", name, boundAddr)

	bindCh <- bindEvent{targetAddr: boundAddr, data: payload}

	if err := socks4WaitConnect(conn); err != nil {
		failTest(name, fmt.Sprintf("wait connect: %v", err))
		return
	}

	conn.SetReadDeadline(time.Now().Add(tcpTimeout))
	buf := make([]byte, 2048+len(dataPayload))
	n, err := conn.Read(buf)
	if err != nil && !errors.Is(err, io.EOF) {
		failTest(name, fmt.Sprintf("read: %v", err))
		return
	}

	response := buf[:n]
	debugf("%s: received %d bytes", name, len(response))

	if bytes.Equal(payload, response) {
		passTest(name)
	} else {
		debugf("%s: expected: %q", name, payload)
		debugf("%s: received: %q", name, response)
		failTest(name, fmt.Sprintf("data mismatch: sent %d bytes, received %d bytes", len(payload), len(response)))
	}
}

func testSocks5Bind(proxyAddr string, serverIP net.IP, serverPort int, bindCh chan<- bindEvent) {
	const name = "socks5_bind"
	conn, ip, port, err := socks5BindRequest(proxyAddr, serverIP, serverPort)
	if err != nil {
		failTest(name, err.Error())
		return
	}
	defer conn.Close()

	payload := []byte(name + "_test\n" + dataPayload)
	boundAddr := fmt.Sprintf("%s:%d", ip, port)
	debugf("%s: bound address: %s", name, boundAddr)

	bindCh <- bindEvent{targetAddr: boundAddr, data: payload}

	if err := socks5WaitConnect(conn); err != nil {
		failTest(name, fmt.Sprintf("wait connect: %v", err))
		return
	}

	conn.SetReadDeadline(time.Now().Add(tcpTimeout))
	buf := make([]byte, 2048+len(dataPayload))
	n, err := conn.Read(buf)
	if err != nil && !errors.Is(err, io.EOF) {
		failTest(name, fmt.Sprintf("read: %v", err))
		return
	}

	response := buf[:n]
	debugf("%s: received %d bytes", name, len(response))

	if bytes.Equal(payload, response) {
		passTest(name)
	} else {
		debugf("%s: expected: %q", name, payload)
		debugf("%s: received: %q", name, response)
		failTest(name, fmt.Sprintf("data mismatch: sent %d bytes, received %d bytes", len(payload), len(response)))
	}
}

func testSocks5UDP(proxyAddr, serverAddr string) {
	const name = "socks5_udp"
	controlConn, relayAddr, localUDP, err := socks5UDPAssociate(proxyAddr)
	if err != nil {
		failTest(name, err.Error())
		return
	}
	defer controlConn.Close()
	defer localUDP.Close()

	serverUDPAddr, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		failTest(name, fmt.Sprintf("resolve server addr: %v", err))
		return
	}

	payload := []byte("UDP Data" + dataPayload)
	header := buildUDPHeader(serverUDPAddr.IP, serverUDPAddr.Port)
	packet := make([]byte, 0, len(header)+len(payload))
	packet = append(packet, header...)
	packet = append(packet, payload...)

	debugf("%s: sending %d bytes via relay %s to %s", name, len(payload), relayAddr, serverAddr)

	if _, err := localUDP.WriteToUDP(packet, relayAddr); err != nil {
		failTest(name, fmt.Sprintf("write: %v", err))
		return
	}

	var received []byte
	buf := make([]byte, 65536)
	for len(received) < len(payload) {
		localUDP.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, _, err := localUDP.ReadFromUDP(buf)
		if err != nil {
			failTest(name, fmt.Sprintf("read: %v", err))
			return
		}
		data, err := parseUDPRelay(buf[:n])
		if err != nil {
			failTest(name, fmt.Sprintf("parse relay: %v", err))
			return
		}
		received = append(received, data...)
	}

	debugf("%s: received %d bytes", name, len(received))

	if bytes.Equal(payload, received) {
		passTest(name)
	} else {
		debugf("%s: expected: %q", name, payload)
		debugf("%s: received: %q", name, received)
		failTest(name, fmt.Sprintf("data mismatch: sent %d bytes, received %d bytes", len(payload), len(received)))
	}
}
