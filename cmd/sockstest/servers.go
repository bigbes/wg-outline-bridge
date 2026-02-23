package main

import (
	"fmt"
	"net"
	"time"
)

type bindEvent struct {
	targetAddr string
	data       []byte
}

func runTCPEchoServer(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("tcp echo: listen: %w", err)
	}
	debugf("TCP echo server listening on %s", addr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			debugf("tcp echo: accept error: %v", err)
			continue
		}
		go func(c net.Conn) {
			defer c.Close()
			buf := make([]byte, 2048)
			for {
				c.SetReadDeadline(time.Now().Add(tcpTimeout))
				n, err := c.Read(buf)
				if n > 0 {
					c.Write(buf[:n])
				}
				if err != nil {
					return
				}
			}
		}(conn)
	}
}

func runUDPEchoServer(addr string) error {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return fmt.Errorf("udp echo: resolve: %w", err)
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("udp echo: listen: %w", err)
	}
	debugf("UDP echo server listening on %s", addr)

	buf := make([]byte, 1024+len(dataPayload))
	for {
		n, remoteAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			debugf("udp echo: read error: %v", err)
			continue
		}
		debugf("udp echo: received %d bytes from %s", n, remoteAddr)
		conn.WriteToUDP(buf[:n], remoteAddr)
	}
}

func runBindHelper(ch <-chan bindEvent) {
	for event := range ch {
		go func(ev bindEvent) {
			debugf("bind helper: connecting to %s", ev.targetAddr)
			conn, err := net.DialTimeout("tcp", ev.targetAddr, 5*time.Second)
			if err != nil {
				debugf("bind helper: connect error: %v", err)
				return
			}
			defer conn.Close()
			conn.Write(ev.data)
			if tc, ok := conn.(*net.TCPConn); ok {
				tc.CloseWrite()
			}
		}(event)
	}
}
