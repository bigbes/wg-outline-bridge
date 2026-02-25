package main

import (
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"slices"
	"strings"
	"time"
)

var (
	debugEnabled bool
	dataPayload  string
	tcpTimeout   = 10 * time.Second
)

func debugf(format string, args ...any) {
	if debugEnabled {
		fmt.Printf("[DEBUG] "+format+"\n", args...)
	}
}

func passTest(name string) {
	fmt.Printf("\033[32m%s OK PASS\033[0m\n", name)
}

func failTest(name, reason string) {
	fmt.Printf("\033[31m%s ERR:%s\033[0m\n", name, reason)
}

func main() {
	proxyIP := flag.String("proxyip", "", "SOCKS proxy IP address (required)")
	proxyPort := flag.Int("proxyport", 0, "SOCKS proxy port (required)")
	serverIP := flag.String("serverip", "", "Local test server IP (required)")
	serverPort := flag.Int("serverport", 3307, "Local test server port")
	auth := flag.String("auth", "", "username:password for SOCKS5 auth")
	datasize := flag.Int("datasize", 0, "Size of random padding appended to test payloads")
	casename := flag.String("casename", "", "Test case name (required)")
	debug := flag.Bool("debug", false, "Enable debug output")
	flag.Parse()

	if *proxyIP == "" || *proxyPort == 0 || *serverIP == "" || *casename == "" {
		fmt.Fprintln(os.Stderr, "Missing required flags: -proxyip, -proxyport, -serverip, -casename")
		flag.Usage()
		os.Exit(1)
	}

	validCases := []string{
		"socks4_connect", "socks5_connect", "socks5_connect_hostname",
		"socks4a_connect_hostname", "socks4a_connect",
		"socks4_bind", "socks5_bind", "socks5_udp",
		"socks5_auth_connect", "socks5_auth_bind", "socks5_auth_udp",
	}
	valid := slices.Contains(validCases, *casename)
	if !valid {
		fmt.Fprintf(os.Stderr, "Invalid casename: %s\nValid cases: %s\n", *casename, strings.Join(validCases, ", "))
		os.Exit(1)
	}

	debugEnabled = *debug

	if *datasize > 0 {
		const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
		b := make([]byte, *datasize)
		for i := range b {
			b[i] = charset[rand.Intn(len(charset))]
		}
		dataPayload = string(b)
	}

	proxyAddr := fmt.Sprintf("%s:%d", *proxyIP, *proxyPort)
	serverAddr := fmt.Sprintf("%s:%d", *serverIP, *serverPort)

	bindCh := make(chan bindEvent, 100)

	go func() {
		if err := runTCPEchoServer(serverAddr); err != nil {
			fmt.Fprintf(os.Stderr, "TCP echo server error: %v\n", err)
			os.Exit(1)
		}
	}()
	go func() {
		if err := runUDPEchoServer(serverAddr); err != nil {
			fmt.Fprintf(os.Stderr, "UDP echo server error: %v\n", err)
			os.Exit(1)
		}
	}()
	go func() { runBindHelper(bindCh) }()

	// Give servers time to start
	time.Sleep(100 * time.Millisecond)

	serverIPParsed := net.ParseIP(*serverIP)
	if serverIPParsed == nil {
		fmt.Fprintf(os.Stderr, "Invalid server IP: %s\n", *serverIP)
		os.Exit(1)
	}

	username, password := "", ""
	if *auth != "" {
		parts := strings.SplitN(*auth, ":", 2)
		username = parts[0]
		if len(parts) > 1 {
			password = parts[1]
		}
	}

	switch *casename {
	case "socks4_connect":
		testSocks4Connect(proxyAddr, serverIPParsed, *serverPort)
	case "socks4a_connect":
		testSocks4aConnect(proxyAddr, serverIPParsed, *serverPort)
	case "socks5_connect":
		testSocks5Connect(proxyAddr, serverIPParsed, *serverPort)
	case "socks5_connect_hostname":
		testSocks5ConnectHostname(proxyAddr)
	case "socks4a_connect_hostname":
		testSocks4aConnectHostname(proxyAddr)
	case "socks4_bind":
		testSocks4Bind(proxyAddr, bindCh)
	case "socks5_bind":
		testSocks5Bind(proxyAddr, serverIPParsed, *serverPort, bindCh)
	case "socks5_udp":
		testSocks5UDP(proxyAddr, serverAddr)
	case "socks5_auth_connect":
		testSocks5AuthConnect(proxyAddr, serverIPParsed, *serverPort, username, password)
	case "socks5_auth_bind", "socks5_auth_udp":
		// Not implemented in the original tool either
		debugf("test case %s not implemented", *casename)
	}
}
