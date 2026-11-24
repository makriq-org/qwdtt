package main

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func startTestSocks(t *testing.T, cfg socksServerConfig) (string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cfg.Listen = listener.Addr().String()
	if cfg.Resolver == nil {
		cfg.Resolver = &tunnelResolver{}
	}
	if cfg.DialTCP == nil {
		cfg.DialTCP = func(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", addr.String())
		}
	}
	if cfg.DialUDP == nil {
		cfg.DialUDP = func(addr netip.AddrPort) (net.Conn, error) {
			return net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(addr))
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = serveSocks5(ctx, listener, cfg)
		close(done)
	}()
	stop := func() {
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("SOCKS server did not stop")
		}
	}
	return listener.Addr().String(), stop
}

func negotiate(t *testing.T, conn net.Conn, methods ...byte) byte {
	t.Helper()
	if _, err := conn.Write(append([]byte{5, byte(len(methods))}, methods...)); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatal(err)
	}
	return reply[1]
}

func authenticate(t *testing.T, conn net.Conn, user, pass string) bool {
	t.Helper()
	payload := []byte{1, byte(len(user))}
	payload = append(payload, user...)
	payload = append(payload, byte(len(pass)))
	payload = append(payload, pass...)
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatal(err)
	}
	return reply[1] == 0
}

func connectRequest(t *testing.T, conn net.Conn, host string, port uint16) byte {
	t.Helper()
	ip := net.ParseIP(host).To4()
	if ip == nil {
		t.Fatal("test uses IPv4 literals")
	}
	req := []byte{5, 1, 0, 1}
	req = append(req, ip...)
	p := make([]byte, 2)
	binary.BigEndian.PutUint16(p, port)
	req = append(req, p...)
	if _, err := conn.Write(req); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatal(err)
	}
	return reply[1]
}

func udpAssociate(t *testing.T, conn net.Conn, token string) netip.AddrPort {
	t.Helper()
	var req []byte
	if token != "" {
		req = []byte{5, 3, 0, 3, byte(len(token))}
		req = append(req, token...)
		req = append(req, 0, 0)
	} else {
		req = []byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}
	}
	if _, err := conn.Write(req); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatal(err)
	}
	if reply[1] != 0 {
		t.Fatalf("UDP associate failed with %d", reply[1])
	}
	ip := netip.AddrFrom4([4]byte(reply[4:8]))
	return netip.AddrPortFrom(ip, binary.BigEndian.Uint16(reply[8:10]))
}

func startUDPEcho(t *testing.T) (*net.UDPConn, uint16) {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 2048)
		for {
			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = conn.WriteToUDP(buf[:n], addr)
		}
	}()
	t.Cleanup(func() { _ = conn.Close(); wg.Wait() })
	return conn, uint16(conn.LocalAddr().(*net.UDPAddr).Port)
}

func TestSocksTCPConnect(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			conn, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(conn, conn); _ = conn.Close() }()
		}
	}()

	addr, stop := startTestSocks(t, socksServerConfig{})
	defer stop()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if method := negotiate(t, conn, 0); method != 0 {
		t.Fatalf("method=%d", method)
	}
	port := uint16(echo.Addr().(*net.TCPAddr).Port)
	if code := connectRequest(t, conn, "127.0.0.1", port); code != 0 {
		t.Fatalf("connect code=%d", code)
	}
	if _, err = conn.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 5)
	if _, err = io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "hello" {
		t.Fatalf("echo=%q", buf)
	}
}

func TestSocksAuthenticationRequired(t *testing.T) {
	addr, stop := startTestSocks(t, socksServerConfig{RequireAuth: true, Username: "user", Password: "pass"})
	defer stop()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	if method := negotiate(t, conn, 0); method != socksAuthRejected {
		t.Fatalf("no-auth must be rejected, got %d", method)
	}
	_ = conn.Close()

	conn, err = net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	if method := negotiate(t, conn, 2); method != 2 {
		t.Fatalf("method=%d", method)
	}
	if authenticate(t, conn, "user", "wrong") {
		t.Fatal("wrong password accepted")
	}
	_ = conn.Close()

	conn, err = net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if method := negotiate(t, conn, 2); method != 2 {
		t.Fatalf("method=%d", method)
	}
	if !authenticate(t, conn, "user", "pass") {
		t.Fatal("correct password rejected")
	}
}

func TestSocksUDPTokenRoundTrip(t *testing.T) {
	_, port := startUDPEcho(t)
	token := "0123456789abcdef0123456789abcdef"
	addr, stop := startTestSocks(t, socksServerConfig{
		RequireAuth: true, Username: "user", Password: "pass",
		AllowUDP: true, UDPToken: true,
	})
	defer stop()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if method := negotiate(t, conn, 2); method != 2 {
		t.Fatalf("method=%d", method)
	}
	if !authenticate(t, conn, "user", "pass") {
		t.Fatal("auth failed")
	}
	bound := udpAssociate(t, conn, token)
	client, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(bound))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	frame := append([]byte(token), encodeSocksDatagram(netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port), []byte("ping"))...)
	// Посторонний процесс с неверным токеном не должен захватить ассоциацию.
	attacker, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(bound))
	if err != nil {
		t.Fatal(err)
	}
	badFrame := append([]byte("ffffffffffffffffffffffffffffffff"), frame[len(token):]...)
	if _, err = attacker.Write(badFrame); err != nil {
		t.Fatal(err)
	}
	_ = attacker.Close()
	if _, err = client.Write(frame); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 2048)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	got := buf[:n]
	if string(got[:len(token)]) != token {
		t.Fatalf("response token missing: %x", got[:len(token)])
	}
	reader := &socksDatagramReader{data: got[len(token)+3:]}
	target, err := reader.address()
	if err != nil {
		t.Fatal(err)
	}
	if target.port != port || string(reader.data) != "ping" {
		t.Fatalf("target=%+v payload=%q", target, reader.data)
	}

	// Посторонний токен не должен получать ответ.
	bad := append([]byte("ffffffffffffffffffffffffffffffff"), frame[len(token):]...)
	if _, err = client.Write(bad); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if _, err = client.Read(buf); err == nil {
		t.Fatal("datagram with wrong token was accepted")
	}
}

func TestSocksUDPWithoutToken(t *testing.T) {
	_, port := startUDPEcho(t)
	addr, stop := startTestSocks(t, socksServerConfig{AllowUDP: true})
	defer stop()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if method := negotiate(t, conn, 0); method != 0 {
		t.Fatalf("method=%d", method)
	}
	bound := udpAssociate(t, conn, "")
	client, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(bound))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	frame := encodeSocksDatagram(netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port), []byte("plain"))
	if _, err = client.Write(frame); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 2048)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	reader := &socksDatagramReader{data: buf[3:n]}
	_, err = reader.address()
	if err != nil {
		t.Fatal(err)
	}
	if string(reader.data) != "plain" {
		t.Fatalf("payload=%q", reader.data)
	}
}

func TestSocksRejectsPublicListener(t *testing.T) {
	if err := runSocks5Server(context.Background(), socksServerConfig{
		Listen: "0.0.0.0:0", Resolver: &tunnelResolver{},
		DialTCP: func(context.Context, netip.AddrPort) (net.Conn, error) { return nil, io.EOF },
		DialUDP: func(netip.AddrPort) (net.Conn, error) { return nil, io.EOF },
	}); err == nil {
		t.Fatal("public SOCKS listener must be rejected")
	}
}
