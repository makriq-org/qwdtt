package main

// SOCKS5 для qwdtt в режиме -mode socks.
//
// Поддерживаются CONNECT (TCP) и UDP ASSOCIATE. Весь пользовательский трафик
// идёт только через gVisor netstack: сервер не открывает прямых соединений в
// сеть и не использует системный DNS, поэтому при отказе транспорта пакеты
// не утекают мимо туннеля.
//
// UDP ASSOCIATE совместим с flclashm-udp-token: клиент (mihomo) передаёт в
// запросе 32-символьный hex-токен как доменное имя с портом 0, а каждый
// датаграм обменивается с префиксом токена в обе стороны. Без совпадения
// префикса датаграм отбрасывается — посторонний локальный процесс не может
// пользоваться открытой UDP-ассоциацией.

import (
	"context"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

const (
	socksVersion = 5

	socksAuthNone     = 0x00
	socksAuthPassword = 0x02
	socksAuthRejected = 0xFF

	socksCmdConnect = 0x01
	socksCmdBind    = 0x02
	socksCmdUDP     = 0x03

	socksAtypIPv4   = 0x01
	socksAtypDomain = 0x03
	socksAtypIPv6   = 0x04

	socksRepSuccess        = 0x00
	socksRepGeneral        = 0x01
	socksRepNotAllowed     = 0x02
	socksRepHostUnreach    = 0x04
	socksRepConnRefused    = 0x05
	socksRepCmdUnsupported = 0x07
	socksRepAddrType       = 0x08

	socksUDPIdleTimeout = 2 * time.Minute
	socksUDPMaxTargets  = 256
	socksUDPMaxDatagram = 65507
	socksTCPDialTimeout = 20 * time.Second
	socksUDPReadBuffer  = 64 * 1024
)

type socksServerConfig struct {
	Listen      string
	Username    string
	Password    string
	RequireAuth bool
	AllowUDP    bool
	UDPToken    bool
	Resolver    *tunnelResolver
	DialTCP     func(context.Context, netip.AddrPort) (net.Conn, error)
	DialUDP     func(netip.AddrPort) (net.Conn, error)
	Logf        func(format string, args ...any)
}

type socksServer struct {
	cfg socksServerConfig
}

func (s *socksServer) logf(format string, args ...any) {
	if s.cfg.Logf != nil {
		s.cfg.Logf(format, args...)
	}
}

// runSocks5Server обслуживает SOCKS5 до отмены ctx. Адрес обязан быть
// loopback: иначе локальный прокси стал бы доступен другим машинам.
func runSocks5Server(ctx context.Context, cfg socksServerConfig) error {
	if cfg.Resolver == nil || cfg.DialTCP == nil || cfg.DialUDP == nil {
		return errors.New("SOCKS5 server requires netstack dialers")
	}
	if !isLoopbackAddress(cfg.Listen) {
		return errors.New("SOCKS5 listener must be loopback")
	}
	if cfg.UDPToken && (!cfg.RequireAuth || !cfg.AllowUDP) {
		return errors.New("SOCKS5 UDP token requires authentication and UDP")
	}
	listener, err := listenTCP(cfg.Listen)
	if err != nil {
		return fmt.Errorf("listen %s: %w", cfg.Listen, err)
	}
	return serveSocks5(ctx, listener, cfg)
}

// serveSocks5 обслуживает уже созданный listener. Отделено от runSocks5Server,
// чтобы тесты могли занять произвольный свободный порт.
func serveSocks5(ctx context.Context, listener net.Listener, cfg socksServerConfig) error {
	defer listener.Close()
	stop := context.AfterFunc(ctx, func() { _ = listener.Close() })
	defer stop()

	server := &socksServer{cfg: cfg}
	log.Printf("[SOCKS] listening %s (udp=%v auth=%v token=%v)", cfg.Listen, cfg.AllowUDP, cfg.RequireAuth, cfg.UDPToken)

	var wg sync.WaitGroup
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				break
			}
			if temporary, ok := err.(interface{ Temporary() bool }); ok && temporary.Temporary() {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			wg.Wait()
			return err
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			server.handle(ctx, conn)
		}()
	}
	wg.Wait()
	return nil
}

func listenTCP(address string) (net.Listener, error) {
	lc := net.ListenConfig{Control: reuseAddrControl}
	return lc.Listen(context.Background(), "tcp", address)
}

func (s *socksServer) handle(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	if err := s.handshake(conn); err != nil {
		s.logf("[SOCKS] handshake: %v", err)
		return
	}
	_ = conn.SetDeadline(time.Time{})

	command, target, err := readSocksRequest(conn)
	if err != nil {
		s.logf("[SOCKS] request: %v", err)
		writeSocksReply(conn, socksRepGeneral, netip.AddrPort{})
		return
	}
	switch command {
	case socksCmdConnect:
		s.handleConnect(ctx, conn, target)
	case socksCmdUDP:
		s.handleUDP(ctx, conn, target)
	default:
		writeSocksReply(conn, socksRepCmdUnsupported, netip.AddrPort{})
	}
}

func (s *socksServer) handshake(conn net.Conn) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}
	if header[0] != socksVersion || header[1] == 0 {
		return errors.New("unsupported SOCKS version or empty method list")
	}
	methods := make([]byte, header[1])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}
	offered := map[byte]bool{}
	for _, method := range methods {
		offered[method] = true
	}
	if s.cfg.RequireAuth {
		if !offered[socksAuthPassword] {
			_, _ = conn.Write([]byte{socksVersion, socksAuthRejected})
			return errors.New("client does not support username/password authentication")
		}
		if _, err := conn.Write([]byte{socksVersion, socksAuthPassword}); err != nil {
			return err
		}
		return s.authenticate(conn)
	}
	if !offered[socksAuthNone] {
		_, _ = conn.Write([]byte{socksVersion, socksAuthRejected})
		return errors.New("client requires unsupported authentication")
	}
	_, err := conn.Write([]byte{socksVersion, socksAuthNone})
	return err
}

func (s *socksServer) authenticate(conn net.Conn) error {
	head := make([]byte, 2)
	if _, err := io.ReadFull(conn, head); err != nil {
		return err
	}
	if head[0] != 0x01 {
		return errors.New("unsupported authentication version")
	}
	user := make([]byte, head[1])
	if _, err := io.ReadFull(conn, user); err != nil {
		return err
	}
	if _, err := io.ReadFull(conn, head[:1]); err != nil {
		return err
	}
	pass := make([]byte, head[0])
	if _, err := io.ReadFull(conn, pass); err != nil {
		return err
	}
	userOK := subtle.ConstantTimeCompare(user, []byte(s.cfg.Username)) == 1
	passOK := subtle.ConstantTimeCompare(pass, []byte(s.cfg.Password)) == 1
	if !userOK || !passOK {
		_, _ = conn.Write([]byte{0x01, 0x01})
		return errors.New("invalid SOCKS5 credentials")
	}
	_, err := conn.Write([]byte{0x01, 0x00})
	return err
}

type socksTarget struct {
	host string
	port uint16
}

func readSocksRequest(conn net.Conn) (byte, socksTarget, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return 0, socksTarget{}, err
	}
	if header[0] != socksVersion || header[2] != 0 {
		return 0, socksTarget{}, errors.New("invalid SOCKS request header")
	}
	target, err := readSocksAddress(conn, header[3])
	return header[1], target, err
}

func readSocksAddress(r io.Reader, atyp byte) (socksTarget, error) {
	switch atyp {
	case socksAtypIPv4:
		buf := make([]byte, 4+2)
		if _, err := io.ReadFull(r, buf); err != nil {
			return socksTarget{}, err
		}
		ip := netip.AddrFrom4([4]byte(buf[:4]))
		return socksTarget{host: ip.String(), port: binary.BigEndian.Uint16(buf[4:])}, nil
	case socksAtypIPv6:
		buf := make([]byte, 16+2)
		if _, err := io.ReadFull(r, buf); err != nil {
			return socksTarget{}, err
		}
		ip := netip.AddrFrom16([16]byte(buf[:16]))
		return socksTarget{host: ip.String(), port: binary.BigEndian.Uint16(buf[16:])}, nil
	case socksAtypDomain:
		length := make([]byte, 1)
		if _, err := io.ReadFull(r, length); err != nil {
			return socksTarget{}, err
		}
		if length[0] == 0 {
			return socksTarget{}, errors.New("empty SOCKS domain")
		}
		buf := make([]byte, int(length[0])+2)
		if _, err := io.ReadFull(r, buf); err != nil {
			return socksTarget{}, err
		}
		host := string(buf[:len(buf)-2])
		return socksTarget{host: host, port: binary.BigEndian.Uint16(buf[len(buf)-2:])}, nil
	default:
		return socksTarget{}, errors.New("unsupported SOCKS address type")
	}
}

func writeSocksReply(conn net.Conn, code byte, bound netip.AddrPort) {
	addr := bound.Addr().Unmap()
	var body []byte
	if addr.Is4() {
		body = append([]byte{socksVersion, code, 0x00, socksAtypIPv4}, addr.AsSlice()...)
	} else if addr.Is6() {
		body = append([]byte{socksVersion, code, 0x00, socksAtypIPv6}, addr.AsSlice()...)
	} else {
		body = []byte{socksVersion, code, 0x00, socksAtypIPv4, 0, 0, 0, 0}
	}
	port := make([]byte, 2)
	binary.BigEndian.PutUint16(port, bound.Port())
	_, _ = conn.Write(append(body, port...))
}

func (s *socksServer) handleConnect(ctx context.Context, conn net.Conn, target socksTarget) {
	if target.port == 0 {
		writeSocksReply(conn, socksRepGeneral, netip.AddrPort{})
		return
	}
	dialCtx, cancel := context.WithTimeout(ctx, socksTCPDialTimeout)
	defer cancel()
	addr, err := resolveDialAddress(dialCtx, s.cfg.Resolver, target.host, target.port)
	if err != nil {
		s.logf("[SOCKS] resolve %s: %v", target.host, err)
		writeSocksReply(conn, socksRepHostUnreach, netip.AddrPort{})
		return
	}
	remote, err := s.cfg.DialTCP(dialCtx, addr)
	if err != nil {
		s.logf("[SOCKS] connect %s: %v", addr, err)
		writeSocksReply(conn, socksRepConnRefused, netip.AddrPort{})
		return
	}
	defer remote.Close()
	writeSocksReply(conn, socksRepSuccess, netip.AddrPort{})

	done := make(chan struct{}, 2)
	copyConn := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		if closeWriter, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = closeWriter.CloseWrite()
		}
		done <- struct{}{}
	}
	go copyConn(remote, conn)
	go copyConn(conn, remote)
	select {
	case <-ctx.Done():
		_ = conn.SetDeadline(time.Now())
		_ = remote.SetDeadline(time.Now())
		<-done
		<-done
	case <-done:
		_ = conn.SetDeadline(time.Now())
		_ = remote.SetDeadline(time.Now())
		<-done
	}
}

func (s *socksServer) handleUDP(ctx context.Context, control net.Conn, target socksTarget) {
	if !s.cfg.AllowUDP {
		writeSocksReply(control, socksRepCmdUnsupported, netip.AddrPort{})
		return
	}
	token := ""
	if s.cfg.UDPToken {
		token = strings.ToLower(target.host)
		if target.port != 0 || len(token) != 32 {
			writeSocksReply(control, socksRepNotAllowed, netip.AddrPort{})
			return
		}
		if _, err := hex.DecodeString(token); err != nil {
			writeSocksReply(control, socksRepNotAllowed, netip.AddrPort{})
			return
		}
		tokenBytes := []byte(token)
		assoc := newUDPAssociation(ctx, s, tokenBytes)
		defer assoc.close()
		if err := assoc.listen(control); err != nil {
			s.logf("[SOCKS] UDP associate: %v", err)
		}
		return
	}
	assoc := newUDPAssociation(ctx, s, nil)
	defer assoc.close()
	if err := assoc.listen(control); err != nil {
		s.logf("[SOCKS] UDP associate: %v", err)
	}
}

type udpTarget struct {
	addr     netip.AddrPort
	conn     net.Conn
	lastUsed time.Time
}

type udpAssociation struct {
	ctx      context.Context
	server   *socksServer
	token    []byte
	socket   *net.UDPConn
	client   netip.AddrPort
	clientMu sync.Mutex

	mu      sync.Mutex
	targets map[netip.AddrPort]*udpTarget
	closed  bool
}

func newUDPAssociation(ctx context.Context, server *socksServer, token []byte) *udpAssociation {
	return &udpAssociation{ctx: ctx, server: server, token: token, targets: map[netip.AddrPort]*udpTarget{}}
}

func (a *udpAssociation) listen(control net.Conn) error {
	host, _, _ := net.SplitHostPort(a.server.cfg.Listen)
	localIP, ok := parseIPLiteral(host)
	if !ok && strings.EqualFold(host, "localhost") {
		localIP = netip.MustParseAddr("127.0.0.1")
		ok = true
	}
	if !ok {
		writeSocksReply(control, socksRepGeneral, netip.AddrPort{})
		return errors.New("invalid loopback listener address")
	}
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: localIP.AsSlice(), Port: 0})
	if err != nil {
		writeSocksReply(control, socksRepGeneral, netip.AddrPort{})
		return err
	}
	a.socket = udp
	bound := udp.LocalAddr().(*net.UDPAddr)
	boundIP, _ := netip.AddrFromSlice(bound.IP)
	writeSocksReply(control, socksRepSuccess, netip.AddrPortFrom(boundIP.Unmap(), uint16(bound.Port)))

	stop := context.AfterFunc(a.ctx, func() { a.close() })
	defer stop()
	go func() {
		_, _ = io.Copy(io.Discard, control)
		a.close()
	}()
	go a.reapLoop()

	buffer := make([]byte, socksUDPReadBuffer)
	for {
		n, addr, err := udp.ReadFromUDP(buffer)
		if err != nil {
			if a.isClosed() || a.ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		clientAddr, _ := netip.AddrFromSlice(addr.IP)
		client := netip.AddrPortFrom(clientAddr.Unmap(), uint16(addr.Port))
		if !a.acceptClient(client) {
			continue
		}
		payload := buffer[:n]
		if len(a.token) > 0 {
			if len(payload) <= len(a.token) || subtle.ConstantTimeCompare(payload[:len(a.token)], a.token) != 1 {
				continue
			}
			payload = payload[len(a.token):]
		}
		a.handleDatagram(client, payload)
	}
}

func (a *udpAssociation) acceptClient(client netip.AddrPort) bool {
	a.clientMu.Lock()
	defer a.clientMu.Unlock()
	if a.client.Addr().IsValid() {
		return a.client == client
	}
	a.client = client
	return true
}

func (a *udpAssociation) handleDatagram(client netip.AddrPort, packet []byte) {
	if len(packet) < 4 {
		return
	}
	if packet[0] != 0 || packet[1] != 0 || packet[2] != 0 {
		// FRAG != 0 и зарезервированные биты не поддерживаются.
		return
	}
	reader := &socksDatagramReader{data: packet[3:]}
	target, err := reader.address()
	if err != nil || len(reader.data) == 0 {
		return
	}
	if target.port == 0 {
		return
	}
	addr, err := resolveDialAddress(a.ctx, a.server.cfg.Resolver, target.host, target.port)
	if err != nil {
		return
	}
	entry := a.target(addr)
	if entry == nil {
		return
	}
	if len(reader.data) > socksUDPMaxDatagram {
		return
	}
	_ = entry.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := entry.conn.Write(reader.data); err != nil {
		a.dropTarget(addr)
	}
}

func (a *udpAssociation) target(addr netip.AddrPort) *udpTarget {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return nil
	}
	if entry := a.targets[addr]; entry != nil {
		entry.lastUsed = time.Now()
		return entry
	}
	if len(a.targets) >= socksUDPMaxTargets {
		var oldestAddr netip.AddrPort
		var oldest time.Time
		for key, entry := range a.targets {
			if oldest.IsZero() || entry.lastUsed.Before(oldest) {
				oldest, oldestAddr = entry.lastUsed, key
			}
		}
		if entry := a.targets[oldestAddr]; entry != nil {
			_ = entry.conn.Close()
			delete(a.targets, oldestAddr)
		}
	}
	conn, err := a.server.cfg.DialUDP(addr)
	if err != nil {
		return nil
	}
	entry := &udpTarget{addr: addr, conn: conn, lastUsed: time.Now()}
	a.targets[addr] = entry
	go a.readTarget(entry)
	return entry
}

func (a *udpAssociation) readTarget(entry *udpTarget) {
	buffer := make([]byte, socksUDPReadBuffer)
	for {
		_ = entry.conn.SetReadDeadline(time.Now().Add(socksUDPIdleTimeout))
		n, err := entry.conn.Read(buffer)
		if err != nil {
			a.dropTarget(entry.addr)
			return
		}
		a.mu.Lock()
		entry.lastUsed = time.Now()
		closed := a.closed
		a.mu.Unlock()
		if closed {
			return
		}
		if n == 0 || n > socksUDPMaxDatagram {
			continue
		}
		a.sendToClient(entry.addr, buffer[:n])
	}
}

func (a *udpAssociation) sendToClient(source netip.AddrPort, payload []byte) {
	a.clientMu.Lock()
	client := a.client
	a.clientMu.Unlock()
	if !client.Addr().IsValid() {
		return
	}
	frame := encodeSocksDatagram(source, payload)
	if len(a.token) > 0 {
		framed := make([]byte, 0, len(a.token)+len(frame))
		framed = append(framed, a.token...)
		framed = append(framed, frame...)
		frame = framed
	}
	_, _ = a.socket.WriteToUDPAddrPort(frame, client)
}

func (a *udpAssociation) dropTarget(addr netip.AddrPort) {
	a.mu.Lock()
	entry := a.targets[addr]
	delete(a.targets, addr)
	a.mu.Unlock()
	if entry != nil {
		_ = entry.conn.Close()
	}
}

func (a *udpAssociation) reapLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-a.ctx.Done():
			return
		case <-ticker.C:
			cutoff := time.Now().Add(-socksUDPIdleTimeout)
			a.mu.Lock()
			for key, entry := range a.targets {
				if entry.lastUsed.Before(cutoff) {
					_ = entry.conn.Close()
					delete(a.targets, key)
				}
			}
			a.mu.Unlock()
		}
	}
}

func (a *udpAssociation) close() {
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return
	}
	a.closed = true
	entries := make([]*udpTarget, 0, len(a.targets))
	for _, entry := range a.targets {
		entries = append(entries, entry)
	}
	a.targets = map[netip.AddrPort]*udpTarget{}
	a.mu.Unlock()
	if a.socket != nil {
		_ = a.socket.Close()
	}
	for _, entry := range entries {
		_ = entry.conn.Close()
	}
}

type socksDatagramReader struct {
	data []byte
}

func (r *socksDatagramReader) address() (socksTarget, error) {
	if len(r.data) < 1 {
		return socksTarget{}, io.ErrUnexpectedEOF
	}
	atyp := r.data[0]
	r.data = r.data[1:]
	switch atyp {
	case socksAtypIPv4:
		if len(r.data) < 6 {
			return socksTarget{}, io.ErrUnexpectedEOF
		}
		ip := netip.AddrFrom4([4]byte(r.data[:4]))
		target := socksTarget{host: ip.String(), port: binary.BigEndian.Uint16(r.data[4:6])}
		r.data = r.data[6:]
		return target, nil
	case socksAtypIPv6:
		if len(r.data) < 18 {
			return socksTarget{}, io.ErrUnexpectedEOF
		}
		ip := netip.AddrFrom16([16]byte(r.data[:16]))
		target := socksTarget{host: ip.String(), port: binary.BigEndian.Uint16(r.data[16:18])}
		r.data = r.data[18:]
		return target, nil
	case socksAtypDomain:
		if len(r.data) < 1 || int(r.data[0])+3 > len(r.data) {
			return socksTarget{}, io.ErrUnexpectedEOF
		}
		length := int(r.data[0])
		host := string(r.data[1 : 1+length])
		port := binary.BigEndian.Uint16(r.data[1+length : 3+length])
		r.data = r.data[3+length:]
		return socksTarget{host: host, port: port}, nil
	default:
		return socksTarget{}, errors.New("unsupported SOCKS datagram address type")
	}
}

func encodeSocksDatagram(source netip.AddrPort, payload []byte) []byte {
	addr := source.Addr().Unmap()
	var header []byte
	if addr.Is4() {
		header = append([]byte{0, 0, 0, socksAtypIPv4}, addr.AsSlice()...)
	} else {
		header = append([]byte{0, 0, 0, socksAtypIPv6}, addr.AsSlice()...)
	}
	frame := make([]byte, 0, len(header)+2+len(payload))
	frame = append(frame, header...)
	port := make([]byte, 2)
	binary.BigEndian.PutUint16(port, source.Port())
	frame = append(frame, port...)
	frame = append(frame, payload...)
	return frame
}

func (a *udpAssociation) isClosed() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.closed
}
