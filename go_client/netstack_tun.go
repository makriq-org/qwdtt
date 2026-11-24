package main

// Единый виртуальный сетевой стек для всех режимов SOCKS5.
//
// WireGuard-режимы используют gVisor netstack как TUN-устройство
// userspace-WireGuard. Raw-IP режим не имеет WireGuard: сервер присылает
// клиенту сырые IP-пакеты, поэтому тот же netstack подключается напрямую к
// диспетчеру. Прикладной уровень (SOCKS5 TCP/UDP) во всех трёх режимах
// работает с одним и тем же *netstack.Net и не знает, откуда взялись пакеты.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

type dnsEndpoint struct {
	addr netip.Addr
	port uint16
}

func (e dnsEndpoint) String() string {
	return net.JoinHostPort(e.addr.String(), fmt.Sprint(e.port))
}

type netstackTunnel struct {
	Device tun.Device
	Net    *netstack.Net
	Addr   netip.Addr
	MTU    int
	once   sync.Once
	err    error
}

func createNetstackTunnel(addresses []netip.Addr, dns []netip.Addr, mtu int) (*netstackTunnel, error) {
	if len(addresses) == 0 {
		return nil, errors.New("netstack requires at least one address")
	}
	if mtu < 576 || mtu > 65535 {
		return nil, fmt.Errorf("invalid MTU %d", mtu)
	}
	dev, net, err := netstack.CreateNetTUN(addresses, dns, mtu)
	if err != nil {
		return nil, fmt.Errorf("gVisor netstack: %w", err)
	}
	return &netstackTunnel{Device: dev, Net: net, Addr: addresses[0], MTU: mtu}, nil
}

func (t *netstackTunnel) Close() error {
	if t == nil || t.Device == nil {
		return nil
	}
	t.once.Do(func() { t.err = t.Device.Close() })
	return t.err
}

// tunPacketConn представляет netstack-устройство как net.PacketConn для
// диспетчера: ReadFrom отдаёт IP-пакеты, которые netstack хочет отправить в
// сеть, WriteTo — наоборот, вкладывает принятые из сети пакеты в стек.
type tunPacketConn struct {
	dev    tun.Device
	tunnel *netstackTunnel
	closed chan struct{}
	once   sync.Once
}

func newTunPacketConn(tunnel *netstackTunnel) *tunPacketConn {
	return &tunPacketConn{dev: tunnel.Device, tunnel: tunnel, closed: make(chan struct{})}
}

func (c *tunPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case <-c.closed:
		return 0, nil, net.ErrClosed
	default:
	}
	sizes := []int{0}
	bufs := [][]byte{p}
	n, err := c.dev.Read(bufs, sizes, 0)
	if err != nil {
		return 0, nil, err
	}
	if n == 0 || sizes[0] == 0 {
		return 0, nil, io.EOF
	}
	return sizes[0], tunAddr{}, nil
}

func (c *tunPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
	}
	bufs := [][]byte{p}
	if _, err := c.dev.Write(bufs, 0); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *tunPacketConn) Close() error {
	c.once.Do(func() {
		close(c.closed)
		// Закрываем netstack, иначе ReadFrom навсегда останется в blocking Read.
		_ = c.tunnel.Close()
	})
	return nil
}

func (c *tunPacketConn) LocalAddr() net.Addr              { return tunAddr{} }
func (c *tunPacketConn) SetDeadline(time.Time) error      { return nil }
func (c *tunPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *tunPacketConn) SetWriteDeadline(time.Time) error { return nil }

type tunAddr struct{}

func (tunAddr) Network() string { return "raw-ip" }
func (tunAddr) String() string  { return "raw-ip" }

// parseDNSEndpoints разбирает значение dns-server: один адрес, список через
// запятую/пробел, с портом или без. Поддерживается только IP-литерал:
// резолвить сам DNS-сервер через системный DNS нельзя, иначе при отказе
// транспорта запрос утечёт мимо туннеля.
func parseDNSEndpoints(value string) ([]dnsEndpoint, error) {
	value = strings.TrimSpace(value)
	if value == "" || strings.EqualFold(value, "system") {
		return nil, nil
	}
	var result []dnsEndpoint
	seen := map[string]bool{}
	for _, part := range strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\n' || r == '\t'
	}) {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		host, portText, err := splitHostPortDefault(part, "53")
		if err != nil {
			return nil, err
		}
		ip, ok := parseIPLiteral(host)
		if !ok {
			return nil, fmt.Errorf("DNS server %q must be an IP literal", part)
		}
		port := 53
		if portText != "" {
			if port, err = parsePortNumber(portText); err != nil {
				return nil, fmt.Errorf("DNS server %q: %w", part, err)
			}
		}
		key := net.JoinHostPort(ip.String(), fmt.Sprint(port))
		if seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, dnsEndpoint{addr: ip, port: uint16(port)})
		if len(result) >= 16 {
			break
		}
	}
	return result, nil
}

func parsePortNumber(text string) (int, error) {
	n, err := net.LookupPort("tcp", text)
	if err == nil && n > 0 && n <= 65535 {
		return n, nil
	}
	var port int
	if _, scanErr := fmt.Sscan(text, &port); scanErr != nil || port < 1 || port > 65535 {
		return 0, errors.New("port must be within 1..65535")
	}
	return port, nil
}

func systemDNSEndpoints() []dnsEndpoint {
	raw, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	var result []dnsEndpoint
	seen := map[netip.Addr]bool{}
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		ip, ok := parseIPLiteral(fields[1])
		if !ok || ip.IsLoopback() || ip.IsUnspecified() || seen[ip] {
			continue
		}
		seen[ip] = true
		result = append(result, dnsEndpoint{addr: ip, port: 53})
		if len(result) >= 16 {
			break
		}
	}
	return result
}

// effectiveDNS выбирает DNS для пользовательского трафика. Явно заданный
// сервер имеет абсолютный приоритет: переключение на DNS оператора при его
// недоступности не допускается. "system" означает DNS текущей сети, который
// FlClashM передаёт в dns-fallback; запасной вариант — DNS из конфигурации
// туннеля (WG/RAWCONF), чтобы самостоятельный запуск без dns-fallback не
// терял связность.
func effectiveDNS(explicit, fallback string, tunnelProvided []netip.Addr) ([]dnsEndpoint, error) {
	if strings.TrimSpace(explicit) != "" && !strings.EqualFold(strings.TrimSpace(explicit), "system") {
		return parseDNSEndpoints(explicit)
	}
	// DNS, выданный сервером (WireGuard/RAWCONF), гарантированно достижим
	// внутри туннеля. Физический DNS телефона (10.0.2.3, DNS оператора)
	// находится вне туннеля и для netstack бесполезен, поэтому он идёт после
	// серверного резолвера.
	var result []dnsEndpoint
	for _, ip := range tunnelProvided {
		if ip.IsValid() && !ip.IsUnspecified() {
			result = append(result, dnsEndpoint{addr: ip.Unmap(), port: 53})
		}
	}
	if len(result) > 0 {
		return result, nil
	}
	fallback = strings.TrimSpace(fallback)
	if fallback != "" {
		if endpoints, err := parseDNSEndpoints(fallback); err == nil && len(endpoints) > 0 {
			return endpoints, nil
		}
	}
	if endpoints := systemDNSEndpoints(); len(endpoints) > 0 {
		return endpoints, nil
	}
	return nil, errors.New("no DNS server available for the tunnel")
}

func dnsAddresses(endpoints []dnsEndpoint) []netip.Addr {
	var result []netip.Addr
	seen := map[netip.Addr]bool{}
	for _, endpoint := range endpoints {
		if endpoint.port == 53 && !seen[endpoint.addr] {
			seen[endpoint.addr] = true
			result = append(result, endpoint.addr)
		}
	}
	return result
}

type dnsCacheEntry struct {
	addr    netip.Addr
	expires time.Time
}

// tunnelResolver резолвит имена через netstack и заданный DNS-сервер,
// включая нестандартный порт, который gVisor netstack сам не поддерживает.
type tunnelResolver struct {
	tnet    *netstack.Net
	servers []dnsEndpoint

	mu    sync.Mutex
	cache map[string]dnsCacheEntry
}

func newTunnelResolver(tnet *netstack.Net, servers []dnsEndpoint) *tunnelResolver {
	return &tunnelResolver{tnet: tnet, servers: servers, cache: map[string]dnsCacheEntry{}}
}

func (r *tunnelResolver) Resolve(ctx context.Context, host string) (netip.Addr, error) {
	host = strings.TrimSpace(strings.Trim(host, "[]"))
	if ip, ok := parseIPLiteral(host); ok {
		if ip.IsUnspecified() || ip.IsMulticast() {
			return netip.Addr{}, fmt.Errorf("invalid destination %q", host)
		}
		return ip, nil
	}
	key := strings.ToLower(host)
	r.mu.Lock()
	if entry, ok := r.cache[key]; ok && time.Now().Before(entry.expires) {
		r.mu.Unlock()
		return entry.addr, nil
	}
	r.mu.Unlock()

	query, id, err := buildAQuery(host)
	if err != nil {
		return netip.Addr{}, err
	}
	if len(r.servers) == 0 {
		return netip.Addr{}, errors.New("no DNS server configured for the tunnel")
	}
	var lastErr error
	for _, server := range r.servers {
		addr, ttl, err := r.exchange(ctx, server, query, id, host)
		if err != nil {
			lastErr = err
			continue
		}
		if ttl < 30*time.Second {
			ttl = 30 * time.Second
		}
		if ttl > 10*time.Minute {
			ttl = 10 * time.Minute
		}
		r.mu.Lock()
		if len(r.cache) > 1024 {
			for k, v := range r.cache {
				if time.Now().After(v.expires) {
					delete(r.cache, k)
				}
			}
			if len(r.cache) > 1024 {
				r.cache = map[string]dnsCacheEntry{}
			}
		}
		r.cache[key] = dnsCacheEntry{addr: addr, expires: time.Now().Add(ttl)}
		r.mu.Unlock()
		return addr, nil
	}
	return netip.Addr{}, fmt.Errorf("resolve %s: %w", host, lastErr)
}

func buildAQuery(host string) ([]byte, uint16, error) {
	if !strings.HasSuffix(host, ".") {
		host += "."
	}
	name, err := dnsmessage.NewName(host)
	if err != nil {
		return nil, 0, err
	}
	id := uint16(time.Now().UnixNano())
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, RecursionDesired: true})
	if err = builder.StartQuestions(); err != nil {
		return nil, 0, err
	}
	if err = builder.Question(dnsmessage.Question{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}); err != nil {
		return nil, 0, err
	}
	packet, err := builder.Finish()
	return packet, id, err
}

func (r *tunnelResolver) exchange(ctx context.Context, server dnsEndpoint, query []byte, id uint16, host string) (netip.Addr, time.Duration, error) {
	if r.tnet == nil {
		return netip.Addr{}, 0, errors.New("netstack is unavailable")
	}
	conn, err := r.tnet.DialUDPAddrPort(netip.AddrPort{}, netip.AddrPortFrom(server.addr, server.port))
	if err != nil {
		return netip.Addr{}, 0, err
	}
	defer conn.Close()
	deadline := time.Now().Add(3 * time.Second)
	_ = conn.SetDeadline(deadline)
	if _, err = conn.Write(query); err != nil {
		return netip.Addr{}, 0, err
	}
	response := make([]byte, 4096)
	n, err := conn.Read(response)
	if err != nil {
		return netip.Addr{}, 0, err
	}
	addr, ttl, truncated, err := parseDNSResponse(response[:n], id, host)
	if err != nil {
		return netip.Addr{}, 0, err
	}
	if truncated {
		// Ответ обрезан — повторяем по TCP через тот же туннель.
		tcpAddr, ttl2, err := r.exchangeTCP(ctx, server, query, id, host)
		if err != nil {
			return netip.Addr{}, 0, err
		}
		return tcpAddr, ttl2, nil
	}
	return addr, ttl, nil
}

func (r *tunnelResolver) exchangeTCP(ctx context.Context, server dnsEndpoint, query []byte, id uint16, host string) (netip.Addr, time.Duration, error) {
	dialCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	conn, err := r.tnet.DialContextTCPAddrPort(dialCtx, netip.AddrPortFrom(server.addr, server.port))
	if err != nil {
		return netip.Addr{}, 0, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
	framed := make([]byte, 2+len(query))
	framed[0] = byte(len(query) >> 8)
	framed[1] = byte(len(query))
	copy(framed[2:], query)
	if _, err = conn.Write(framed); err != nil {
		return netip.Addr{}, 0, err
	}
	var length uint16
	if _, err = io.ReadFull(conn, framed[:2]); err != nil {
		return netip.Addr{}, 0, err
	}
	length = uint16(framed[0])<<8 | uint16(framed[1])
	if length == 0 || length > 4096 {
		return netip.Addr{}, 0, errors.New("invalid DNS TCP response length")
	}
	response := make([]byte, length)
	if _, err = io.ReadFull(conn, response); err != nil {
		return netip.Addr{}, 0, err
	}
	addr, ttl, _, err := parseDNSResponse(response, id, host)
	return addr, ttl, err
}

func parseDNSResponse(packet []byte, id uint16, host string) (netip.Addr, time.Duration, bool, error) {
	var parser dnsmessage.Parser
	header, err := parser.Start(packet)
	if err != nil {
		return netip.Addr{}, 0, false, err
	}
	if header.ID != id || !header.Response {
		return netip.Addr{}, 0, false, errors.New("unexpected DNS response")
	}
	switch header.RCode {
	case dnsmessage.RCodeSuccess:
	case dnsmessage.RCodeNameError:
		return netip.Addr{}, 0, false, fmt.Errorf("DNS name %s does not exist", host)
	default:
		return netip.Addr{}, 0, false, fmt.Errorf("DNS error %v", header.RCode)
	}
	if err = parser.SkipAllQuestions(); err != nil {
		return netip.Addr{}, 0, false, err
	}
	for {
		answer, err := parser.AnswerHeader()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			break
		}
		if err != nil {
			return netip.Addr{}, 0, false, err
		}
		ttl := time.Duration(answer.TTL) * time.Second
		switch answer.Type {
		case dnsmessage.TypeA:
			resource, err := parser.AResource()
			if err != nil {
				return netip.Addr{}, 0, false, err
			}
			return netip.AddrFrom4(resource.A), ttl, header.Truncated, nil
		case dnsmessage.TypeAAAA:
			if _, err = parser.AAAAResource(); err != nil {
				return netip.Addr{}, 0, false, err
			}
		case dnsmessage.TypeCNAME:
			if _, err = parser.CNAMEResource(); err != nil {
				return netip.Addr{}, 0, false, err
			}
		default:
			if err = parser.SkipAnswer(); err != nil {
				return netip.Addr{}, 0, false, err
			}
		}
	}
	return netip.Addr{}, 0, header.Truncated, fmt.Errorf("no A record for %s", host)
}

// resolveDialAddress превращает SOCKS-адрес (IP или домен) в netip.AddrPort.
func resolveDialAddress(ctx context.Context, resolver *tunnelResolver, host string, port uint16) (netip.AddrPort, error) {
	addr, err := resolver.Resolve(ctx, host)
	if err != nil {
		return netip.AddrPort{}, err
	}
	if !addr.IsValid() {
		return netip.AddrPort{}, fmt.Errorf("unsupported address family for %s", host)
	}
	return netip.AddrPortFrom(addr, port), nil
}

var _ net.PacketConn = (*tunPacketConn)(nil)
