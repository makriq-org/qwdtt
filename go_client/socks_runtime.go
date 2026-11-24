package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"golang.zx2c4.com/wireguard/tun/netstack"
)

// startSocksServer связывает SOCKS5 с уже поднятым netstack. Все dial'ы идут
// через него, поэтому источником пакетов остаётся выбранный транспорт.
func startSocksServer(ctx context.Context, opts *clientOptions, tnet *netstack.Net, resolver *tunnelResolver) error {
	if tnet == nil || resolver == nil {
		return errors.New("SOCKS5 requires netstack")
	}
	return runSocks5Server(ctx, socksServerConfig{
		Listen:      opts.SocksAddr,
		Username:    opts.SocksUser,
		Password:    opts.SocksPass,
		RequireAuth: opts.SocksAuth,
		AllowUDP:    opts.UDP,
		UDPToken:    opts.UDPToken,
		Resolver:    resolver,
		DialTCP: func(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
			return tnet.DialContextTCPAddrPort(ctx, addr)
		},
		DialUDP: func(addr netip.AddrPort) (net.Conn, error) {
			return tnet.DialUDPAddrPort(netip.AddrPort{}, addr)
		},
	})
}

// parseRawConf разбирает ответ сервера RAWCONF:ip|dns|mtu.
func parseRawConf(conf string) (netip.Addr, []netip.Addr, int, error) {
	parts := strings.Split(strings.TrimPrefix(conf, "RAWCONF:"), "|")
	if len(parts) != 3 {
		return netip.Addr{}, nil, 0, fmt.Errorf("некорректный RAWCONF: %q", conf)
	}
	ip, err := netip.ParseAddr(strings.TrimSpace(parts[0]))
	if err != nil {
		return netip.Addr{}, nil, 0, fmt.Errorf("RAWCONF IP: %w", err)
	}
	mtu, err := strconv.Atoi(strings.TrimSpace(parts[2]))
	if err != nil || mtu < 576 || mtu > 65535 {
		return netip.Addr{}, nil, 0, fmt.Errorf("RAWCONF MTU %q", parts[2])
	}
	var dns []netip.Addr
	for _, entry := range strings.FieldsFunc(parts[1], func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\t'
	}) {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		host, _, err := splitHostPortDefault(entry, "")
		if err != nil {
			continue
		}
		if addr, ok := parseIPLiteral(host); ok {
			dns = append(dns, addr)
		}
	}
	if !ip.Is4() {
		return netip.Addr{}, nil, 0, errors.New("RAWCONF requires an IPv4 client address")
	}
	return ip, dns, mtu, nil
}
