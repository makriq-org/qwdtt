package main

// Конфигурация процесса из файла.
//
// FlClashM запускает qwdtt как дочерний процесс и не должен передавать
// пароль подключения, пароль SOCKS5 и прочие секреты в argv: список
// аргументов виден другим процессам через /proc и попадает в диагностику.
// Поэтому все параметры, включая секреты, читаются из приватного JSON-файла,
// а в командной строке остаётся только путь к нему.
//
// Оригинальное Android-приложение продолжает пользоваться флагами: файл
// необязателен, а явно заданные флаги имеют приоритет над файлом.

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

const (
	tunnelWireGuard       = "wireguard"
	tunnelWireGuardDirect = "wireguard-direct"
	tunnelRawIP           = "raw-ip"

	maxWorkersPerHash = 27
	maxWorkerHashes   = 6
)

type socksFileConfig struct {
	Listen    string `json:"listen"`
	Username  string `json:"username"`
	Password  string `json:"password"`
	Auth      *bool  `json:"auth"`
	UDP       *bool  `json:"udp"`
	UDPToken  *bool  `json:"udp-token"`
	UDPMaxAge string `json:"udp-idle-timeout"`
}

type clientFileConfig struct {
	Mode string `json:"mode"`

	Peer      string   `json:"peer"`
	Server    string   `json:"server"`
	Port      any      `json:"port"`
	Password  string   `json:"password"`
	VKHashes  []string `json:"vk-hashes"`
	Workers   *int     `json:"workers"`
	Tunnel    string   `json:"tunnel"`
	Obfs      string   `json:"obfs"`
	UDP       *bool    `json:"udp"`
	TurnAddr  []string `json:"turn-servers"`
	TurnPort  any      `json:"turn-port"`
	TurnTCP   bool     `json:"turn-tcp"`
	Transport string   `json:"turn-transport"`

	Listen    string           `json:"listen"`
	Socks     *socksFileConfig `json:"socks"`
	SocksAddr string           `json:"socks-listen"`
	SocksAuth *bool            `json:"socks-auth"`
	SocksUser string           `json:"socks-username"`
	SocksPass string           `json:"socks-password"`
	UDPToken  *bool            `json:"udp-token"`

	DeviceID     string   `json:"device-id"`
	CaptchaMode  string   `json:"captcha-mode"`
	VKAuth       string   `json:"vk-auth"`
	VKAnonPath   string   `json:"vk-anon-path"`
	VKCredsFile  string   `json:"vk-creds-file"`
	GoDNS        string   `json:"go-dns"`
	DNSFallback  []string `json:"dns-fallback"`
	DNSServer    string   `json:"dns-server"`
	TunFdSock    string   `json:"tun-fd-sock"`
	NoDTLS       *bool    `json:"notls"`
	RawMode      *bool    `json:"raw"`
	LogNoSecrets *bool    `json:"log-no-secrets"`
}

// readClientConfig читает и валидирует файл. Секреты не логируются.
func readClientConfig(path string) (*clientFileConfig, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("config path is not a regular file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("config file must not be readable by group or others")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 || len(raw) > 1<<20 {
		return nil, errors.New("config file has invalid size")
	}
	var cfg clientFileConfig
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	if err = decoder.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("config JSON: %w", err)
	}
	if decoder.More() {
		return nil, errors.New("config JSON has trailing data")
	}
	return &cfg, nil
}

func textPort(value any) (string, error) {
	switch v := value.(type) {
	case nil:
		return "", nil
	case string:
		return strings.TrimSpace(v), nil
	case float64:
		if v != float64(int(v)) || v < 1 || v > 65535 {
			return "", errors.New("port must be an integer within 1..65535")
		}
		return strconv.Itoa(int(v)), nil
	case json.Number:
		n, err := v.Int64()
		if err != nil || n < 1 || n > 65535 {
			return "", errors.New("port must be an integer within 1..65535")
		}
		return strconv.FormatInt(n, 10), nil
	default:
		return "", errors.New("port has unsupported type")
	}
}

// apply переносит значения файла в опции, не переопределяя явные флаги.
func (c *clientFileConfig) apply(o *clientOptions, explicit map[string]bool) error {
	set := func(name string, assign func()) {
		if !explicit[name] {
			assign()
		}
	}
	if c.Mode != "" {
		set("mode", func() { o.Mode = c.Mode })
	}
	if c.Peer != "" {
		set("peer", func() { o.Peer = c.Peer })
	} else if c.Server != "" {
		set("peer", func() {
			port, err := textPort(c.Port)
			if err == nil && port != "" {
				o.Peer = joinHostPort(c.Server, port)
			} else {
				o.Peer = c.Server
			}
		})
	}
	if c.Peer == "" && c.Server != "" {
		if _, err := textPort(c.Port); err != nil {
			return err
		}
	}
	if c.Password != "" {
		set("password", func() { o.Password = c.Password })
	}
	if len(c.VKHashes) > 0 {
		set("vk", func() { o.VKHash = strings.Join(c.VKHashes, ",") })
	}
	if c.Workers != nil {
		set("n", func() { o.Workers = *c.Workers })
	}
	if c.Tunnel != "" {
		set("tunnel", func() { o.Tunnel = c.Tunnel })
	}
	if c.Obfs != "" {
		set("obfs", func() { o.Obfs = c.Obfs })
	}
	if c.UDP != nil {
		set("udp", func() { o.UDP = *c.UDP })
	}
	if len(c.TurnAddr) > 0 {
		set("turn", func() { o.Turn = strings.Join(c.TurnAddr, ",") })
	}
	if port, err := textPort(c.TurnPort); err != nil {
		return fmt.Errorf("turn-port: %w", err)
	} else if port != "" {
		set("port", func() { o.Port = port })
	}
	if c.Transport != "" {
		set("turn-transport", func() { o.TurnTransport = c.Transport })
	}
	if c.TurnTCP {
		set("turn-tcp", func() { o.TurnTCP = true })
	}
	if c.Listen != "" {
		set("listen", func() { o.Listen = c.Listen })
	}
	if c.Socks != nil {
		if c.Socks.Listen != "" {
			set("socks", func() { o.SocksAddr = c.Socks.Listen })
		}
		if c.Socks.Username != "" {
			set("socks-user", func() { o.SocksUser = c.Socks.Username })
		}
		if c.Socks.Password != "" {
			set("socks-pass", func() { o.SocksPass = c.Socks.Password })
		}
		if c.Socks.Auth != nil {
			set("socks-auth", func() { o.SocksAuth = *c.Socks.Auth })
		}
		if c.Socks.UDP != nil {
			set("udp", func() { o.UDP = *c.Socks.UDP })
		}
		if c.Socks.UDPToken != nil {
			set("udp-token", func() { o.UDPToken = *c.Socks.UDPToken })
		}
	}
	if c.SocksAddr != "" {
		set("socks", func() { o.SocksAddr = c.SocksAddr })
	}
	if c.SocksAuth != nil {
		set("socks-auth", func() { o.SocksAuth = *c.SocksAuth })
	}
	if c.SocksUser != "" {
		set("socks-user", func() { o.SocksUser = c.SocksUser })
	}
	if c.SocksPass != "" {
		set("socks-pass", func() { o.SocksPass = c.SocksPass })
	}
	if c.UDPToken != nil {
		set("udp-token", func() { o.UDPToken = *c.UDPToken })
	}
	if c.DeviceID != "" {
		set("device-id", func() { o.DeviceID = c.DeviceID })
	}
	if c.CaptchaMode != "" {
		set("captcha-mode", func() { o.CaptchaMode = c.CaptchaMode })
	}
	if c.VKAuth != "" {
		set("vk-auth", func() { o.VKAuth = c.VKAuth })
	}
	if c.VKAnonPath != "" {
		set("vk-anon-path", func() { o.VKAnonPath = c.VKAnonPath })
	}
	if c.VKCredsFile != "" {
		set("vk-creds-file", func() { o.VKCredsFile = c.VKCredsFile })
	}
	if c.GoDNS != "" {
		set("go-dns", func() { o.GoDNS = c.GoDNS })
	}
	if len(c.DNSFallback) > 0 {
		set("dns-fallback", func() { o.DNSFallback = strings.Join(c.DNSFallback, ",") })
	}
	if c.DNSServer != "" {
		o.DNSServer = c.DNSServer
	}
	if c.TunFdSock != "" {
		set("tun-fd-sock", func() { o.TunFdSock = c.TunFdSock })
	}
	if c.NoDTLS != nil {
		set("notls", func() { o.NoDTLS = *c.NoDTLS })
	}
	if c.RawMode != nil {
		set("tunnel", func() {
			if *c.RawMode {
				o.Tunnel = tunnelRawIP
			}
		})
	}
	return nil
}

func joinHostPort(host, port string) string {
	host = strings.TrimSpace(host)
	port = strings.TrimSpace(port)
	if host == "" || port == "" {
		return host
	}
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		return "[" + host + "]:" + port
	}
	return host + ":" + port
}

// clientOptions — все параметры одного запуска. Флаги и файл заполняют одну
// и ту же структуру, поэтому значения не могут разойтись.
type clientOptions struct {
	Config string

	Mode          string
	Tunnel        string
	Turn          string
	Port          string
	Listen        string
	VKHash        string
	Peer          string
	Workers       int
	PingOnly      bool
	DeviceID      string
	Password      string
	CaptchaMode   string
	VKAuth        string
	VKAnonPath    string
	VKCredsFile   string
	GoDNS         string
	DNSFallback   string
	Obfs          string
	CheckHashes   bool
	SocksAddr     string
	SocksAuth     bool
	SocksUser     string
	SocksPass     string
	UDP           bool
	UDPToken      bool
	NoDTLS        bool
	TurnTCP       bool
	TurnTransport string
	TunFdSock     string
	DiagOnly      bool
	DiagKey       string
	DiagPorts     string
	DiagAuto      bool
	DiagTrigger   string
	DNSServer     string
}

func (o *clientOptions) tunnelMode() (string, error) {
	value := strings.ToLower(strings.TrimSpace(o.Tunnel))
	switch value {
	case tunnelWireGuard:
		return tunnelWireGuard, nil
	case tunnelWireGuardDirect, "wireguard-no-dtls", "notls":
		return tunnelWireGuardDirect, nil
	case tunnelRawIP, "raw", "rawtun":
		return tunnelRawIP, nil
	case "":
		if o.Mode == "rawtun" {
			return tunnelRawIP, nil
		}
		if o.NoDTLS {
			return tunnelWireGuardDirect, nil
		}
		return tunnelWireGuard, nil
	default:
		return "", fmt.Errorf("unsupported tunnel %q", o.Tunnel)
	}
}

func (o *clientOptions) validate() error {
	switch o.Mode {
	case "vpn", "socks", "rawtun":
	default:
		return fmt.Errorf("unsupported mode %q", o.Mode)
	}
	tunnel, err := o.tunnelMode()
	if err != nil {
		return err
	}
	if o.Mode == "socks" && tunnel != tunnelRawIP && o.Listen != "" && !isLoopbackAddress(o.Listen) {
		return errors.New("local WireGuard listener must be loopback")
	}
	if o.Mode == "socks" {
		if !isLoopbackAddress(o.SocksAddr) {
			return errors.New("SOCKS5 listener must be loopback")
		}
		if o.UDPToken {
			if !o.SocksAuth {
				return errors.New("udp-token requires SOCKS5 authentication")
			}
			if !o.UDP {
				return errors.New("udp-token requires UDP support")
			}
			if len([]byte(o.SocksUser)) > 255 || len([]byte(o.SocksPass)) > 255 {
				return errors.New("SOCKS5 credentials must be at most 255 bytes")
			}
		}
		if o.SocksAuth && (o.SocksUser == "" || o.SocksPass == "") {
			return errors.New("SOCKS5 authentication requires username and password")
		}
	}
	if o.Mode != "socks" && o.UDPToken {
		return errors.New("udp-token is supported only in socks mode")
	}
	if tunnel == tunnelRawIP && o.Mode != "socks" && o.Mode != "rawtun" {
		return errors.New("raw-ip tunnel requires socks or rawtun mode")
	}
	if o.Workers < 1 {
		return errors.New("workers must be at least 1")
	}
	if o.Workers > maxWorkersPerHash*maxWorkerHashes {
		return fmt.Errorf("workers must not exceed %d", maxWorkersPerHash*maxWorkerHashes)
	}
	return nil
}

func isLoopbackAddress(address string) bool {
	host, _, err := splitHostPortDefault(address, "")
	if err != nil || host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip, err := netip.ParseAddr(strings.Trim(host, "[]"))
	return err == nil && ip.IsLoopback()
}

func parseIPLiteral(host string) (netip.Addr, bool) {
	ip, err := netip.ParseAddr(strings.Trim(strings.TrimSpace(host), "[]"))
	if err != nil {
		return netip.Addr{}, false
	}
	return ip.Unmap(), true
}

func bindClientFlags(o *clientOptions) {
	flag.StringVar(&o.Config, "config", "", "путь к JSON-конфигурации (секреты не передаются в argv)")
	flag.StringVar(&o.Turn, "turn", "", "свои TURN-адреса вместо адресов VK: IP или IP:порт через запятую")
	flag.StringVar(&o.Port, "port", "", "переопределить порт TURN")
	flag.StringVar(&o.Listen, "listen", "127.0.0.1:9000", "локальный адрес WireGuard-loopback")
	flag.StringVar(&o.VKHash, "vk", "", "хеши VK-звонков (через запятую)")
	flag.StringVar(&o.Peer, "peer", "", "адрес:порт VPS сервера")
	flag.IntVar(&o.Workers, "n", 9, "количество воркеров")
	flag.BoolVar(&o.PingOnly, "ping-only", false, "запустить только замер задержки и выйти")
	flag.StringVar(&o.DeviceID, "device-id", "unknown", "уникальный ID устройства")
	flag.StringVar(&o.Password, "password", "", "пароль подключения")
	flag.StringVar(&o.CaptchaMode, "captcha-mode", "auto", "режим обхода капчи (auto/native/wv/rjs)")
	flag.StringVar(&o.VKAuth, "vk-auth", "anonymous", "режим VK авторизации (account/anonymous)")
	flag.StringVar(&o.VKAnonPath, "vk-anon-path", "vkcalls", "анонимный путь VK TURN (vkcalls/legacy)")
	flag.StringVar(&o.VKCredsFile, "vk-creds-file", "", "файл с TURN кредами от аккаунта VK")
	flag.StringVar(&o.GoDNS, "go-dns", "yandex", "DNS для VK (yandex/cloudflare/google, doh-yandex/doh-cloudflare/doh-google, custom:IP или doh:URL)")
	flag.StringVar(&o.DNSFallback, "dns-fallback", "", "DNS текущей сети (оператора/роутера) через запятую — запасной для -go-dns, основной для -go-dns operator")
	flag.StringVar(&o.Obfs, "obfs", "audio", "режим обфускации (audio/video)")
	flag.BoolVar(&o.CheckHashes, "check-hashes", false, "проверить VK-хеши и выйти")
	flag.StringVar(&o.Mode, "mode", "vpn", "режим клиента (vpn|socks|rawtun)")
	flag.StringVar(&o.SocksAddr, "socks", "127.0.0.1:1080", "локальный SOCKS5 (только -mode socks)")
	flag.BoolVar(&o.SocksAuth, "socks-auth", false, "требовать логин и пароль SOCKS5")
	flag.StringVar(&o.SocksUser, "socks-user", "", "логин SOCKS5")
	flag.StringVar(&o.SocksPass, "socks-pass", "", "пароль SOCKS5")
	flag.BoolVar(&o.UDP, "udp", true, "разрешить UDP ASSOCIATE в SOCKS5")
	flag.BoolVar(&o.UDPToken, "udp-token", false, "требовать flclashm-udp-token в UDP ASSOCIATE")
	flag.BoolVar(&o.NoDTLS, "notls", false, "прямой режим: RTP-obfs AEAD без DTLS поверх TURN (нужен сервер с -listen-direct)")
	flag.BoolVar(&o.TurnTCP, "turn-tcp", false, "то же, что -turn-transport tcp (оставлено для совместимости)")
	flag.StringVar(&o.TurnTransport, "turn-transport", "", "транспорт до TURN-relay VK: udp или tcp")
	flag.StringVar(&o.TunFdSock, "tun-fd-sock", "", "unix-сокет для получения TUN fd от Android (только -mode rawtun)")
	flag.StringVar(&o.Tunnel, "tunnel", "", "режим туннеля: wireguard | wireguard-direct | raw-ip")
	flag.StringVar(&o.DNSServer, "dns-server", "", "DNS для пользовательского трафика: system или IP[:порт]")
	flag.BoolVar(&o.DiagOnly, "diag", false, "проверить соединение через VK (TURN, сервер, пароль, порты, MTU) и выйти")
	flag.StringVar(&o.DiagKey, "diag-key", "", "ключ диагностики сервера из ссылки (dk=)")
	flag.StringVar(&o.DiagPorts, "diag-ports", "", "порты сервера для проверки: dtls=56000,direct=56002,raw=56003")
	flag.BoolVar(&o.DiagAuto, "diag-auto", true, "проверять соединение автоматически, если туннель не поднимается")
	flag.StringVar(&o.DiagTrigger, "diag-trigger", "", "файл-триггер: появился — запустить проверку (для приложения)")
}
