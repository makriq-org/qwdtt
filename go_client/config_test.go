package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func defaultOptionsForTest() *clientOptions {
	return &clientOptions{
		Mode: "vpn", Listen: "127.0.0.1:9000", SocksAddr: "127.0.0.1:1080",
		Workers: 9, UDP: true, CaptchaMode: "auto", VKAuth: "anonymous",
		VKAnonPath: "vkcalls", GoDNS: "yandex", Obfs: "audio", DeviceID: "test",
	}
}

func writeConfig(t *testing.T, body any, mode os.FileMode) string {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "qwdtt.json")
	if err = os.WriteFile(path, raw, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestConfigFileAppliesWithoutFlags(t *testing.T) {
	path := writeConfig(t, map[string]any{
		"mode":           "socks",
		"peer":           "vpn.example.com:56003",
		"password":       "secret",
		"vk-hashes":      []string{"hash1", "hash2"},
		"workers":        11,
		"tunnel":         "raw-ip",
		"obfs":           "video",
		"turn-transport": "tcp",
		"turn-servers":   []string{"192.0.2.10", "192.0.2.20:443"},
		"turn-port":      3478,
		"dns-server":     "1.1.1.1:5353",
		"socks": map[string]any{
			"listen":    "127.0.0.1:36500",
			"username":  "user",
			"password":  "pass",
			"auth":      true,
			"udp":       true,
			"udp-token": true,
		},
		"device-id":    "node-1",
		"captcha-mode": "native",
	}, 0600)
	cfg, err := readClientConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	opts := defaultOptionsForTest()
	if err = cfg.apply(opts, nil); err != nil {
		t.Fatal(err)
	}
	if opts.Mode != "socks" || opts.Peer != "vpn.example.com:56003" || opts.Workers != 11 {
		t.Fatalf("unexpected options: %+v", opts)
	}
	if opts.Tunnel != "raw-ip" || opts.Port != "3478" || opts.Turn != "192.0.2.10,192.0.2.20:443" {
		t.Fatalf("unexpected tunnel/turn: %+v", opts)
	}
	if opts.SocksAddr != "127.0.0.1:36500" || !opts.SocksAuth || !opts.UDPToken || opts.DNSServer != "1.1.1.1:5353" {
		t.Fatalf("unexpected socks: %+v", opts)
	}
	if err = opts.validate(); err != nil {
		t.Fatal(err)
	}
	tunnel, err := opts.tunnelMode()
	if err != nil || tunnel != tunnelRawIP {
		t.Fatalf("tunnel=%q err=%v", tunnel, err)
	}
}

func TestConfigFileRejectsLoosePermissions(t *testing.T) {
	path := writeConfig(t, map[string]any{"mode": "socks"}, 0644)
	if _, err := readClientConfig(path); err == nil {
		t.Fatal("world-readable config must be rejected")
	}
}

func TestConfigDefaultsAndValidation(t *testing.T) {
	opts := defaultOptionsForTest()
	opts.Tunnel = "wireguard-direct"
	opts.Mode = "socks"
	opts.SocksAuth = true
	opts.SocksUser = "u"
	opts.SocksPass = "p"
	opts.Peer = "host:56002"
	opts.Password = "secret"
	opts.VKHash = "h1"
	if err := opts.validate(); err != nil {
		t.Fatal(err)
	}
	tunnel, _ := opts.tunnelMode()
	if tunnel != tunnelWireGuardDirect {
		t.Fatalf("tunnel=%q", tunnel)
	}

	cases := []struct {
		name   string
		mutate func(*clientOptions)
	}{
		{"workers zero", func(o *clientOptions) { o.Workers = 0 }},
		{"workers too many", func(o *clientOptions) { o.Workers = 163 }},
		{"bad tunnel", func(o *clientOptions) { o.Tunnel = "udp" }},
		{"public socks", func(o *clientOptions) { o.SocksAddr = "0.0.0.0:1080" }},
		{"public wg loopback", func(o *clientOptions) { o.Listen = "0.0.0.0:9000" }},
		{"token without auth", func(o *clientOptions) { o.UDPToken = true; o.SocksAuth = false }},
		{"token without udp", func(o *clientOptions) { o.UDPToken = true; o.UDP = false }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := defaultOptionsForTest()
			o.Mode = "socks"
			o.SocksAuth = true
			o.SocksUser = "u"
			o.SocksPass = "p"
			o.Tunnel = tunnelWireGuard
			tc.mutate(o)
			if err := o.validate(); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestTunnelModeLegacyMapping(t *testing.T) {
	cases := map[string]string{
		"":                 tunnelWireGuard,
		"wireguard":        tunnelWireGuard,
		"wireguard-direct": tunnelWireGuardDirect,
		"raw-ip":           tunnelRawIP,
	}
	for value, want := range cases {
		o := defaultOptionsForTest()
		o.Tunnel = value
		got, err := o.tunnelMode()
		if err != nil || got != want {
			t.Fatalf("%q: got %q err %v", value, got, err)
		}
	}
	o := defaultOptionsForTest()
	o.Mode = "rawtun"
	if got, _ := o.tunnelMode(); got != tunnelRawIP {
		t.Fatalf("rawtun must map to raw-ip, got %q", got)
	}
	o = defaultOptionsForTest()
	o.NoDTLS = true
	if got, _ := o.tunnelMode(); got != tunnelWireGuardDirect {
		t.Fatalf("notls must map to wireguard-direct, got %q", got)
	}
}

func TestGroupSizesPartialLastGroup(t *testing.T) {
	cases := []struct {
		total int
		want  []int
	}{
		{1, []int{1}},
		{8, []int{8}},
		{9, []int{9}},
		{10, []int{9, 1}},
		{17, []int{9, 8}},
		{18, []int{9, 9}},
		{27, []int{9, 9, 9}},
		{28, []int{9, 9, 9, 1}},
	}
	for _, tc := range cases {
		got := groupSizes(tc.total)
		if len(got) != len(tc.want) {
			t.Fatalf("%d: got %v want %v", tc.total, got, tc.want)
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Fatalf("%d: got %v want %v", tc.total, got, tc.want)
			}
		}
	}
}
