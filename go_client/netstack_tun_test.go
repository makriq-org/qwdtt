package main

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func TestParseDNSEndpoints(t *testing.T) {
	endpoints, err := parseDNSEndpoints("1.1.1.1, 8.8.8.8:5353; 1.1.1.1")
	if err != nil {
		t.Fatal(err)
	}
	if len(endpoints) != 2 {
		t.Fatalf("endpoints=%v", endpoints)
	}
	if endpoints[0].String() != "1.1.1.1:53" || endpoints[1].String() != "8.8.8.8:5353" {
		t.Fatalf("endpoints=%v", endpoints)
	}
	if _, err = parseDNSEndpoints("dns.example.com"); err == nil {
		t.Fatal("hostname DNS server must be rejected")
	}
	if _, err = parseDNSEndpoints("1.1.1.1:70000"); err == nil {
		t.Fatal("invalid port must be rejected")
	}
	if got, err := parseDNSEndpoints("system"); err != nil || got != nil {
		t.Fatalf("system: %v %v", got, err)
	}
}

func TestEffectiveDNSPriority(t *testing.T) {
	explicit, err := effectiveDNS("1.1.1.1:5353", "9.9.9.9", []netip.Addr{netip.MustParseAddr("8.8.8.8")})
	if err != nil {
		t.Fatal(err)
	}
	if len(explicit) != 1 || explicit[0].String() != "1.1.1.1:5353" {
		t.Fatalf("explicit DNS overridden: %v", explicit)
	}
	system, err := effectiveDNS("system", "9.9.9.9:53", []netip.Addr{netip.MustParseAddr("8.8.8.8")})
	if err != nil {
		t.Fatal(err)
	}
	if len(system) != 1 || system[0].addr.String() != "8.8.8.8" {
		t.Fatalf("system DNS must prefer the tunnel resolver: %v", system)
	}
	fallbackOnly, err := effectiveDNS("system", "9.9.9.9:53", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(fallbackOnly) != 1 || fallbackOnly[0].addr.String() != "9.9.9.9" {
		t.Fatalf("fallback DNS: %v", fallbackOnly)
	}
	tunnel, err := effectiveDNS("system", "", []netip.Addr{netip.MustParseAddr("8.8.8.8")})
	if err != nil {
		t.Fatal(err)
	}
	if len(tunnel) != 1 || tunnel[0].addr.String() != "8.8.8.8" {
		t.Fatalf("tunnel DNS fallback: %v", tunnel)
	}
}

func TestParseRawConf(t *testing.T) {
	ip, dns, mtu, err := parseRawConf("RAWCONF:10.66.0.2|8.8.8.8, 1.1.1.1|1280")
	if err != nil {
		t.Fatal(err)
	}
	if ip.String() != "10.66.0.2" || mtu != 1280 || len(dns) != 2 {
		t.Fatalf("ip=%v dns=%v mtu=%d", ip, dns, mtu)
	}
	for _, bad := range []string{"RAWCONF:", "RAWCONF:10.66.0.2|8.8.8.8", "RAWCONF:not-ip|8.8.8.8|1280", "RAWCONF:10.66.0.2|8.8.8.8|100"} {
		if _, _, _, err = parseRawConf(bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}

func TestParseDNSResponse(t *testing.T) {
	name, _ := dnsmessage.NewName("example.com.")
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 42, Response: true, RecursionAvailable: true})
	if err := builder.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := builder.Question(dnsmessage.Question{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}); err != nil {
		t.Fatal(err)
	}
	if err := builder.StartAnswers(); err != nil {
		t.Fatal(err)
	}
	if err := builder.AResource(dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60}, dnsmessage.AResource{A: [4]byte{93, 184, 216, 34}}); err != nil {
		t.Fatal(err)
	}
	packet, err := builder.Finish()
	if err != nil {
		t.Fatal(err)
	}
	addr, ttl, _, err := parseDNSResponse(packet, 42, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if addr.String() != "93.184.216.34" || ttl != time.Minute {
		t.Fatalf("addr=%v ttl=%v", addr, ttl)
	}
	if _, _, _, err = parseDNSResponse(packet, 43, "example.com"); err == nil {
		t.Fatal("mismatched ID accepted")
	}
}

func TestTunnelResolverIPLiteral(t *testing.T) {
	resolver := newTunnelResolver(nil, nil)
	addr, err := resolver.Resolve(context.Background(), "127.0.0.1")
	if err != nil || addr.String() != "127.0.0.1" {
		t.Fatalf("addr=%v err=%v", addr, err)
	}
	if _, err = resolver.Resolve(context.Background(), "example.com"); err == nil || !strings.Contains(err.Error(), "DNS server") {
		t.Fatalf("expected resolve error, got %v", err)
	}
}
