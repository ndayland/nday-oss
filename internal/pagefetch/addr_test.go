package pagefetch

import (
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestIsPublicAddr(t *testing.T) {
	cases := []struct {
		addr string
		want bool
	}{
		// IPv4 public
		{"8.8.8.8", true}, {"1.1.1.1", true}, {"93.184.216.34", true},
		{"100.63.255.255", true}, {"100.128.0.0", true}, // just outside 100.64/10
		{"172.15.255.255", true}, {"172.32.0.0", true}, // just outside 172.16/12
		{"169.253.255.255", true}, {"169.255.0.0", true},
		{"198.17.255.255", true}, {"198.20.0.0", true}, // around 198.18/15
		{"223.255.255.255", true}, {"11.0.0.0", true}, {"192.0.1.1", true}, {"192.0.3.0", true},
		// IPv4 non-public
		{"0.0.0.0", false}, {"0.1.2.3", false}, {"10.0.0.1", false}, {"10.255.255.255", false},
		{"100.64.0.0", false}, {"100.127.255.255", false}, {"127.0.0.1", false}, {"127.255.255.254", false},
		{"169.254.169.254", false}, {"169.254.0.0", false}, {"172.16.0.0", false}, {"172.31.255.255", false},
		{"192.0.0.1", false}, {"192.0.0.255", false}, {"192.0.2.1", false}, {"192.88.99.1", false},
		{"192.168.1.1", false}, {"198.18.0.1", false}, {"198.19.255.255", false},
		{"198.51.100.7", false}, {"203.0.113.9", false}, {"224.0.0.1", false}, {"239.255.255.255", false},
		{"240.0.0.1", false}, {"255.255.255.255", false},
		// IPv6 public
		{"2606:4700::1111", true}, {"2a00:1450:4001::1", true}, {"2400:cb00::1", true},
		{"::ffff:8.8.8.8", true}, {"64:ff9b::808:808", true}, {"2002:808:808::1", true},
		// IPv6 non-public
		{"::", false}, {"::1", false}, {"fe80::1", false}, {"febf::1", false}, {"fc00::1", false}, {"fd12:3456::1", false},
		{"ff02::1", false}, {"ff0e::1", false}, {"100::1", false}, {"2001:db8::1", false}, {"2001::1", false},
		{"2001:0:4136:e378::1", false}, {"3fff::1", false}, {"4000::1", false},
		// mapped / compatible / NAT64 / 6to4 forms of non-public IPv4
		{"::ffff:127.0.0.1", false}, {"::ffff:10.0.0.1", false}, {"::ffff:169.254.169.254", false}, {"::ffff:0.0.0.0", false},
		{"::127.0.0.1", false}, {"::8.8.8.8", false}, // IPv4-compatible: always refused
		{"64:ff9b::7f00:1", false}, {"64:ff9b::a9fe:a9fe", false}, {"64:ff9b::a00:1", false}, {"64:ff9b:1::808:808", false},
		{"2002:7f00:1::1", false}, {"2002:a9fe:a9fe::1", false}, {"2002:c0a8:101::", false},
		// zone
		{"fe80::1%en0", false},
	}
	for _, c := range cases {
		a, err := netip.ParseAddr(c.addr)
		if err != nil {
			t.Fatalf("%s: %v", c.addr, err)
		}
		if got := IsPublicAddr(a); got != c.want {
			t.Errorf("IsPublicAddr(%s) = %v, want %v", c.addr, got, c.want)
		}
	}
	if IsPublicAddr(netip.Addr{}) {
		t.Error("the zero Addr is public")
	}
	for _, c := range []struct{ network, addr string }{{"udp", "8.8.8.8:53"}, {"tcp", "127.0.0.1:80"}, {"tcp6", "[::1]:443"},
		{"tcp", "localhost:80"}, {"tcp", "[::ffff:10.0.0.1]:80"}} {
		if err := GuardControl(c.network, c.addr, nil); !errors.Is(err, ErrRefused) {
			t.Errorf("GuardControl(%s, %s) = %v", c.network, c.addr, err)
		}
	}
	if err := GuardControl("tcp4", "8.8.8.8:443", nil); err != nil {
		t.Errorf("public address refused: %v", err)
	}
}

// TestGuardNoConnection: a dialer with the real guard refuses a loopback
// listener without connecting (the listener never accepts anything).
func TestGuardNoConnection(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan struct{}, 1)
	go func() {
		if c, err := ln.Accept(); err == nil {
			accepted <- struct{}{}
			c.Close()
		}
	}()
	d := net.Dialer{Control: GuardControl, Timeout: time.Second}
	if c, err := d.Dial("tcp", ln.Addr().String()); err == nil || !errors.Is(err, ErrRefused) {
		if c != nil {
			c.Close()
		}
		t.Fatalf("dial: %v", err)
	}
	select {
	case <-accepted:
		t.Fatal("the guarded dial reached the listener")
	case <-time.After(200 * time.Millisecond):
	}
}
