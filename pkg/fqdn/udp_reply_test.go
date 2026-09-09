package fqdn

import (
	"encoding/hex"
	"net/netip"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func TestDNSRawUDPReplyPacketVectors(t *testing.T) {
	for _, test := range []struct{ source, destination, wire string }{
		{"192.0.2.1:53", "198.51.100.2:40000", "4500001f0000000040118e97c0000201c633640200359c40000bb2c8616263"},
		{"[2001:db8::1]:53", "[2001:db8::2]:40000", "60000000000b114020010db800000000000000000000000120010db800000000000000000000000200359c40000b438b616263"},
	} {
		packet, err := dnsUDPReplyPacket(netip.MustParseAddrPort(test.source), netip.MustParseAddrPort(test.destination), []byte("abc"))
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(packet) != test.wire {
			t.Fatalf("IP/UDP tuple or checksum wrong: got %x want %s", packet, test.wire)
		}
	}
	if _, err := dnsUDPReplyPacket(netip.MustParseAddrPort("192.0.2.1:1053"), netip.MustParseAddrPort("198.51.100.2:40000"), []byte("abc")); err == nil {
		t.Fatal("non-resolver sourceport accepted")
	}
	if _, err := dnsUDPReplyPacket(netip.MustParseAddrPort("192.0.2.1:53"), netip.MustParseAddrPort("[2001:db8::2]:40000"), []byte("abc")); err == nil {
		t.Fatal("mixed-family reply accepted")
	}
	if _, err := dnsUDPReplyPacket(netip.MustParseAddrPort("192.0.2.1:53"), netip.MustParseAddrPort("198.51.100.2:40000"), make([]byte, maxDNSUDPPayload+1)); err == nil {
		t.Fatal("fragment-requiring payload accepted")
	}
}

func TestDNSUDPTruncationHonorsClientAndPathLimits(t *testing.T) {
	var records []dnsmessage.Resource
	for i := 0; i < 80; i++ {
		records = append(records, dnsTestA("allowed.example.", 60, [4]byte{192, 0, 2, byte(i)}))
	}
	q, r := dnsTestExchange(t, "allowed.example.", dnsmessage.TypeA, records, nil)
	if dnsUDPLimit(q) != 512 {
		t.Fatal("legacy UDP size changed")
	}
	message, _ := unpackDNS(q)
	message.Additionals = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: dnsTestName("."), Type: dnsmessage.TypeOPT, Class: dnsmessage.Class(4096)}, Body: &dnsmessage.UnknownResource{Type: dnsmessage.TypeOPT}}}
	edns, err := message.Pack()
	if err != nil {
		t.Fatal(err)
	}
	if dnsUDPLimit(edns) != maxDNSUDPPayload {
		t.Fatal("EDNS exceeded minimum-path-MTU payload")
	}
	for _, query := range [][]byte{q, edns} {
		wire, err := fitDNSUDP(query, r)
		if err != nil {
			t.Fatal(err)
		}
		answer, err := ParseDNSAnswer(query, wire, 1, 4)
		if err != nil {
			t.Fatal(err)
		}
		if !answer.message.Truncated || len(answer.Observations) != 0 || len(answer.message.Answers) != 0 {
			t.Fatal("truncated response leaked positive address records")
		}
		if len(wire) > dnsUDPLimit(query) {
			t.Fatal("fallback exceeds client buffer")
		}
	}
}
