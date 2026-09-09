package fqdn

import (
	"bytes"
	"encoding/binary"
	"io"
	"net/netip"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func dnsTestName(s string) dnsmessage.Name { return dnsmessage.MustNewName(s) }
func dnsTestA(name string, ttl uint32, ip [4]byte) dnsmessage.Resource {
	return dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: dnsTestName(name), Class: dnsmessage.ClassINET, Type: dnsmessage.TypeA, TTL: ttl}, Body: &dnsmessage.AResource{A: ip}}
}
func dnsTestAAAA(name string, ttl uint32, ip [16]byte) dnsmessage.Resource {
	return dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: dnsTestName(name), Class: dnsmessage.ClassINET, Type: dnsmessage.TypeAAAA, TTL: ttl}, Body: &dnsmessage.AAAAResource{AAAA: ip}}
}
func dnsTestCNAME(name, target string, ttl uint32) dnsmessage.Resource {
	return dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: dnsTestName(name), Class: dnsmessage.ClassINET, Type: dnsmessage.TypeCNAME, TTL: ttl}, Body: &dnsmessage.CNAMEResource{CNAME: dnsTestName(target)}}
}
func dnsTestExchange(t testing.TB, name string, typ dnsmessage.Type, answers, additionals []dnsmessage.Resource) ([]byte, []byte) {
	t.Helper()
	q := dnsmessage.Message{Header: dnsmessage.Header{ID: 173, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: dnsTestName(name), Type: typ, Class: dnsmessage.ClassINET}}}
	query, err := q.Pack()
	if err != nil {
		t.Fatal(err)
	}
	q.Response = true
	q.Answers = answers
	q.Additionals = additionals
	response, err := q.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return query, response
}

func TestDNSReachabilityTTLAndFamily(t *testing.T) {
	q, r := dnsTestExchange(t, "Allow.Example.", dnsmessage.TypeA, []dnsmessage.Resource{
		dnsTestCNAME("allow.example.", "edge.example.", 9), dnsTestCNAME("edge.example.", "cdn.example.", 4), dnsTestA("cdn.example.", 30, [4]byte{1, 2, 3, 4}), dnsTestA("unrelated.example.", 90, [4]byte{9, 9, 9, 9}), dnsTestAAAA("cdn.example.", 60, netip.MustParseAddr("2001:db8::1").As16()),
	}, []dnsmessage.Resource{dnsTestA("unrelated-additional.example.", 100, [4]byte{5, 6, 7, 8})})
	a, err := ParseDNSAnswer(q, r, 1_000_000_000, 4)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Observations) != 1 || a.Observations[0].Name != "allow.example" || a.Observations[0].Address != netip.MustParseAddr("1.2.3.4") || a.Observations[0].ExpiresAt != 5_000_000_000 {
		t.Fatalf("unexpected observations %+v", a.Observations)
	}
	wire, err := a.Pack([]uint32{2})
	if err != nil {
		t.Fatal(err)
	}
	packed, err := unpackDNS(wire)
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range []int{0, 1, 2} {
		if packed.Answers[i].Header.TTL != 2 {
			t.Fatalf("support TTL not clamped: %+v", packed.Answers[i])
		}
	}
	if packed.Answers[3].Header.TTL != 90 {
		t.Fatal("unrelated TTL modified")
	}
	v6, err := ParseDNSAnswer(q, r, 1_000_000_000, 6)
	if err != nil || len(v6.Observations) != 1 || !v6.Observations[0].Address.Is6() {
		t.Fatalf("IPv6 parsing: %+v %v", v6, err)
	}
}

func TestDNSZeroTTLAndANYBarrier(t *testing.T) {
	q, r := dnsTestExchange(t, "allowed.example.", dnsmessage.TypeALL, []dnsmessage.Resource{dnsTestCNAME("allowed.example.", "edge.example.", 0), dnsTestA("edge.example.", 3600, [4]byte{1, 2, 3, 4})}, nil)
	a, err := ParseDNSAnswer(q, r, 55, 4)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Observations) != 1 || a.Observations[0].ExpiresAt != 55 {
		t.Fatalf("ANY/zero TTL must cross publication barrier: %+v", a.Observations)
	}
	wire, err := a.Pack([]uint32{0})
	if err != nil {
		t.Fatal(err)
	}
	message, _ := unpackDNS(wire)
	if message.Answers[1].Header.TTL != 0 {
		t.Fatal("zero TTL was positively clamped")
	}
}

func TestDNSRejectsUncorrelatedAndAmbiguousAnswers(t *testing.T) {
	baseQ, baseR := dnsTestExchange(t, "allowed.example.", dnsmessage.TypeA, []dnsmessage.Resource{dnsTestA("allowed.example.", 10, [4]byte{1, 2, 3, 4})}, nil)
	for _, field := range []string{"id", "question", "type", "class", "response", "opcode"} {
		t.Run(field, func(t *testing.T) {
			m, _ := unpackDNS(baseR)
			switch field {
			case "id":
				m.ID++
			case "question":
				m.Questions[0].Name = dnsTestName("other.example.")
			case "type":
				m.Questions[0].Type = dnsmessage.TypeAAAA
			case "class":
				m.Questions[0].Class = dnsmessage.ClassCHAOS
			case "response":
				m.Response = false
			case "opcode":
				m.OpCode = 2
			}
			wire, _ := m.Pack()
			if _, err := ParseDNSAnswer(baseQ, wire, 1, 4); err == nil {
				t.Fatal("accepted uncorrelated answer")
			}
		})
	}
	for _, rrs := range [][]dnsmessage.Resource{
		{dnsTestCNAME("allowed.example.", "edge.example.", 10), dnsTestCNAME("edge.example.", "allowed.example.", 10)},
		{dnsTestCNAME("allowed.example.", "edge.example.", 10), dnsTestCNAME("allowed.example.", "other.example.", 10)},
		{dnsTestCNAME("allowed.example.", "edge.example.", 10), dnsTestA("allowed.example.", 10, [4]byte{1, 2, 3, 4})},
	} {
		q, r := dnsTestExchange(t, "allowed.example.", dnsmessage.TypeA, rrs, nil)
		if _, err := ParseDNSAnswer(q, r, 1, 4); err == nil {
			t.Fatal("accepted ambiguous CNAME chain")
		}
	}
}

func TestDNSPartialAndNegativeResponsesCannotPublishAddresses(t *testing.T) {
	for _, truncated := range []bool{true, false} {
		q, r := dnsTestExchange(t, "allowed.example.", dnsmessage.TypeA, []dnsmessage.Resource{dnsTestA("allowed.example.", 10, [4]byte{1, 2, 3, 4})}, nil)
		m, _ := unpackDNS(r)
		m.Truncated = truncated
		if !truncated {
			m.RCode = dnsmessage.RCodeNameError
		}
		r, _ = m.Pack()
		a, err := ParseDNSAnswer(q, r, 1, 4)
		if err != nil {
			t.Fatal(err)
		}
		if len(a.Observations) != 0 {
			t.Fatal("partial/negative answer learned")
		}
		wire, err := a.Pack(nil)
		if err != nil {
			t.Fatal(err)
		}
		m, _ = unpackDNS(wire)
		if len(m.Answers) != 0 || len(m.Additionals) != 0 || m.Truncated != truncated {
			t.Fatal("partial/negative positive records escaped")
		}
	}
}

func TestDNSRecordAndCNAMELimits(t *testing.T) {
	q, r := dnsTestExchange(t, "allowed.example.", dnsmessage.TypeA, nil, nil)
	binary.BigEndian.PutUint16(r[6:8], maxDNSRecords+1)
	if _, err := ParseDNSAnswer(q, r, 1, 4); err == nil {
		t.Fatal("oversized record count accepted")
	}
	if _, err := ParseDNSAnswer(q, make([]byte, maxDNSMessage+1), 1, 4); err == nil {
		t.Fatal("oversized message accepted")
	}
}

type dnsShortWriter struct{ bytes.Buffer }

func (w *dnsShortWriter) Write(b []byte) (int, error) {
	if len(b) > 3 {
		b = b[:3]
	}
	return w.Buffer.Write(b)
}
func TestDNSTCPFramingHandlesPartialWritesAndPersistentMessages(t *testing.T) {
	q, r := dnsTestExchange(t, "allowed.example.", dnsmessage.TypeA, nil, nil)
	var writer dnsShortWriter
	for _, wire := range [][]byte{q, r} {
		if err := writeDNSFrame(&writer, wire); err != nil {
			t.Fatal(err)
		}
	}
	for _, want := range [][]byte{q, r} {
		got, err := readDNSFrame(&writer)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("frame corrupted: %v", err)
		}
	}
	if _, err := readDNSFrame(bytes.NewReader([]byte{0, 20, 1, 2})); err != io.ErrUnexpectedEOF {
		t.Fatalf("truncated frame: %v", err)
	}
}

func FuzzDNSResponseParser(f *testing.F) {
	q, r := dnsTestExchange(f, "allowed.example.", dnsmessage.TypeA, []dnsmessage.Resource{dnsTestA("allowed.example.", 10, [4]byte{1, 2, 3, 4})}, nil)
	f.Add(q, r)
	f.Fuzz(func(t *testing.T, query, response []byte) {
		for _, family := range []int{4, 6} {
			answer, err := ParseDNSAnswer(query, response, 1_000_000_000, family)
			if err != nil {
				continue
			}
			if len(answer.Observations) > maxDNSRecords {
				t.Fatal("unbounded records")
			}
			ttls := make([]uint32, len(answer.Observations))
			for i, observation := range answer.Observations {
				if observation.Name != answer.Question || !observation.Address.IsValid() {
					t.Fatal("invalid observation")
				}
				ttls[i] = 1
			}
			if _, err := answer.Pack(ttls); err != nil {
				t.Fatalf("valid answer cannot repack: %v", err)
			}
		}
	})
}
