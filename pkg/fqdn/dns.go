package fqdn

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

const maxDNSMessage = 65535
const maxDNSRecords = 1024
const maxCNAMEHops = 16

// DNSAnswer contains only address observations supported by the question and a
// complete, acyclic CNAME chain in this answer. Unrelated additional records are
// never authority. Split CNAME answers remain informational until a complete
// answer is observed; no cross-query global DNS cache is used.
type DNSAnswer struct {
	Question     string
	Observations []Observation
	message      dnsmessage.Message
	indices      []dnsRecordIndex
	chain        []dnsRecordIndex
}

type dnsRecordIndex struct{ section, index int }

func (a *DNSAnswer) record(index dnsRecordIndex) *dnsmessage.Resource {
	switch index.section {
	case 0:
		return &a.message.Answers[index.index]
	case 1:
		return &a.message.Authorities[index.index]
	default:
		return &a.message.Additionals[index.index]
	}
}

func dnsName(s string) string { return strings.ToLower(strings.TrimSuffix(s, ".")) }

func unpackDNS(wire []byte) (dnsmessage.Message, error) {
	var message dnsmessage.Message
	if len(wire) < 12 || len(wire) > maxDNSMessage {
		return message, errors.New("invalid DNS message length")
	}
	count := func(i int) int { return int(wire[i])<<8 | int(wire[i+1]) }
	if count(4) != 1 || count(6)+count(8)+count(10) > maxDNSRecords {
		return message, errors.New("DNS question or record limit")
	}
	if err := message.Unpack(wire); err != nil {
		return message, err
	}
	return message, nil
}

// ParseDNSAnswer validates transport-independent request/response correlation.
// now is CLOCK_BOOTTIME nanoseconds, the same clock used by the datapath.
func ParseDNSAnswer(request, response []byte, now uint64, family int) (*DNSAnswer, error) {
	query, err := unpackDNS(request)
	if err != nil {
		return nil, err
	}
	answer, err := unpackDNS(response)
	if err != nil {
		return nil, err
	}
	if query.Response || query.OpCode != 0 || !answer.Response || answer.ID != query.ID || answer.OpCode != query.OpCode {
		return nil, errors.New("uncorrelated DNS response")
	}
	q, a := query.Questions[0], answer.Questions[0]
	if dnsName(q.Name.String()) != dnsName(a.Name.String()) || q.Type != a.Type || q.Class != a.Class {
		return nil, errors.New("DNS question mismatch")
	}
	out := &DNSAnswer{Question: dnsName(q.Name.String()), message: answer}
	if answer.Truncated || answer.RCode != dnsmessage.RCodeSuccess || q.Class != dnsmessage.ClassINET {
		// A partial or negative response cannot establish the full address set.
		// Preserve its status/question but remove any contradictory positive
		// records when Pack is used for a matched response. Informational
		// nonmatching replies retain the original validated upstream bytes.
		out.message.Answers, out.message.Authorities, out.message.Additionals = nil, nil, nil
		return out, nil
	}
	if family != 4 && family != 6 {
		return nil, errors.New("invalid enforced address family")
	}
	current, deadline := out.Question, ^uint64(0)
	seen := make(map[string]bool)
	sections := [][]dnsmessage.Resource{answer.Answers, answer.Authorities, answer.Additionals}
	for hops := 0; ; hops++ {
		if seen[current] || hops > maxCNAMEHops {
			return nil, errors.New("cyclic or excessive DNS CNAME chain")
		}
		seen[current] = true
		aliasIndex := dnsRecordIndex{index: -1}
		for section, records := range sections {
			for i, rr := range records {
				if rr.Header.Class != dnsmessage.ClassINET || dnsName(rr.Header.Name.String()) != current {
					continue
				}
				if _, ok := rr.Body.(*dnsmessage.CNAMEResource); ok {
					if aliasIndex.index != -1 {
						return nil, errors.New("ambiguous DNS CNAME owner")
					}
					aliasIndex = dnsRecordIndex{section: section, index: i}
				}
			}
		}
		if aliasIndex.index == -1 {
			break
		}
		for _, records := range sections {
			for _, rr := range records {
				if rr.Header.Class == dnsmessage.ClassINET && dnsName(rr.Header.Name.String()) == current && (rr.Header.Type == dnsmessage.TypeA || rr.Header.Type == dnsmessage.TypeAAAA) {
					return nil, errors.New("DNS CNAME owner also has an address")
				}
			}
		}
		rr := out.record(aliasIndex)
		ttlDeadline := now + uint64(rr.Header.TTL)*1_000_000_000
		if ttlDeadline < now {
			ttlDeadline = ^uint64(0)
		}
		if ttlDeadline < deadline {
			deadline = ttlDeadline
		}
		out.chain = append(out.chain, aliasIndex)
		current = dnsName(rr.Body.(*dnsmessage.CNAMEResource).CNAME.String())
	}
	for section, records := range sections {
		for i, rr := range records {
			if rr.Header.Class != dnsmessage.ClassINET || dnsName(rr.Header.Name.String()) != current {
				continue
			}
			var addr netip.Addr
			switch resource := rr.Body.(type) {
			case *dnsmessage.AResource:
				if family == 4 {
					addr = netip.AddrFrom4(resource.A)
				}
			case *dnsmessage.AAAAResource:
				if family == 6 {
					addr = netip.AddrFrom16(resource.AAAA)
				}
			}
			if !addr.IsValid() {
				continue
			}
			end := now + uint64(rr.Header.TTL)*1_000_000_000
			if end < now {
				end = ^uint64(0)
			}
			if deadline < end {
				end = deadline
			}
			out.Observations = append(out.Observations, Observation{Name: out.Question, Address: addr, ExpiresAt: end})
			out.indices = append(out.indices, dnsRecordIndex{section: section, index: i})
		}
	}
	return out, nil
}

// Pack clamps all returned supporting TTLs to the lifetime the publication
// fence actually admitted. It never increases an upstream TTL, including zero.
func (a *DNSAnswer) Pack(ttls []uint32) ([]byte, error) {
	if len(ttls) != len(a.indices) {
		return nil, fmt.Errorf("DNS publication TTL count %d, want %d", len(ttls), len(a.indices))
	}
	minimum := ^uint32(0)
	for j, i := range a.indices {
		record := a.record(i)
		if ttls[j] < record.Header.TTL {
			record.Header.TTL = ttls[j]
		}
		if record.Header.TTL < minimum {
			minimum = record.Header.TTL
		}
	}
	if len(a.indices) > 0 {
		for _, i := range a.chain {
			record := a.record(i)
			if minimum < record.Header.TTL {
				record.Header.TTL = minimum
			}
		}
	}
	return a.message.Pack()
}

func dnsFailure(request []byte) []byte {
	query, err := unpackDNS(request)
	if err != nil || query.Response {
		return nil
	}
	query.Response, query.Authoritative, query.Truncated = true, false, false
	query.RCode = dnsmessage.RCodeServerFailure
	query.Answers, query.Authorities, query.Additionals = nil, nil, nil
	wire, _ := query.Pack()
	return wire
}
