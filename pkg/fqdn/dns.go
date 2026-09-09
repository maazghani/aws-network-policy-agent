package fqdn

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"strings"
	"time"
)

const maxDNSMessage = 64 << 10

// ParseResponse validates transaction/question correlation and extracts only
// A, AAAA, and CNAME answer records. Additional-section addresses are never
// returned and therefore cannot create grants.
func ParseResponse(request, response []byte, maxRecords int) (Response, error) {
	if len(request) < 12 || len(response) < 12 || len(request) > maxDNSMessage || len(response) > maxDNSMessage {
		return Response{}, errors.New("invalid dns message length")
	}
	if binary.BigEndian.Uint16(request[:2]) != binary.BigEndian.Uint16(response[:2]) {
		return Response{}, errors.New("dns transaction mismatch")
	}
	if response[2]&0x80 == 0 {
		return Response{}, errors.New("not a dns response")
	}
	rq, roff, err := parseQuestion(request)
	if err != nil {
		return Response{}, err
	}
	sq, off, err := parseQuestion(response)
	if err != nil {
		return Response{}, err
	}
	if rq.name != sq.name || rq.typ != sq.typ || rq.class != sq.class || roff < 12 {
		return Response{}, errors.New("dns question mismatch")
	}
	answers := int(binary.BigEndian.Uint16(response[6:8]))
	if answers > maxRecords {
		return Response{}, ErrCapacity
	}
	out := Response{Question: rq.name}
	for i := 0; i < answers; i++ {
		name, n, err := dnsName(response, off, map[int]bool{})
		if err != nil {
			return Response{}, err
		}
		off = n
		if off+10 > len(response) {
			return Response{}, errors.New("truncated resource record")
		}
		typ := binary.BigEndian.Uint16(response[off:])
		class := binary.BigEndian.Uint16(response[off+2:])
		ttl := time.Duration(binary.BigEndian.Uint32(response[off+4:])) * time.Second
		rdlen := int(binary.BigEndian.Uint16(response[off+8:]))
		off += 10
		end := off + rdlen
		if end > len(response) {
			return Response{}, errors.New("truncated rdata")
		}
		if class == 1 {
			switch typ {
			case 1:
				if rdlen == 4 {
					var a [4]byte
					copy(a[:], response[off:end])
					out.Addresses = append(out.Addresses, AddressRecord{Name: name, Address: netip.AddrFrom4(a), TTL: ttl})
				}
			case 28:
				if rdlen == 16 {
					var a [16]byte
					copy(a[:], response[off:end])
					out.Addresses = append(out.Addresses, AddressRecord{Name: name, Address: netip.AddrFrom16(a), TTL: ttl})
				}
			case 5:
				target, _, e := dnsName(response, off, map[int]bool{})
				if e != nil {
					return Response{}, e
				}
				out.CNAMEs = append(out.CNAMEs, CNAMERecord{Name: name, Target: target, TTL: ttl})
			}
		}
		off = end
	}
	return out, nil
}

type question struct {
	name       string
	typ, class uint16
}

func parseQuestion(msg []byte) (question, int, error) {
	if binary.BigEndian.Uint16(msg[4:6]) != 1 {
		return question{}, 0, errors.New("dns message must contain one question")
	}
	name, off, err := dnsName(msg, 12, map[int]bool{})
	if err != nil {
		return question{}, 0, err
	}
	if off+4 > len(msg) {
		return question{}, 0, errors.New("truncated question")
	}
	return question{normalize(name), binary.BigEndian.Uint16(msg[off:]), binary.BigEndian.Uint16(msg[off+2:])}, off + 4, nil
}

func dnsName(msg []byte, off int, seen map[int]bool) (string, int, error) {
	var labels []string
	next := -1
	for steps := 0; steps < 128; steps++ {
		if off >= len(msg) {
			return "", 0, errors.New("truncated dns name")
		}
		if seen[off] {
			return "", 0, errors.New("dns compression loop")
		}
		seen[off] = true
		n := int(msg[off])
		if n == 0 {
			off++
			if next >= 0 {
				off = next
			}
			return strings.ToLower(strings.Join(labels, ".")), off, nil
		}
		if n&0xc0 == 0xc0 {
			if off+1 >= len(msg) {
				return "", 0, errors.New("truncated dns pointer")
			}
			ptr := int(binary.BigEndian.Uint16(msg[off:off+2]) & 0x3fff)
			if ptr >= len(msg) {
				return "", 0, errors.New("invalid dns pointer")
			}
			if next < 0 {
				next = off + 2
			}
			off = ptr
			continue
		}
		if n&0xc0 != 0 || n > 63 || off+1+n > len(msg) {
			return "", 0, errors.New("invalid dns label")
		}
		labels = append(labels, string(msg[off+1:off+1+n]))
		off += 1 + n
	}
	return "", 0, errors.New("dns name too deep")
}
