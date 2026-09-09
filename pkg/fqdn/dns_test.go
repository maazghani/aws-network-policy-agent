package fqdn

import (
	"encoding/binary"
	"testing"
)

func query(id uint16, name string) []byte {
	b := make([]byte, 12)
	binary.BigEndian.PutUint16(b, id)
	binary.BigEndian.PutUint16(b[4:], 1)
	for _, l := range split(name) {
		b = append(b, byte(len(l)))
		b = append(b, l...)
	}
	b = append(b, 0, 0, 1, 0, 1)
	return b
}
func split(s string) []string {
	var o []string
	start := 0
	for i := range s {
		if s[i] == '.' {
			o = append(o, s[start:i])
			start = i + 1
		}
	}
	return append(o, s[start:])
}
func TestParseResponseCorrelationAndAdditionalExclusion(t *testing.T) {
	q := query(7, "api.example")
	r := append([]byte(nil), q...)
	r[2] = 0x80
	binary.BigEndian.PutUint16(r[6:], 1)
	binary.BigEndian.PutUint16(r[10:], 1)
	r = append(r, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 10, 0, 4, 192, 0, 2, 1)
	r = append(r, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 10, 0, 4, 192, 0, 2, 99)
	got, err := ParseResponse(q, r, 8)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Addresses) != 1 || got.Addresses[0].Address.String() != "192.0.2.1" {
		t.Fatalf("addresses %#v", got.Addresses)
	}
	r[0] = 9
	if _, err := ParseResponse(q, r, 8); err == nil {
		t.Fatal("accepted transaction mismatch")
	}
}
func FuzzParseResponse(f *testing.F) {
	q := query(1, "a.example")
	f.Add(q, q)
	f.Fuzz(func(t *testing.T, a, b []byte) { _, _ = ParseResponse(a, b, 64) })
}
