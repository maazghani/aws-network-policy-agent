package fqdn_test

import (
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-network-policy-agent/pkg/fqdn"
)

func benchName(name string) []byte {
	var wire []byte
	for _, label := range strings.Split(name, ".") {
		wire = append(wire, byte(len(label)))
		wire = append(wire, label...)
	}
	return append(wire, 0)
}

func benchmarkDNSMessage(family, count int) ([]byte, []byte) {
	kind := uint16(1)
	if family == 6 {
		kind = 28
	}
	request := make([]byte, 12)
	binary.BigEndian.PutUint16(request, 1)
	binary.BigEndian.PutUint16(request[2:], 0x0100)
	binary.BigEndian.PutUint16(request[4:], 1)
	request = append(request, benchName("allowed.test")...)
	request = binary.BigEndian.AppendUint16(request, kind)
	request = binary.BigEndian.AppendUint16(request, 1)
	response := append([]byte(nil), request...)
	binary.BigEndian.PutUint16(response[2:], 0x8180)
	binary.BigEndian.PutUint16(response[6:], uint16(count))
	for i := 0; i < count; i++ {
		response = append(response, 0xc0, 0x0c)
		response = binary.BigEndian.AppendUint16(response, kind)
		response = binary.BigEndian.AppendUint16(response, 1)
		response = binary.BigEndian.AppendUint32(response, 60)
		if family == 4 {
			response = binary.BigEndian.AppendUint16(response, 4)
			response = append(response, 198, 18, byte(i>>8), byte(i))
		} else {
			response = binary.BigEndian.AppendUint16(response, 16)
			ip := make([]byte, 16)
			ip[0], ip[1] = 0xfd, 0
			binary.BigEndian.PutUint32(ip[12:], uint32(i))
			response = append(response, ip...)
		}
	}
	return request, response
}

func BenchmarkDNSParser(b *testing.B) {
	for _, family := range []int{4, 6} {
		for _, count := range []int{1, 16, 64} {
			b.Run(fmt.Sprintf("IPv%d/%d_addresses", family, count), func(b *testing.B) {
				request, response := benchmarkDNSMessage(family, count)
				if _, err := fqdn.ParseDNSAnswer(request, response, 1_000_000_000, family); err != nil {
					b.Fatal(err)
				}
				b.SetBytes(int64(len(response)))
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if _, err := fqdn.ParseDNSAnswer(request, response, 1_000_000_000, family); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

// This isolates userspace observation accounting. It deliberately excludes
// kernel syscalls, map verification, DNS I/O and publication-writer latency.
// Never use it to claim a production DNS throughput or latency budget.
type bookkeepingBackend struct{}

func (bookkeepingBackend) WithFence(ctx context.Context, fn func(context.Context) error) error {
	return fn(ctx)
}
func (bookkeepingBackend) Bind(context.Context, fqdn.Endpoint) error { return nil }
func (bookkeepingBackend) Replace(context.Context, fqdn.Endpoint, uint64, []fqdn.Grant) error {
	return nil
}
func (bookkeepingBackend) Check(context.Context, fqdn.Endpoint, uint64, []fqdn.Grant) error {
	return nil
}
func (bookkeepingBackend) Delete(context.Context, fqdn.Endpoint) error { return nil }

type bookkeepingClock struct{}

func (bookkeepingClock) Now() (uint64, error) { return 1_000_000_000, nil }

func BenchmarkObservationBookkeeping(b *testing.B) {
	for _, count := range []int{1, 16, 64} {
		b.Run(fmt.Sprintf("%d_addresses_no_kernel_IO", count), func(b *testing.B) {
			engine, err := fqdn.NewEngine(fqdn.Config{Limits: fqdn.Limits{MaxEndpoints: 1, MaxRulesPerEndpoint: 1, MaxObservationsPerEndpoint: 100, MaxAddressesPerEndpoint: 100, MaxGrantsPerAddress: 24, MaxGrantsPerEndpoint: 100, MaxTotalObservations: 100, MaxTotalGrants: 100}, PublicationTimeout: time.Second, Clock: bookkeepingClock{}}, bookkeepingBackend{})
			if err != nil {
				b.Fatal(err)
			}
			ep, err := engine.Enroll(context.Background(), fqdn.Endpoint{UID: "benchmark", Name: "client", Namespace: "benchmark", PodIdentifier: "benchmark", IfIndex: 1, IP: netip.MustParseAddr("192.0.2.1")}, fqdn.Snapshot{Rules: []fqdn.Rule{{Owner: "benchmark", Name: "allowed.test", Ports: []fqdn.PortRange{{Protocol: 6, StartPort: 443, EndPort: 443}}}}})
			if err != nil {
				b.Fatal(err)
			}
			observations := make([]fqdn.Observation, count)
			for i := range observations {
				observations[i] = fqdn.Observation{Name: "allowed.test", Address: netip.AddrFrom4([4]byte{198, 18, 0, byte(i)}), ExpiresAt: 61_000_000_000}
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := engine.Publish(context.Background(), ep, "allowed.test", observations, func(context.Context, []uint32) error { return nil }); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
