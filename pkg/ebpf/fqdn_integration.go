//go:build fqdn_integration

package ebpf

import (
	"sync"

	goelf "github.com/aws/aws-ebpf-sdk-go/pkg/elfparser"
	goebpfmaps "github.com/aws/aws-ebpf-sdk-go/pkg/maps"
)

// FQDNPrograms and this constructor exist only in explicitly tagged kernel
// qualification builds. The backend and all map/TC verification are unchanged.
type FQDNPrograms struct{ Ingress, Egress goelf.BpfData }

func NewFQDNIntegrationBackend(globalMaps map[string]goebpfmaps.BpfMap, programs map[string]FQDNPrograms) (*FQDNBackend, error) {
	c := &bpfClient{globalMaps: new(sync.Map), policyEndpointeBPFContext: new(sync.Map)}
	for name, m := range globalMaps {
		c.globalMaps.Store(name, m)
	}
	for id, p := range programs {
		c.policyEndpointeBPFContext.Store(id, BPFContext{ingressPgmInfo: p.Ingress, egressPgmInfo: p.Egress})
	}
	return NewFQDNBackend(c)
}
