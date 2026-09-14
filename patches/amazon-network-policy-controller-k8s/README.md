# FQDN named ports controller fix

Apply `0001-reject-unresolved-fqdn-named-ports.patch` to
`aws/amazon-network-policy-controller-k8s` at
`5d464ed62d9ce8f18b74292f0e319fa91e1c6201`.

```sh
git apply 0001-reject-unresolved-fqdn-named-ports.patch
go test ./pkg/resolvers
```

An FQDN destination has no Kubernetes pod on which the controller can resolve
a named port. The current resolver erases string ports, which silently permits
all ports. This patch rejects each unsupported named-port alternative and logs
the rejection. If no usable alternatives remain, it emits no allow endpoint.
It preserves numeric ports, ranges, explicit protocol-only alternatives and an
omitted port list. ANP policy types still reach `PolicyEndpoint.PodIsolation`,
including when every domain alternative is rejected.

The patch includes regression coverage for named-only, mixed named/numeric,
range and omitted ports, plus an egress-isolation regression. The nodeagent PE
schema contains numeric ports only and cannot distinguish a legitimate omitted
port from a string port erased upstream. This controller fix must therefore be
included in the controller version qualified for feature enablement.

This directory is an applicable companion change, not a claim that the managed
EKS controller has incorporated or deployed it.
