# Standard EKS FQDN enforcement implementation status

The `--enable-fqdn-policy` gate is **experimental and disabled by default**.
This repository does not yet satisfy the end-to-end acceptance criteria in the
proposal and must not advertise Standard EKS FQDN enforcement as production
ready.

## Implemented and unit tested

- Per-pod effective policy compilation retains normalized domain, port, and
  PolicyEndpoint-owner contributions without writing them to shared CIDR maps.
- The bounded state engine isolates pod lifetimes, composes policy owners,
  rejects wildcard apex matches, follows bounded CNAME chains, uses the
  earliest address/CNAME TTL, expires authority independently of garbage
  collection, and restrictively republishes state on policy change/deletion.
- The response barrier checks the live attachment before and after synchronous
  programming. Failed, cancelled, capacity-rejected, expired-only, or stale
  publications do not release a positive matching answer.
- DNS parsing correlates transaction IDs and questions, bounds messages and
  records, detects compression loops, and excludes unrelated additional data.
- Proxy core checks independent resolver-transport authorization before
  forwarding. Nonmatching queries may be forwarded but cannot learn grants.
- Static map deletion errors are returned to reconciliation rather than hidden.

## Implemented but requiring privileged integration evidence

None. Pure userspace behavior is not evidence for TC steering, transparent
socket tuple preservation, or packet enforcement.

## Not yet implemented

- TC socket assignment/TPROXY steering and exclusively owned host plumbing.
- A kernel dynamic-grant map, namespace-tier lookup, IPv4/IPv6 packet parsing,
  DNS reply admission under ingress isolation, and fail-closed steering.
- FQDN conntrack provenance, fresh-SYN revalidation, UDP expiry, and dependent
  forward/reverse flow revocation.
- UDP/TCP transparent listeners, TCP fallback/persistence, upstream forwarding,
  TTL rewriting, split-response CNAME dependency storage, and proxy lifecycle
  wiring in `main.go`.
- Reconciliation wiring between PolicyEndpoint snapshots, concrete pod
  UID/IP/ifindex lifetimes, cluster-policy changes, the state engine, and kernel
  programming.
- Bounded metrics/diagnostics and recovery of only provable state.

## Repository-external blockers

- The named-port conversion bug is in
  `amazon-network-policy-controller-k8s`, not this repository. Production enablement
  requires a coordinated controller change and compatible release.
- VPC CNI chart/add-on packaging is in `amazon-vpc-cni-k8s`, not this
  repository. Its disabled-by-default setting must be delivered there.
- Kernel/OS/resolver qualification and Agent Sandbox acceptance require fresh
  privileged Standard EKS nodes. They cannot be established by unit tests or an
  unprivileged build container.
- AWS query-filter compatibility, managed version selection, and production
  resource defaults remain release decisions. They do not weaken the local
  fail-closed contract.
