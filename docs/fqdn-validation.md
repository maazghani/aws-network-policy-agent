# FQDN qualification and acceptance

This is an experimental implementation. A build or unit-test pass is not an EKS
compatibility result. Keep the feature disabled outside explicitly qualified
canary nodes. Resource settings are qualification inputs, not measured production
defaults. The implementation and the uploaded contract are distinct from evidence
that a particular kernel, image, resolver and networking configuration work.

## Reproducible kernel test

On a disposable Linux host with Go matching `go.mod`, clang, libbpf headers,
iproute2, iptables/ip6tables, bpftool, Python 3 and util-linux:

```sh
sudo env "PATH=$PATH" ./scripts/fqdn-kernel-tests.sh
```

The script requires actual `CAP_SYS_ADMIN`, `CAP_NET_ADMIN` and `CAP_NET_RAW`, BPF
loading and transparent sockets. Modern kernels additionally use `CAP_BPF`/`CAP_PERFMON` for
unprivileged capability separation; the disposable test runs with root's full
capabilities. UID 0 with an empty capability set is insufficient. Prerequisite
failure exits unsuccessfully: the suite never converts missing privileges into a
skipped or passing datapath claim.

Each family runs inside private mount and network namespaces. A private bpffs
keeps all maps and pins away from any existing nodeagent. The suite compiles the
actual production C objects, uses the AWS ELF loader and TC attachment APIs, and
creates a pod veth and a reachable resolver behind a second veth. It uses real
`BPF_PROG_TEST_RUN` for exact packet/tuple boundaries and real sockets for steering.
It does not need Kubernetes, Cilium or AWS resources.

The PR workflow `.github/workflows/fqdn-validation.yaml` runs this command and
retains kernel, compiler, feature-probe and test output. A green Ubuntu runner
qualifies that runner only. Record the workflow URL and exact commit with a result.

| Test surface | Executable assertions |
| --- | --- |
| Endpoint authority | No grant denies; source spoof rejected; another lifetime/interface cannot use the first endpoint's grant |
| L4 and lifetime | UDP range edges; transport mismatch; expired UDP on an existing tuple; expired fresh SYN on a reused tuple; generation/lifetime replacement |
| Policy order | Admin deny defeats namespace dynamic allow; Admin pass preserves namespace evaluation |
| Steering | UDP and persistent TCP, both families; original resolver tuples; trusted ifindex/IP/lifetime; replies under ingress isolation |
| Resolver permission | Reachable direct resolver baseline; missing setup denies; transport-denied resolver cannot complete TCP handshake |
| Service/NAT | PREROUTING/OUTPUT DNAT to a non-local resolver; same-source-port UDP with pre-existing NAT state; original Service VIP maintained |
| Plumbing failure | Listener crash with stale readiness fails closed; local-route deletion cannot forward selected DNS directly |
| Full DNS path | Actual proxy + engine + backend + TC; duplicate replies; UDP truncation/TCP retry; delayed/failed writes; attachment loss; endpoint deletion during publication; zero premature positive answers |

The packet tests do not use Linux conntrack as FQDN authority. Deliberate fault
injection wraps the real backend to delay or reject an operation; every successful
operation and active-program/map check still uses the production implementation.
Transport echo measurements report a baseline-relative smoke result. Forty samples
do not establish a production p99 budget.

Local userspace microbenchmarks are reproducible without kernel privileges:

```sh
go test ./test/fqdn -run '^$' -bench . -benchtime=200ms -benchmem
```

An initial Linux/amd64 run on an AMD EPYC 9V74 with Go 1.26.6 produced these
results. Other build work was active on the host; these short runs describe the
parser and bookkeeping costs only, and exclude socket I/O, BPF programming,
attachment verification and response hold time.

| Operation | Addresses | ns/op | Bytes allocated/op | Allocations/op |
| --- | ---: | ---: | ---: | ---: |
| Parse IPv4 answer | 1 | 1,407 | 1,156 | 8 |
| Parse IPv4 answer | 16 | 5,611 | 7,840 | 31 |
| Parse IPv4 answer | 64 | 21,055 | 53,600 | 85 |
| Parse IPv6 answer | 1 | 1,233 | 1,168 | 8 |
| Parse IPv6 answer | 16 | 5,683 | 8,032 | 31 |
| Parse IPv6 answer | 64 | 25,180 | 54,368 | 85 |
| Observation bookkeeping, no kernel I/O | 1 | 4,496 | 2,376 | 28 |
| Observation bookkeeping, no kernel I/O | 16 | 23,150 | 24,088 | 129 |
| Observation bookkeeping, no kernel I/O | 64 | 97,451 | 103,888 | 387 |

The five FQDN maps' declared maximum key/value payload totals 34,390,036 bytes
(about 32.8 MiB). This is arithmetic from `fqdn.h`, **not measured map memory**:
it excludes hash buckets, allocation rounding, bookkeeping, existing static maps,
legacy conntrack and event buffers. Kernel allocation/occupancy and process RSS
must be measured separately during the load/recovery matrix.

## SPEC traceability and remaining evidence

| Contract area | Local artifact | Evidence still required before release |
| --- | --- | --- |
| Controller compilation and named ports | Controller regression tests and companion controller patch | Deploy patched/schema-compatible controller; verify numeric, range, omitted and rejected named-port behavior on EKS |
| Endpoint-specific grants and policy tiers | Real TC packet tests plus backend/state tests | Full overlapping-policy churn, established TCP and both-direction Admin revocation under concurrent real traffic |
| DNS steering feasibility | Isolated veth, transparent sockets, both families and Service DNAT tests | Successful privileged job output; NodeLocal, Route 53, resolver ACL/view and host-firewall matrix |
| Positive-response barrier | Production proxy/engine/backend kernel harness with injected delay, write failure, detach and deletion | Sustained concurrent publication/static-policy churn, deletion at every boundary and load saturation |
| Parsing, TTL and bounded state | Parser/state tests, fuzz seeds and microbenchmarks | Extended fuzz runs; GC-stopped kernel expiry/load; capacity defaults measured on candidate nodes |
| Lifecycle and recovery | Generation/lifetime packet tests and agent/backend lifecycle tests | Lost deletion, real IP/ifindex reuse, process restart and node upgrade/rollback workload runs |
| Packaging | Feature-gated image/chart integration and controlled acceptance script | Managed add-on/controller versions, mixed-node scheduling, replacement/rollback qualification |
| Agent Sandbox | Reachable controls and the workload sequence below | Actual PyPI, STS, authorized Bedrock and sandbox execution results |
| Performance | Userspace microbenchmarks and transport smoke measurements | Baseline-relative DNS QPS/tails, hold time, CPU/RSS, map allocation, packet cost, churn and recovery budgets |

These are evidence boundaries. A local unit result or an unexecuted test does not
close a row. Neither AL2023, Bottlerocket, accelerated images nor arm64 is claimed
qualified by the local amd64 benchmarks.

## Fresh Standard EKS workload acceptance

Use a fresh test cluster with the patched controller/schema and agent image, the
feature enabled with explicit limits, and no Cilium enforcement. Verify each
candidate node first, then label only those nodes:

```sh
kubectl label node NODE fqdn.nodeagent.k8s.aws/qualified=true
FQDN_ACCEPTANCE_CONTEXT="$(kubectl config current-context)" \
  ./scripts/fqdn-workload-acceptance.sh
```

The context variable makes the target concrete. The script creates the dedicated
`fqdn-acceptance` namespace, retains it for inspection, and refuses to reuse an
existing namespace. It installs ordinary ingress/egress isolation, permits only
the clients' configured resolver IPs on TCP/UDP 53, and creates one ANP allowing a
controlled name on TCP 8080. The name's Service and a separate denied Service both
have reachable HTTP servers. An unrestricted control pod verifies both before
testing denial and rechecks the denied server afterward.

The client resolves the allowed name and connects. A sibling selected by the same
ANP attempts that IP without resolving it and must fail. A nonmatching name still
resolves under the proposed DNS contract, but its destination remains blocked.
No NXDOMAIN or TLS error is counted as network-policy enforcement. Cleanup:

```sh
kubectl delete namespace fqdn-acceptance
```

The first-packet contract still starts after verified local enrollment and observed
policy convergence. This fixture explicitly waits for isolation before resolving
the allowed name; it does not infer a complete-policy snapshot from independent
PolicyEndpoint chunks.

## Agent Sandbox extension

Run the controlled fixture before adapting it to Agent Sandbox. Preserve its
existing service isolation and higher-priority metadata/sensitive-CIDR denies.
Record the sandbox image, controller/schema and add-on versions, node AMI, kernel,
architecture, resolver mode, and policy files. Do not move FQDN-dependent workloads
to unlabeled nodes. Exercise this sequence with the intended sandbox identity:

1. Install a pinned test package from PyPI with `pip --no-cache-dir`, allowing the
   actual package-index and artifact-host names required by that package. Execute
   the installed package inside the sandbox and check the result. Keep a reachable
   unapproved package mirror as the negative control.
2. Call regional STS `GetCallerIdentity` with the sandbox's intended credentials.
   Record the expected identity; a credentials failure is not a network-policy
   result. Confirm the same endpoint is reachable from a control workload.
3. Exercise the configured Bedrock model endpoint with an explicitly authorized
   test invocation. A model/IAM/account error is not proof of network blocking.
   This harness does not issue paid model calls or create credentials.
4. Repeat the sandbox's real execution path under policy revocation, proxy restart,
   node replacement and quota pressure. Verify that existing metadata denies and
   isolation remain effective. Hubble feature parity is outside this increment.

## Required release evidence

No entries in this matrix are established by this document. Complete them with
links to raw run output; record unsupported combinations explicitly.

| Dimension | Required variants |
| --- | --- |
| Standard EC2 lifecycle | Managed node group, self-managed, Karpenter; canary replacement, upgrade, restart and drained rollback |
| OS / architecture | Supported AL2023, Bottlerocket and accelerated AMIs; amd64 and arm64 |
| IP family | IPv4-only cluster and IPv6-only cluster; no dual-stack claim |
| Resolver | CoreDNS Service, NodeLocal DNSCache, Route 53 Resolver and a reachable custom resolver |
| Networking | Actual kube-proxy backends and supported VPC CNI variants; host filtering; source-based resolver ACL/views; security groups |
| Packet handling | IPv4 options, accepted IPv6 extensions, denied fragments, PMTU and essential IPv6; fragment restrictions documented to operators |
| Recovery | Lost deletion, UID/IP/ifindex reuse, process kill, retained deadlines, policy/chunk churn, additive and restrictive upgrades |

Host-source upstream DNS is intentional: it does not preserve the pod's upstream
source identity. Resolver ACLs/views and security groups require separate results.
Windows, Fargate, hostNetwork, Multus and dual-stack remain outside the support claim.

Measure baseline and enabled runs on the same topology and workload. Retain DNS
QPS, p50/p95/p99/max, response-hold and programming latency, process CPU/RSS, kernel
map allocation/occupancy, packet cost, policy/endpoint churn and recovery time.
Include cold and warm caches, TTL-zero/short-TTL traffic, address rotation, repeated
duplicates, TCP reuse, near-capacity admission and resolver failure. Sweep bounded
concurrency until the proposed limits saturate; reclaim expired entries before new
admission and verify the limits remain bounded while userspace GC is stopped.

Acceptance requires zero cross-pod grants, zero expired new-flow admissions, zero
premature positive DNS responses, preserved tier order, and bounded resources.
Choose production resource and performance budgets only after those measurements.
Managed release versions, AWS DNS-query composition agreement and fleet scheduling
of mixed-capability nodes remain release decisions, not things a local test proves.
