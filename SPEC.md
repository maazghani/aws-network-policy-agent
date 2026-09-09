# Native FQDN Egress Enforcement for Standard EKS

**Status:** Proposed implementation contract. Source baseline: 2026-09-09. Runtime validation and benchmarks remain required.

## Goal and boundary

Extend `aws-network-policy-agent`, inside the existing `aws-eks-nodeagent` container, to enforce `ApplicationNetworkPolicy.domainNames` on Standard EKS. The first useful outcome is a pod resolving an allowed name through its configured resolver and connecting only after its own datapath admits the answer. Sibling pods must not inherit that permission.

Keep the existing ANP → `PolicyEndpoint` → nodeagent architecture. No new CRD, DaemonSet, CNI dependency, CoreDNS modification, mandatory NodeLocal DNSCache, systemd service, or `ipamd` responsibility is needed.

### Verified starting point

The controller's `resolveFQDNRules` emits domain strings and ports through ordinary `PolicyEndpoint` objects. The agent's `deriveIngressAndEgressFirewallRules` skips domain-only entries because its current compiler requires CIDRs. Static programs/maps can be shared among replicas. Current BPF conntrack has no DNS lifetime or fresh-SYN check; its success path cannot establish FQDN correctness. [A][B][C][D]

AWS currently restricts native DNS rules to Auto Mode nodes. Roadmap discussion describes delivery sequencing, while public code establishes a viable nodeagent extension boundary; neither establishes a Standard release commitment. [E][F]

## Existing interfaces to change

Paths below belong to the agent unless otherwise identified. Preserve existing naming and package patterns; exact new signatures are implementation choices.

| Boundary | Required change | Decisive validation |
|---|---|---|
| `controllers/policyendpoints_controller.go`: `deriveIngressAndEgressFirewallRules` | Compile domain rules alongside static rules; retain owner, ports, and concrete selected-pod associations. Consume relevant cluster-policy changes too. | Multiple policies compose; removing one contributor preserves another. |
| `pkg/ebpf/bpf_client.go`: `BpfClient`, `UpdateEbpfMaps` | Add synchronous FQDN admission/revocation operations with checked errors and active program/map binding. Propagate existing `BulkRefresh` deletion failures; fence shared static-map updates. | Missing attachment, failed write/deletion, and duplicate answers cannot produce premature success. |
| `AttacheBPFProbes`, `DeleteBPFProbes`, `ReAttachEbpfProbes`; existing CNI RPC lifecycle | Bind individual pod/interface lifetimes; invalidate pending work and dynamic state independently of shared static programs. Preserve restrictive enforcement during replacement. | IP/ifindex reuse, lost deletion, restart, and upgrade cannot inherit grants. |
| `pkg/ebpf/c/tc.v4egress.bpf.c`, IPv6 counterpart, ingress programs | Classify selected DNS; admit proxy replies; evaluate dynamic grants at the namespace tier; distinguish FQDN flow state. | Both families, ingress isolation, tier precedence, expired same-tuple SYN, UDP cutoff. |
| `pkg/ebpf/conntrack/conntrack_client.go` and shared conntrack definitions | Preserve valid established TCP without retaining address-wide or reused-tuple authorization. Coordinate cleanup with datapath provenance. | DNS expiry preserves established TCP but denies new connections; revocation affects only dependent traffic. |
| `main.go`, existing configuration/health/metrics/CLI | Own proxy lifecycle, bounded work, diagnostics, and required host plumbing. Reuse existing libraries where suitable. | Proxy outage is bounded and cannot silently bypass selected DNS. |
| Controller: `pkg/resolvers/applicationnetworkpolicy_resolver.go` | Fix named-port loss before production enablement: string ports currently become unspecified ports. Reject unsupported names without removing isolation. | Named ports cannot widen access; numeric/range/omitted ports retain semantics. |
| VPC CNI chart/add-on | Package the image and an initially disabled feature flag with qualified settings. | Existing `aws-node` lifecycle installs, restarts, and rolls back predictably. |

## Required policy contract

Dynamic grants are endpoint-specific namespace-tier allows. Preserve Admin CNP → namespace NP/ANP → Baseline CNP → existing default behavior. Admin terminal decisions remain authoritative; union static and dynamic namespace permissions before applying namespace isolation. Preserve rule ports and overlapping permissions. CNP domain enforcement remains outside this increment. [D]

Separate resolver transport authorization from destination authorization: an FQDN rule does not implicitly allow contacting arbitrary DNS servers. Check the original resolver's effective TCP/UDP permission before proxying, including before a TCP handshake response.

**Proposed DNS contract:** forward transport-permitted queries; learn grants only from matching names. Nonmatching answers are informational and create no grant. This preserves independently permitted service discovery but does not prevent DNS exfiltration.

AWS describes query-name filtering without fully specifying its composition with static allowances and Admin decisions. Maintainer agreement on that behavior blocks a compatibility claim, not a local prototype. Keep this decision inside the proxy; do not introduce customer-selectable semantics to conceal the uncertainty. [E]

Guarantees begin after verified local enrollment and apply to policy changes observed by nodeagent. Independently published PE chunks lack a complete-policy snapshot marker. Strict mode and informer synchronization alone cannot promise complete policy enforcement from every pod's first packet. [A][G][N]

## DNS steering: prove the mechanism first

Use existing host-veth TC ingress for pod egress classification, before conntrack and local-node shortcuts. Intercept selected UDP/TCP destination port 53; leave unselected pods on their existing path.

Prefer TC socket assignment with transparent sockets because it uses the existing hook. Compare TC marks plus TPROXY if qualification exposes a concrete advantage. Neither mechanism is accepted until a small network-namespace prototype proves:

- Trusted originating interface, assigned source address, and current pod UID/lifetime survive interception; direct listener access cannot impersonate a redirected exchange.
- Original resolver address/port and UDP/TCP response tuples are preserved, including TCP fallback and persistent connections.
- CoreDNS Service translation, NodeLocal DNSCache, Route 53 Resolver, custom resolvers, and proxy replies under ingress isolation work.
- Scoped marks, routing, NAT/NOTRACK handling, host filtering, and backend coexistence remain correct during partial setup and process failure.

Use only the required host rules, capabilities, and modules proven by that test. Reconcile exclusively owned rules idempotently. Missing plumbing must block selected DNS rather than forward it directly; readiness alone is insufficient. Linux documents both socket-assignment tests and TPROXY prerequisites. [H][I]

Forward to the workload's original resolver. Host-sourced upstream sockets are the initial candidate; source-based resolver ACLs/views and security-group behavior require qualification. Do not claim preserved upstream pod identity.

Custom `dnsConfig` works for visible port-53 traffic. Loopback-only resolution, encrypted DNS, and nonstandard ports cannot populate grants. Validate IPv4 options, IPv6 extension headers, and transport lengths; unclassifiable fragments must not bypass interception. Document any fragment restriction and test PMTU/essential IPv6 traffic.

## State and admission

Keep immutable effective policy snapshots and bounded DNS observations per pod lifetime. Retain rule ownership, normalized name, address, L4 constraints, and expiry sufficiently to recompute overlapping contributions. A recreated pod receives a new identity even if its IP/interface is reused.

Use endpoint-scoped dynamic BPF entries separate from shared static LPM maps. The exact map layout, generation mechanism, and locking strategy must satisfy the contracts below; no general transaction framework is required.

Match the ANP grammar: exact names or leading `*.` for descendant labels, excluding the apex; normalize ASCII case and the root dot. Validate request/response correlation. Learn only A/AAAA records reachable from the allowed question through a valid, bounded CNAME chain. Split CNAME answers may retain bounded endpoint-local dependencies. Unrelated additional records create no grants. Negative/non-address answers create no grants. [J]

Expire each contribution at the earliest supporting CNAME/address deadline using a consistent, suspend-aware monotonic clock. Rotation adds new observations without renewing absent addresses. Do not impose a positive minimum TTL. BPF must reject expired grants even when userspace GC stops. Returned TTLs cannot exceed remaining authorized lifetime.

Bound compiled rules, observations, addresses, per-address L4 entries, pending requests/bytes, TCP sockets, and total userspace/kernel memory. Measure limits before choosing defaults. Reclaim expired state first; reject new learning when capacity is exhausted. A rejected policy update must not preserve permissions it removed: invalidate affected dynamic authority while retaining independently provable permissions.

### Positive-response barrier

Every matching terminal address returned in the enforced family must have effective permission before release. A wholly denied address fails the matched answer; do not admit a subset and return the whole address set.

1. Validate the exchange and current endpoint/policy; derive permitted addresses and L4 constraints; reserve capacity.
2. Serialize conflicting endpoint updates. Confirm live program attachment and synchronously update its active map, checking every operation.
3. Confirm effective admission under all policy tiers, remaining TTL, and unchanged endpoint/policy identity. Coordinate shared static-map changes so they cannot bypass this check.
4. Release the response under the same bounded, cancellable publication fence.

A failed check, expired-only grant, or programming timeout yields no positive matched answer: return SERVFAIL or close/drop. Independent current static permission may satisfy admission. No successful map insertion alone proves effective reachability.

The multi-address update need not become packet-visible atomically. Partial additions may remain only while independently valid and bounded by expiry; revoked additions must become ineffective. Never justify partial visibility by assuming the workload does not already know an address.

Cilium provides the synchronization and duplicate-response lessons, but its inspected timeout path releases responses. This design deliberately requires stricter failure behavior. [K]

## Connections, revocation, and recovery

Keep DNS observations, BPF grants, BPF conntrack, and Linux conntrack distinct. Linux conntrack provides transport/NAT state and cleanup hints, never FQDN authority. At enrollment, invalidate legacy conntrack entries from previous/default-allow state wherever they would bypass current restrictions.

- **TCP:** tag DNS-derived flow authority. A SYN without ACK requires fresh admission even for an existing tuple. Only verified established flows may outlive DNS expiry; bound handshake/closing/idle state. Validate provenance on forward and reverse paths.
- **UDP/QUIC and other transports:** require a live grant for outbound traffic; a reused tuple cannot extend authorization indefinitely. Bounded reply handling may preserve responses to previously admitted packets.
- **Observed policy revocation:** invalidate removed permissions and dependent flows. A new Admin deny revokes affected established FQDN flows in both directions even if their ANP rule survives. Otherwise surviving rules or independent static permission remain usable. Policy-capacity failures must not defeat revocation. Preserve existing static-origin behavior.
- **Endpoint deletion:** invalidate lifetime authority before cleanup and cancel outstanding exchanges. Physical deletion can retry after stale entries become ineffective.
- **Restart:** retain absolute deadlines. Recover only state whose endpoint and current authorizing policy can be proven; otherwise discard grants and relearn. Established TCP may survive only with separately verified provenance. No persistent DNS database is required.

If even restrictive kernel updates fail, report unsuccessful revocation; do not promise immediate enforcement from an unmodifiable datapath. Previously committed grants still expire.

## Operations and compatibility

Use existing health, metrics, logging, and CLI surfaces. Expose response-hold/programming latency, failure stage, capacity, expiry, revocation delay, recovery, and proxy readiness. Detailed endpoint/name/grant diagnostics are opt-in; avoid unbounded metric labels. Resolver outages or quota pressure must not create restart loops.

Qualify Standard managed/self-managed/Karpenter EC2 Linux nodes, supported AL2023/Bottlerocket/accelerated images, CPU architectures, IPv4 and IPv6 cluster modes, and existing networking variants. Do not add Windows/Fargate/hostNetwork/Multus or dual-stack support claims. Existing privileges may suffice; publish actual capability/module and version requirements after testing. Existing pod/PE/CPE watches suffice; no new DNS-data Kubernetes writes are required. [G][L]

Feature-gate rollout on canary nodes. Do not place FQDN-dependent workloads on unsupported nodes. Upgrades must avoid transient default-allow. Roll back through drained/replacement nodes or equivalent enforcement before removing steering.

FQDN policy authorizes IP/port access, not HTTP Host, TLS identity, or CDN tenants. Learned IPs permit direct access within their grant. Trusted resolver policy and higher-priority sensitive-CIDR denies remain necessary where required. DoH/DoT, existing node exceptions, privileged access, and independent broad static allowances remain security boundaries.

## Validation and delivery

Encode failing validations before production implementation. Use real TC/BPF integration for datapath claims; mocks cannot prove response ordering.

| Increment | Required evidence |
|---|---|
| 1. Feasibility and prerequisites | Named-port regression; UDP/TCP steering and ingress replies across both families; denied resolver, identity spoofing, and failure plumbing tests. |
| 2. Grants and flow lifecycle | Synthetic observations prove policy composition, cross-pod isolation, CNAME/TTL/port behavior, reused SYN/UDP expiry, revocation, bounds, and restart. |
| 3. Complete proxy path | Delayed/failed map writes, duplicate answers, deletion at every response boundary, shared-policy changes, IP/ifindex reuse, and parser fuzzing. Assert zero premature positive responses. |
| 4. Packaging and workload acceptance | Upgrade/rollback, OS/resolver matrix, measured load/recovery, and Agent Sandbox on fresh Standard nodes without Cilium enforcement. |

For Agent Sandbox, preserve ordinary isolation and metadata denies alongside FQDN behavior; Hubble parity is outside scope. Exercise PyPI, STS/Bedrock, and sandbox execution. Use controlled allowed/denied names and reachable targets: NXDOMAIN or unrelated TLS failure cannot count as successful blocking. [M]

Measure baseline-relative DNS QPS/tail latency, response-hold time, CPU/RSS, map memory, packet cost, churn, and recovery. Acceptance requires zero cross-pod grants, zero expired new-flow admissions, bounded resources, and preserved policy order. Production performance budgets follow measurements.

Release decisions remaining: AWS query-filter composition, managed controller/schema/add-on versions, qualified host-source resolver behavior and kernels, resource defaults, and mixed-node capability enforcement. These do not block the local increments above.

## Source baseline

References pin inspected code; documentation and roadmap links describe published context, not implementation guarantees.

[A]: https://github.com/aws/aws-network-policy-agent/blob/69fe6a5ba69abd4c677f8bcfe1779c632eec176a/controllers/policyendpoints_controller.go
[B]: https://github.com/aws/amazon-network-policy-controller-k8s/blob/5d464ed62d9ce8f18b74292f0e319fa91e1c6201/pkg/resolvers/applicationnetworkpolicy_resolver.go
[C]: https://github.com/aws/aws-network-policy-agent/blob/69fe6a5ba69abd4c677f8bcfe1779c632eec176a/pkg/ebpf/bpf_client.go
[D]: https://github.com/aws/aws-network-policy-agent/blob/69fe6a5ba69abd4c677f8bcfe1779c632eec176a/pkg/ebpf/c/tc.v4egress.bpf.c
[E]: https://docs.aws.amazon.com/eks/latest/userguide/auto-net-pol.html
[F]: https://github.com/aws/containers-roadmap/issues/2801#issuecomment-5593138747
[G]: https://docs.aws.amazon.com/eks/latest/userguide/cni-network-policy.html
[H]: https://github.com/torvalds/linux/blob/v5.10/tools/testing/selftests/bpf/prog_tests/sk_assign.c
[I]: https://docs.kernel.org/networking/tproxy.html
[J]: https://github.com/aws/amazon-network-policy-controller-k8s/blob/5d464ed62d9ce8f18b74292f0e319fa91e1c6201/api/v1alpha1/applicationnetworkpolicy_types.go
[K]: https://github.com/cilium/cilium/blob/c3f93518bffe7d9cd1e61e5785d2296eeaacaa59/pkg/fqdn/messagehandler/message_handler.go
[L]: https://github.com/aws/amazon-vpc-cni-k8s/blob/c038e4258f01dbe63104d3f2935063877dd8a31d/charts/aws-vpc-cni/templates/daemonset.yaml
[M]: https://github.com/awslabs/ai-on-eks/tree/baaa71af72bc25efba14e1920754cf592c11d47c/blueprints/agent-sandbox
[N]: https://github.com/aws/amazon-network-policy-controller-k8s/blob/5d464ed62d9ce8f18b74292f0e319fa91e1c6201/pkg/policyendpoints/manager.go
