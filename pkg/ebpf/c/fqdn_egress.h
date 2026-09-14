#ifndef AWS_NPA_FQDN_EGRESS_H
#define AWS_NPA_FQDN_EGRESS_H
#include "fqdn_packet.h"

static __always_inline void fqdn_egress_keys(const struct fqdn_tuple *tuple, __u32 ifindex,
        struct keystruct *trie, struct conntrack_key *flow)
{
#ifdef FQDN_IPV6
    trie->prefix_len = 128;
    __builtin_memcpy(trie->ip, tuple->dst, 16);
    __builtin_memcpy(&flow->saddr, tuple->src, 16);
    __builtin_memcpy(&flow->daddr, tuple->dst, 16);
    __builtin_memcpy(&flow->owner_addr, tuple->src, 16);
#else
    trie->prefix_len = 32;
    __builtin_memcpy(trie->ip, tuple->dst, 4);
    __builtin_memcpy(&flow->src_ip, tuple->src, 4);
    __builtin_memcpy(&flow->dest_ip, tuple->dst, 4);
    __builtin_memcpy(&flow->owner_ip, tuple->src, 4);
#endif
    flow->src_port = tuple->sport;
    flow->dest_port = tuple->dport;
    flow->protocol = tuple->protocol;
    flow->ifindex = ifindex;
}

/* Evaluate the original resolver without DNS-derived permissions and without
 * creating conntrack. This must run before socket assignment, including SYN.
 */
static __noinline int fqdn_static_action(struct keystruct *trie, struct conntrack_key *flow,
        __u8 state, int *admin_action, __u8 *tier)
{
    __u32 priority, baseline_priority;
    __u8 baseline;
    int admin = evaluateClusterPolicyByLookUp(*trie, *flow, &priority, &baseline, &baseline_priority);
    *admin_action = priority <= ADMIN_TIER_PRIORITY_LIMIT ? admin : ACTION_PASS;
    if (*admin_action == ACTION_ALLOW || *admin_action == ACTION_DENY) {
        *tier = ADMIN_TIER;
        return *admin_action;
    }
    int ns = evaluateNamespacePolicyByLookUp(*trie, *flow, state);
    if (ns != ACTION_PASS) {
        *tier = NETWORK_POLICY_TIER;
        return ns;
    }
    if (baseline != ACTION_PASS) {
        *tier = BASELINE_TIER;
        return baseline;
    }
    *tier = DEFAULT_TIER;
    return state == DEFAULT_ALLOW ? ACTION_ALLOW : ACTION_DENY;
}

/* The lookup changes only the socket, never the packet's resolver tuple. Owned
 * policy routing delivers the marked packet locally. Missing listener, route
 * readiness, metadata capacity or sk_assign support always drops selected DNS.
 */
static __always_inline void fqdn_dns_socket_tuple(struct bpf_sock_tuple *tuple,
        struct fqdn_packet *packet)
{
#ifdef FQDN_IPV6
    __builtin_memcpy(tuple->ipv6.saddr, packet->tuple.src, 16);
    __builtin_memcpy(tuple->ipv6.daddr, packet->tuple.dst, 16);
    tuple->ipv6.sport = bpf_htons(packet->tuple.sport);
    tuple->ipv6.dport = bpf_htons(packet->tuple.dport);
#else
    __builtin_memcpy(&tuple->ipv4.saddr, packet->tuple.src, 4);
    __builtin_memcpy(&tuple->ipv4.daddr, packet->tuple.dst, 4);
    tuple->ipv4.sport = bpf_htons(packet->tuple.sport);
    tuple->ipv4.dport = bpf_htons(packet->tuple.dport);
#endif
}

static __always_inline void fqdn_dns_listener_tuple(struct bpf_sock_tuple *tuple, __u16 port)
{
#ifdef FQDN_IPV6
    __builtin_memset(tuple->ipv6.daddr, 0, 16);
    tuple->ipv6.daddr[3] = bpf_htonl(1);
    tuple->ipv6.dport = bpf_htons(port);
#else
    tuple->ipv4.daddr = bpf_htonl(0x7f000001);
    tuple->ipv4.dport = bpf_htons(port);
#endif
}

static __always_inline int fqdn_dns_prior_syn(struct __sk_buff *skb, struct fqdn_endpoint *ep,
        struct fqdn_packet *packet, __u64 now)
{
    struct fqdn_dns_value *prior = bpf_map_lookup_elem(&fqdn_dns, &packet->tuple);
    return prior && prior->lifetime == ep->lifetime && prior->generation == ep->generation &&
        prior->ifindex == skb->ifindex && prior->deadline > now;
}

/* Keep this inlined separately into TCP and UDP. skc_lookup_tcp yields a
 * sock_common (including request sockets), whereas sk_lookup_udp yields a full
 * socket; merging their verifier pointer types before sk_assign is invalid.
 */
static __always_inline int fqdn_commit_dns_socket(struct __sk_buff *skb, struct fqdn_endpoint *ep,
        struct fqdn_packet *packet, __u64 now, struct bpf_sock *socket, __u32 mark)
{
    struct fqdn_dns_value identity = {.lifetime = ep->lifetime, .generation = ep->generation,
        .deadline = now + FQDN_DNS_TIMEOUT, .ifindex = skb->ifindex};
    if (!fqdn_endpoint_current(skb->ifindex, ep) ||
        bpf_map_update_elem(&fqdn_dns, &packet->tuple, &identity, 0)) {
        bpf_sk_release(socket);
        return BPF_DROP;
    }
    int result = bpf_sk_assign(skb, socket, 0);
    bpf_sk_release(socket);
    if (result || !fqdn_endpoint_current(skb->ifindex, ep))
        return BPF_DROP;
    skb->mark |= mark;
    return BPF_OK;
}

static __noinline int fqdn_assign_dns_tcp(struct __sk_buff *skb, struct fqdn_endpoint *ep,
        struct fqdn_packet *packet, __u64 now)
{
    __u32 zero = 0;
    struct fqdn_proxy_config *config = bpf_map_lookup_elem(&fqdn_proxy, &zero);
    if (!config || !config->ready || !config->port || config->port > 65535 || !config->mark || !config->reply_mark)
        return BPF_DROP;
    __u32 mark = config->mark, reply_mark = config->reply_mark;
    __u16 port = config->port;
    struct bpf_sock_tuple tuple = {};
#ifdef FQDN_IPV6
    const __u32 size = sizeof(tuple.ipv6);
#else
    const __u32 size = sizeof(tuple.ipv4);
#endif
    fqdn_dns_socket_tuple(&tuple, packet);
    /* sk_lookup_tcp converts TCP_NEW_SYN_RECV to its listener. Assigning that
     * listener to the third ACK skips tcp_check_req and resets the connection.
     * Linux's test_sk_assign.c uses skc_lookup_tcp to retain the request socket
     * and proves that listener and original destination ports can differ.
     */
    struct bpf_sock *socket = bpf_skc_lookup_tcp(skb, &tuple, size, ((__u64)-1), 0);
    if (socket) {
        if (socket->state == 10 /* TCP_LISTEN */) {
            bpf_sk_release(socket);
            socket = 0;
        } else {
            struct bpf_sock *full = bpf_sk_fullsock(socket);
            if (full) {
                /* Never adopt pre-enrollment NodeLocal/other host sockets. */
                if ((full->mark & reply_mark) != reply_mark) {
                    bpf_sk_release(socket);
                    return BPF_DROP;
                }
            } else if (!fqdn_dns_prior_syn(skb, ep, packet, now)) {
                /* Request/TIME_WAIT sockets lack sk_mark. Only a SYN already
                 * assigned by TC in this lifetime/generation proves ownership.
                 */
                bpf_sk_release(socket);
                return BPF_DROP;
            }
        }
    }
    if (!socket) {
        if ((!packet->syn || packet->ack) && !fqdn_dns_prior_syn(skb, ep, packet, now))
            return BPF_DROP;
        fqdn_dns_listener_tuple(&tuple, port);
        socket = bpf_skc_lookup_tcp(skb, &tuple, size, ((__u64)-1), 0);
        if (!socket)
            return BPF_DROP;
        struct bpf_sock *full = bpf_sk_fullsock(socket);
        if (!full || full->state != 10 || (full->mark & reply_mark) != reply_mark) {
            bpf_sk_release(socket);
            return BPF_DROP;
        }
    }
    return fqdn_commit_dns_socket(skb, ep, packet, now, socket, mark);
}

static __noinline int fqdn_assign_dns_udp(struct __sk_buff *skb, struct fqdn_endpoint *ep,
        struct fqdn_packet *packet, __u64 now)
{
    __u32 zero = 0;
    struct fqdn_proxy_config *config = bpf_map_lookup_elem(&fqdn_proxy, &zero);
    if (!config || !config->ready || !config->port || config->port > 65535 || !config->mark || !config->reply_mark)
        return BPF_DROP;
    __u32 mark = config->mark, reply_mark = config->reply_mark;
    __u16 port = config->port;
    struct bpf_sock_tuple tuple = {};
#ifdef FQDN_IPV6
    const __u32 size = sizeof(tuple.ipv6);
#else
    const __u32 size = sizeof(tuple.ipv4);
#endif
    fqdn_dns_socket_tuple(&tuple, packet);
    fqdn_dns_listener_tuple(&tuple, port);
    struct bpf_sock *socket = bpf_sk_lookup_udp(skb, &tuple, size, ((__u64)-1), 0);
    if (!socket)
        return BPF_DROP;
    if ((socket->mark & reply_mark) != reply_mark) {
        bpf_sk_release(socket);
        return BPF_DROP;
    }
    return fqdn_commit_dns_socket(skb, ep, packet, now, socket, mark);
}

static __always_inline int fqdn_assign_dns(struct __sk_buff *skb, struct fqdn_endpoint *ep,
        struct fqdn_packet *packet, __u64 now)
{
    if (packet->tuple.protocol == IPPROTO_TCP)
        return fqdn_assign_dns_tcp(skb, ep, packet, now);
    return fqdn_assign_dns_udp(skb, ep, packet, now);
}

static __noinline int fqdn_static_cached(struct conntrack_key *key, __u8 state, struct fqdn_tuple *tuple)
{
    struct conntrack_value *value = bpf_map_lookup_elem(&aws_conntrack_map, key);
    if (value && value->val == state) {
        value->last_seen = bpf_ktime_get_ns();
        return 1;
    }
    struct conntrack_key reverse = *key;
#ifdef FQDN_IPV6
    __builtin_memcpy(&reverse.saddr, tuple->dst, 16);
    __builtin_memcpy(&reverse.daddr, tuple->src, 16);
#else
    __builtin_memcpy(&reverse.src_ip, tuple->dst, 4);
    __builtin_memcpy(&reverse.dest_ip, tuple->src, 4);
#endif
    reverse.src_port = tuple->dport;
    reverse.dest_port = tuple->sport;
    value = bpf_map_lookup_elem(&aws_conntrack_map, &reverse);
    if (value) {
        value->last_seen = bpf_ktime_get_ns();
        return 1;
    }
    return 0;
}

struct fqdn_egress_policy {
    int action;
    int admin;
    __u8 state;
    __u8 tier;
    __u8 cached;
};

static __noinline int fqdn_read_egress_policy(struct __sk_buff *skb, struct fqdn_packet *packet,
        struct fqdn_egress_policy *policy)
{
    struct keystruct trie = {};
    struct conntrack_key legacy = {};
    fqdn_egress_keys(&packet->tuple, skb->ifindex, &trie, &legacy);
    __u32 zero = 0, one = 1;
    struct pod_state *state = bpf_map_lookup_elem(&egress_pod_state_map, &zero);
    struct pod_state *cluster = bpf_map_lookup_elem(&egress_pod_state_map, &one);
    if (!state || !cluster)
        return -1;
    __u8 ns_state = state->state;
    policy->state = GET_CT_VAL(ns_state, cluster->state);
    policy->action = fqdn_static_action(&trie, &legacy, ns_state, &policy->admin, &policy->tier);
    /* Resolver transport is always evaluated fresh, including TCP SYN. */
    if (packet->tuple.dport != 53 || (packet->tuple.protocol != IPPROTO_TCP && packet->tuple.protocol != IPPROTO_UDP))
        policy->cached = fqdn_static_cached(&legacy, policy->state, &packet->tuple);
    return 0;
}

static __noinline int fqdn_record_static(struct __sk_buff *skb, struct fqdn_endpoint *ep,
        struct fqdn_packet *packet, struct fqdn_egress_policy *policy)
{
    struct data_t event = {};
#ifdef FQDN_IPV6
    __builtin_memcpy(&event.src_ip, packet->tuple.src, 16);
    __builtin_memcpy(&event.dest_ip, packet->tuple.dst, 16);
#else
    __builtin_memcpy(&event.src_ip, packet->tuple.src, 4);
    __builtin_memcpy(&event.dest_ip, packet->tuple.dst, 4);
#endif
    event.src_port = packet->tuple.sport;
    event.dest_port = packet->tuple.dport;
    event.protocol = packet->tuple.protocol;
    event.is_egress = 1;
    event.packet_sz = skb->len;
    event.tier = policy->tier;
    event.verdict = policy->action == ACTION_ALLOW;
    if (!fqdn_endpoint_current(skb->ifindex, ep))
        return BPF_DROP;
    if (policy->action == ACTION_ALLOW) {
        struct conntrack_key legacy = {};
        struct keystruct unused = {};
        fqdn_egress_keys(&packet->tuple, skb->ifindex, &unused, &legacy);
        struct conntrack_value value = {.val = policy->state, .last_seen = bpf_ktime_get_ns()};
        bpf_map_update_elem(&aws_conntrack_map, &legacy, &value, 0);
        /* Independent current static permission can own the flow. */
        struct fqdn_flow_key key = {.lifetime = ep->lifetime, .tuple = packet->tuple};
        bpf_map_delete_elem(&fqdn_flows, &key);
    }
    bpf_ringbuf_output(&policy_events, &event, sizeof(event), 0);
    return policy->action == ACTION_ALLOW ? BPF_OK : BPF_DROP;
}

static __noinline int fqdn_has_flow(struct fqdn_endpoint *ep, struct fqdn_packet *packet)
{
    struct fqdn_flow_key key = {.lifetime = ep->lifetime, .tuple = packet->tuple};
    return bpf_map_lookup_elem(&fqdn_flows, &key) != 0;
}

static __noinline int fqdn_handle_egress(struct __sk_buff *skb)
{
    /* Marks set inside workload namespaces are untrusted. Strip our owned bits
     * on all managed host-veths, including unselected pods, before using them.
     */
    __u32 config_key = 0;
    struct fqdn_proxy_config *config = bpf_map_lookup_elem(&fqdn_proxy, &config_key);
    if (config)
        skb->mark &= ~(config->mark | config->reply_mark);
    __u32 ifindex = skb->ifindex;
    struct fqdn_endpoint *live = bpf_map_lookup_elem(&fqdn_endpoints, &ifindex);
    if (!live || !(live->flags & FQDN_SELECTED))
        return FQDN_DEFER;
    struct fqdn_endpoint ep = *live;
    if (!(ep.flags & FQDN_READY) || !ep.lifetime)
        return BPF_DROP;
    struct fqdn_packet packet = {};
    int parsed = fqdn_parse(skb, &packet);
    if (parsed < 0)
        return BPF_DROP;
    if (parsed > 0)
        return BPF_OK;
    if (packet.tuple.family != ep.family)
        return BPF_DROP;
    /* ND uses multicast/unspecified addresses. PMTU and other errors retain
     * the endpoint's assigned address binding.
     */
    if (packet.essential_icmp == 2)
        return BPF_OK;
    if (__builtin_memcmp(packet.tuple.src, ep.address, 16))
        return BPF_DROP;
    if (packet.essential_icmp == 1)
        return BPF_OK;
#ifdef FQDN_IPV6
    if (packet.tuple.family != 6)
#else
    if (packet.tuple.family != 4)
#endif
        return BPF_DROP;
    struct fqdn_egress_policy policy = {};
    if (fqdn_read_egress_policy(skb, &packet, &policy))
        return BPF_DROP;
    __u64 now = bpf_ktime_get_boot_ns();
    if (packet.tuple.dport == 53 && (packet.tuple.protocol == IPPROTO_TCP || packet.tuple.protocol == IPPROTO_UDP)) {
        if (policy.action != ACTION_ALLOW)
            return BPF_DROP;
        return fqdn_assign_dns(skb, &ep, &packet, now);
    }
    int flow = fqdn_has_flow(&ep, &packet);
    /* Legacy CT is never populated by the FQDN path. Enrollment flushes all
     * older entries before selecting the endpoint; static origins keep their
     * existing behavior thereafter.
     */
    if (!flow && policy.cached)
        return BPF_OK;
    __u64 deadline = fqdn_live_grant(&ep, &packet.tuple, now);
    if (flow || deadline) {
        if (policy.admin == ACTION_DENY)
            return BPF_DROP;
        if (policy.action != ACTION_ALLOW) {
            /* Union dynamic namespace permission before namespace isolation;
             * Admin terminal decisions remain authoritative.
             */
            int result = fqdn_forward_flow(&ep, &packet, deadline, now);
            if (!fqdn_endpoint_current(ifindex, &ep))
                return BPF_DROP;
            return result;
        }
    }
    return fqdn_record_static(skb, &ep, &packet, &policy);
}
#endif
