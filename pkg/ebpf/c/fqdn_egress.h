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
        __u8 state, int *admin_action)
{
    __u32 priority, baseline_priority;
    __u8 baseline;
    int admin = evaluateClusterPolicyByLookUp(*trie, *flow, &priority, &baseline, &baseline_priority);
    *admin_action = priority <= ADMIN_TIER_PRIORITY_LIMIT ? admin : ACTION_PASS;
    if (*admin_action == ACTION_ALLOW || *admin_action == ACTION_DENY)
        return *admin_action;
    int ns = evaluateNamespacePolicyByLookUp(*trie, *flow, state);
    if (ns != ACTION_PASS)
        return ns;
    if (baseline != ACTION_PASS)
        return baseline;
    return state == DEFAULT_ALLOW ? ACTION_ALLOW : ACTION_DENY;
}

/* The lookup changes only the socket, never the packet's resolver tuple. Owned
 * policy routing delivers the marked packet locally. Missing listener, route
 * readiness, metadata capacity or sk_assign support always drops selected DNS.
 */
static __noinline int fqdn_assign_dns(struct __sk_buff *skb, struct fqdn_endpoint *ep,
        struct fqdn_packet *packet, __u64 now)
{
    __u32 zero = 0;
    struct fqdn_proxy_config *config = bpf_map_lookup_elem(&fqdn_proxy, &zero);
    if (!config || !config->ready || !config->port || config->port > 65535 || !config->mark)
        return BPF_DROP;
    __u32 mark = config->mark;
    __u16 port = config->port;
    struct bpf_sock_tuple tuple = {};
    struct bpf_sock *socket = 0;
    __u32 size;
    if (packet->tuple.family == 4) {
        __builtin_memcpy(&tuple.ipv4.saddr, packet->tuple.src, 4);
        __builtin_memcpy(&tuple.ipv4.daddr, packet->tuple.dst, 4);
        tuple.ipv4.sport = bpf_htons(packet->tuple.sport);
        tuple.ipv4.dport = bpf_htons(packet->tuple.dport);
        size = sizeof(tuple.ipv4);
    } else {
        __builtin_memcpy(tuple.ipv6.saddr, packet->tuple.src, 16);
        __builtin_memcpy(tuple.ipv6.daddr, packet->tuple.dst, 16);
        tuple.ipv6.sport = bpf_htons(packet->tuple.sport);
        tuple.ipv6.dport = bpf_htons(packet->tuple.dport);
        size = sizeof(tuple.ipv6);
    }
    if (packet->tuple.protocol == IPPROTO_TCP) {
        socket = bpf_sk_lookup_tcp(skb, &tuple, size, ((__u64)-1), 0);
        if (socket && socket->state == 10 /* TCP_LISTEN */) {
            bpf_sk_release(socket);
            socket = 0;
        }
    }
    if (!socket) {
        /* Lookup the exclusively configured transparent loopback listener. */
        if (packet->tuple.family == 4) {
            tuple.ipv4.daddr = bpf_htonl(0x7f000001);
            tuple.ipv4.dport = bpf_htons(port);
        } else {
            __builtin_memset(tuple.ipv6.daddr, 0, 16);
            tuple.ipv6.daddr[3] = bpf_htonl(1);
            tuple.ipv6.dport = bpf_htons(port);
        }
        if (packet->tuple.protocol == IPPROTO_TCP)
            socket = bpf_sk_lookup_tcp(skb, &tuple, size, ((__u64)-1), 0);
        else
            socket = bpf_sk_lookup_udp(skb, &tuple, size, ((__u64)-1), 0);
        if (!socket)
            return BPF_DROP;
        if (packet->tuple.protocol == IPPROTO_TCP && socket->state != 10) {
            bpf_sk_release(socket);
            return BPF_DROP;
        }
    }
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

static __noinline int fqdn_handle_egress(struct __sk_buff *skb)
{
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
    if (parsed > 0 || packet.essential_icmp)
        return BPF_OK;
    if (packet.tuple.family != ep.family || __builtin_memcmp(packet.tuple.src, ep.address, 16))
        return BPF_DROP;
#ifdef FQDN_IPV6
    if (packet.tuple.family != 6)
#else
    if (packet.tuple.family != 4)
#endif
        return BPF_DROP;
    struct keystruct trie = {};
    struct conntrack_key legacy = {};
    fqdn_egress_keys(&packet.tuple, ifindex, &trie, &legacy);
    __u32 zero = 0, one = 1;
    struct pod_state *state = bpf_map_lookup_elem(&egress_pod_state_map, &zero);
    struct pod_state *cluster = bpf_map_lookup_elem(&egress_pod_state_map, &one);
    if (!state || !cluster)
        return BPF_DROP;
    __u8 ns_state = state->state;
    __u8 ct_state = GET_CT_VAL(ns_state, cluster->state);
    __u64 now = bpf_ktime_get_boot_ns();
    int admin_action;
    int static_action = fqdn_static_action(&trie, &legacy, ns_state, &admin_action);
    if (packet.tuple.dport == 53 && (packet.tuple.protocol == IPPROTO_TCP || packet.tuple.protocol == IPPROTO_UDP)) {
        if (static_action != ACTION_ALLOW)
            return BPF_DROP;
        return fqdn_assign_dns(skb, &ep, &packet, now);
    }
    struct fqdn_flow_key flow_key = {.lifetime = ep.lifetime, .tuple = packet.tuple};
    struct fqdn_flow *flow = bpf_map_lookup_elem(&fqdn_flows, &flow_key);
    /* Legacy entries are never populated by the FQDN path. Existing static
     * origin behavior is retained; enrollment must flush pre-enrollment CT.
     */
    if (!flow && fqdn_static_cached(&legacy, ct_state, &packet.tuple))
        return BPF_OK;
    __u64 deadline = fqdn_live_grant(&ep, &packet.tuple, now);
    if (flow || deadline) {
        if (admin_action == ACTION_DENY)
            return BPF_DROP;
        if (static_action != ACTION_ALLOW) {
            /* Dynamic namespace permission unions with namespace static rules
             * before namespace isolation; Admin terminal decisions came first.
             */
            int result = fqdn_forward_flow(&ep, &packet, deadline, now);
            if (!fqdn_endpoint_current(ifindex, &ep))
                return BPF_DROP;
            return result;
        }
        /* Independent static permission can own the flow from this point. */
        bpf_map_delete_elem(&fqdn_flows, &flow_key);
    }
    struct data_t event = {};
#ifdef FQDN_IPV6
    __builtin_memcpy(&event.src_ip, packet.tuple.src, 16);
    __builtin_memcpy(&event.dest_ip, packet.tuple.dst, 16);
#else
    __builtin_memcpy(&event.src_ip, packet.tuple.src, 4);
    __builtin_memcpy(&event.dest_ip, packet.tuple.dst, 4);
#endif
    event.src_port = packet.tuple.sport;
    event.dest_port = packet.tuple.dport;
    event.protocol = packet.tuple.protocol;
    event.is_egress = 1;
    event.packet_sz = skb->len;
    if (!fqdn_endpoint_current(ifindex, &ep))
        return BPF_DROP;
    return evaluateFlow(trie, legacy, ct_state, &event, ns_state);
}
#endif
