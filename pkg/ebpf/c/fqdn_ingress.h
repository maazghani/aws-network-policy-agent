#ifndef AWS_NPA_FQDN_INGRESS_H
#define AWS_NPA_FQDN_INGRESS_H
#include "fqdn_packet.h"

static __noinline int fqdn_static_ingress(struct __sk_buff *skb, struct fqdn_endpoint *ep, struct fqdn_packet *packet)
{
    __u32 ifindex = skb->ifindex;
    /* Use the parsed transport offset for static-origin traffic as well. The
     * legacy fixed offsets cannot safely classify IPv4 options or IPv6
     * extension headers, even when a flow does not depend on DNS grants.
     */
    struct conntrack_key legacy = {};
    struct keystruct trie = {};
#ifdef FQDN_IPV6
    trie.prefix_len = 128;
    __builtin_memcpy(trie.ip, packet->tuple.src, 16);
    __builtin_memcpy(&legacy.saddr, packet->tuple.src, 16);
    __builtin_memcpy(&legacy.daddr, packet->tuple.dst, 16);
    __builtin_memcpy(&legacy.owner_addr, packet->tuple.dst, 16);
#else
    trie.prefix_len = 32;
    __builtin_memcpy(trie.ip, packet->tuple.src, 4);
    __builtin_memcpy(&legacy.src_ip, packet->tuple.src, 4);
    __builtin_memcpy(&legacy.dest_ip, packet->tuple.dst, 4);
    __builtin_memcpy(&legacy.owner_ip, packet->tuple.dst, 4);
#endif
    legacy.src_port = packet->tuple.sport;
    legacy.dest_port = packet->tuple.dport;
    legacy.protocol = packet->tuple.protocol;
    legacy.ifindex = ifindex;
    __u32 zero = 0, one = 1;
    struct pod_state *state = bpf_map_lookup_elem(&ingress_pod_state_map, &zero);
    struct pod_state *cluster = bpf_map_lookup_elem(&ingress_pod_state_map, &one);
    if (!state || !cluster)
        return BPF_DROP;
    __u8 ns_state = state->state;
    __u8 ct_state = GET_CT_VAL(ns_state, cluster->state);
    struct conntrack_value *ct = bpf_map_lookup_elem(&aws_conntrack_map, &legacy);
    if (ct && ct->val == ct_state) {
        ct->last_seen = bpf_ktime_get_ns();
        return BPF_OK;
    }
    struct conntrack_key legacy_reverse = legacy;
#ifdef FQDN_IPV6
    __builtin_memcpy(&legacy_reverse.saddr, packet->tuple.dst, 16);
    __builtin_memcpy(&legacy_reverse.daddr, packet->tuple.src, 16);
#else
    __builtin_memcpy(&legacy_reverse.src_ip, packet->tuple.dst, 4);
    __builtin_memcpy(&legacy_reverse.dest_ip, packet->tuple.src, 4);
#endif
    legacy_reverse.src_port = packet->tuple.dport;
    legacy_reverse.dest_port = packet->tuple.sport;
    ct = bpf_map_lookup_elem(&aws_conntrack_map, &legacy_reverse);
    if (ct) {
        ct->last_seen = bpf_ktime_get_ns();
        return BPF_OK;
    }
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
    event.packet_sz = skb->len;
    if (!fqdn_endpoint_current(ifindex, ep))
        return BPF_DROP;
    return evaluateFlow(trie, legacy, ct_state, &event, ns_state);
}

static __noinline int fqdn_handle_ingress(struct __sk_buff *skb)
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
    if (packet.tuple.family != ep.family || __builtin_memcmp(packet.tuple.dst, ep.address, 16))
        return BPF_DROP;
    struct fqdn_tuple reverse = {};
    fqdn_reverse_tuple(&reverse, &packet.tuple);
    __u64 now = bpf_ktime_get_boot_ns();
    if (reverse.dport == 53 && (reverse.protocol == IPPROTO_TCP || reverse.protocol == IPPROTO_UDP)) {
        __u32 config_key = 0;
        struct fqdn_proxy_config *config = bpf_map_lookup_elem(&fqdn_proxy, &config_key);
        if (!config || !config->ready || !config->reply_mark ||
            (skb->mark & config->reply_mark) != config->reply_mark)
            return BPF_DROP;
        struct fqdn_dns_value *dns = bpf_map_lookup_elem(&fqdn_dns, &reverse);
        if (dns && dns->lifetime == ep.lifetime && dns->generation == ep.generation &&
            dns->ifindex == ifindex && dns->deadline > now && fqdn_endpoint_current(ifindex, &ep))
            return BPF_OK;
        /* Selected DNS must return through a live redirected exchange; ingress
         * static permission cannot turn a stale or forged DNS reply into one.
         */
        return BPF_DROP;
    }
    struct fqdn_flow_key key = {.lifetime = ep.lifetime, .tuple = reverse};
    struct fqdn_flow *flow = bpf_map_lookup_elem(&fqdn_flows, &key);
    if (flow) {
        int result = fqdn_reverse_flow(&ep, &packet, flow, now);
        if (!fqdn_endpoint_current(ifindex, &ep))
            return BPF_DROP;
        return result;
    }
    return fqdn_static_ingress(skb, &ep, &packet);
}
#endif
