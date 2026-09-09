#ifndef AWS_NPA_FQDN_PACKET_H
#define AWS_NPA_FQDN_PACKET_H
#include <bpf/bpf_endian.h>
#include "fqdn.h"
/* SCTP may be a module and absent from generated vmlinux BTF. This wire
 * header is protocol-defined and never depends on kernel structure layout. */
struct aws_sctphdr { __be16 source, dest; __be32 vtag, checksum; };
struct fqdn_packet {
    struct fqdn_tuple tuple;
    __u32 sequence;
    __u32 ack_sequence;
    __u8 syn;
    __u8 ack;
    __u8 fin;
    __u8 rst;
    __u8 essential_icmp;
};

/* At most 32 TLVs per extension header. Reject mobile IPv6 home-address
 * rewriting and jumbograms: neither may change the identity after TC.
 */
static __noinline int fqdn_ipv6_options(void *header, void *end, __u32 length)
{
    __u32 offset = 2;
    for (int n = 0; n < 32; n++) {
        if (offset >= length)
            return 0;
        __u8 *option = header + offset;
        if (option + 1 > (__u8 *)end)
            return -1;
        if (option[0] == 0) { /* Pad1 */
            offset++;
            continue;
        }
        if (option[0] == 201 || option[0] == 194 || option + 2 > (__u8 *)end)
            return -1;
        __u32 size = (__u32)option[1] + 2;
        if (size > length - offset)
            return -1;
        offset += size;
    }
    return offset == length ? 0 : -1;
}

/* Strict parsing is used only for enrolled endpoints. Fragmented IP is rejected
 * before legacy conntrack; neither a non-initial fragment nor IPv4 options may
 * hide port 53. At most six IPv6 extension headers are accepted. ICMPv6 errors
 * and link-local ND remain available, including Packet Too Big for PMTU.
 */
static __noinline int fqdn_parse(struct __sk_buff *skb, struct fqdn_packet *p)
{
    void *base = (void *)(long)skb->data;
    void *end = (void *)(long)skb->data_end;
    struct ethhdr *eth = base;
    if ((void *)(eth + 1) > end)
        return -1;
    void *l4;
    __u32 transport_len;
    if (eth->h_proto == bpf_htons(0x0800)) {
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > end || ip->version != 4 || ip->ihl < 5)
            return -1;
        __u32 ihl = ip->ihl * 4;
        __u32 total = bpf_ntohs(ip->tot_len);
        if (total < ihl || (void *)ip + ihl > end ||
            total > skb->len - sizeof(*eth) ||
            (ip->frag_off & bpf_htons(0x3fff)))
            return -1;
        /* Source routing changes the effective destination after this hook.
         * Other options use the validated IHL and bounded TLV parsing.
         */
        __u32 option_offset = sizeof(*ip);
        for (int n = 0; n < 40; n++) {
            if (option_offset >= ihl)
                break;
            __u8 *option = (void *)ip + option_offset;
            if (option + 1 > (__u8 *)end)
                return -1;
            __u8 type = option[0];
            if (!type)
                break;
            if (type == 1) {
                option_offset++;
                continue;
            }
            if (type == 131 || type == 137 || option + 2 > (__u8 *)end)
                return -1;
            __u8 length = option[1];
            if (length < 2 || option_offset + length > ihl)
                return -1;
            option_offset += length;
        }
        p->tuple.family = 4;
        __builtin_memcpy(p->tuple.src, &ip->saddr, 4);
        __builtin_memcpy(p->tuple.dst, &ip->daddr, 4);
        p->tuple.protocol = ip->protocol;
        l4 = (void *)ip + ihl;
        transport_len = total - ihl;
    } else if (eth->h_proto == bpf_htons(0x86dd)) {
        struct ipv6hdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > end || ip->version != 6)
            return -1;
        transport_len = bpf_ntohs(ip->payload_len);
        /* IPv6 jumbograms are not supported. */
        if (!transport_len || transport_len > skb->len - sizeof(*eth) - sizeof(*ip))
            return -1;
        p->tuple.family = 6;
        __builtin_memcpy(p->tuple.src, &ip->saddr, 16);
        __builtin_memcpy(p->tuple.dst, &ip->daddr, 16);
        __u8 next = ip->nexthdr;
        l4 = (void *)(ip + 1);
        for (int n = 0; n < 6; n++) {
            if (next == 43 || next == 44) /* Source routing and all fragments. */
                return -1;
            if (next != 0 && next != 60 && next != 51)
                break;
            struct ipv6_opt_hdr *ext = l4;
            if ((void *)(ext + 1) > end || transport_len < 2)
                return -1;
            __u32 length = next == 51 ? ((__u32)ext->hdrlen + 2) * 4 : ((__u32)ext->hdrlen + 1) * 8;
            if (length > transport_len || length < 8 || l4 + length > end || (next == 51 && length < 12))
                return -1;
            if (next != 51 && fqdn_ipv6_options(l4, end, length))
                return -1;
            next = ext->nexthdr;
            l4 += length;
            transport_len -= length;
        }
        if (next == 0 || next == 43 || next == 44 || next == 60 || next == 51 || next == 50)
            return -1;
        p->tuple.protocol = next;
        if (next == 58) {
            struct icmp6hdr *icmp = l4;
            if ((void *)(icmp + 1) > end || transport_len < sizeof(*icmp))
                return -1;
            __u8 type = icmp->icmp6_type;
            __u8 code = icmp->icmp6_code;
            if (type >= 1 && type <= 4) {
                /* Error messages must contain the invoking IPv6 header. */
                if (transport_len < sizeof(*icmp) + sizeof(*ip) ||
                    (type == 1 && code > 7) || (type == 2 && code != 0) ||
                    (type == 3 && code > 1) || (type == 4 && code > 3))
                    return -1;
                p->essential_icmp = 1;
            }
            if (type >= 133 && type <= 136) {
                __u32 minimum = type == 133 ? 8 : type == 134 ? 16 : 24;
                if (ip->hop_limit != 255 || code || transport_len < minimum)
                    return -1;
                p->essential_icmp = 2;
            }
        }
    } else {
        return 1; /* ARP/non-IP: existing behavior. */
    }
    if (p->tuple.protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = l4;
        if ((void *)(tcp + 1) > end || transport_len < sizeof(*tcp) || tcp->doff < 5)
            return -1;
        __u32 length = tcp->doff * 4;
        if (length > transport_len || l4 + length > end)
            return -1;
        p->tuple.sport = bpf_ntohs(tcp->source);
        p->tuple.dport = bpf_ntohs(tcp->dest);
        p->sequence = bpf_ntohl(tcp->seq);
        p->ack_sequence = bpf_ntohl(tcp->ack_seq);
        p->syn = tcp->syn;
        p->ack = tcp->ack;
        p->fin = tcp->fin;
        p->rst = tcp->rst;
    } else if (p->tuple.protocol == IPPROTO_UDP) {
        struct udphdr *udp = l4;
        if ((void *)(udp + 1) > end || transport_len < sizeof(*udp))
            return -1;
        __u32 length = bpf_ntohs(udp->len);
        if (length < sizeof(*udp) || length > transport_len)
            return -1;
        p->tuple.sport = bpf_ntohs(udp->source);
        p->tuple.dport = bpf_ntohs(udp->dest);
    } else if (p->tuple.protocol == IPPROTO_SCTP) {
        struct aws_sctphdr *sctp = l4;
        if ((void *)(sctp + 1) > end || transport_len < sizeof(*sctp))
            return -1;
        p->tuple.sport = bpf_ntohs(sctp->source);
        p->tuple.dport = bpf_ntohs(sctp->dest);
    }
    return 0;
}

static __always_inline void fqdn_reverse_tuple(struct fqdn_tuple *dst, const struct fqdn_tuple *src)
{
    __builtin_memcpy(dst->src, src->dst, 16);
    __builtin_memcpy(dst->dst, src->src, 16);
    dst->sport = src->dport;
    dst->dport = src->sport;
    dst->protocol = src->protocol;
    dst->family = src->family;
}

static __always_inline __u64 fqdn_live_grant(const struct fqdn_endpoint *ep, const struct fqdn_tuple *tuple, __u64 now)
{
    struct fqdn_grant_key key = {.lifetime = ep->lifetime, .generation = ep->generation};
    __builtin_memcpy(key.address, tuple->dst, 16);
    struct fqdn_grant *grant = bpf_map_lookup_elem(&fqdn_grants, &key);
    if (!grant)
        return 0;
    __u64 deadline = 0;
    for (int i = 0; i < FQDN_MAX_PORTS; i++) {
        struct fqdn_l4_grant *port = &grant->ports[i];
        if (port->deadline <= now || (port->protocol != 0 && port->protocol != ANY_IP_PROTOCOL && port->protocol != tuple->protocol))
            continue;
        if (port->start_port && tuple->dport != port->start_port && (tuple->dport < port->start_port || tuple->dport > port->end_port))
            continue;
        if (port->deadline > deadline)
            deadline = port->deadline;
    }
    return deadline;
}

static __always_inline int fqdn_endpoint_current(__u32 ifindex, const struct fqdn_endpoint *expected)
{
    struct fqdn_endpoint *current = bpf_map_lookup_elem(&fqdn_endpoints, &ifindex);
    return current && current->lifetime == expected->lifetime &&
        current->generation == expected->generation && (current->flags & FQDN_READY);
}

/* Keep transport/NAT state separate from FQDN authority. Only SYN -> SYNACK ->
 * ACK, with both initial sequence numbers, establishes expiry-independent TCP.
 * Userspace must explicitly carry verified surviving flows across generations.
 */
static __noinline int fqdn_forward_flow(struct fqdn_endpoint *ep, struct fqdn_packet *p, __u64 deadline, __u64 now)
{
    struct fqdn_flow_key key = {.lifetime = ep->lifetime, .tuple = p->tuple};
    struct fqdn_flow *old = bpf_map_lookup_elem(&fqdn_flows, &key);
    if (p->tuple.protocol != IPPROTO_TCP) {
        if (!deadline)
            return BPF_DROP;
        struct fqdn_flow value = {.generation = ep->generation, .deadline = deadline,
            .last_seen = now, .state = FQDN_FLOW_DATAGRAM};
        if (bpf_map_update_elem(&fqdn_flows, &key, &value, 0))
            return BPF_DROP;
        return BPF_OK;
    }
    if (p->syn && !p->ack) {
        if (!deadline || p->fin || p->rst)
            return BPF_DROP;
        struct fqdn_flow value = {.generation = ep->generation, .deadline = now + FQDN_HANDSHAKE_TIMEOUT,
            .last_seen = now, .state = FQDN_FLOW_SYN, .syn_sequence = p->sequence};
        if (deadline < value.deadline)
            value.deadline = deadline;
        if (bpf_map_update_elem(&fqdn_flows, &key, &value, 0))
            return BPF_DROP;
        return BPF_OK;
    }
    if (!old || old->generation != ep->generation || old->deadline <= now ||
        now - old->last_seen > FQDN_TCP_IDLE_TIMEOUT || p->syn)
        return BPF_DROP;
    if (old->state == FQDN_FLOW_SYN_ACK) {
        if (!p->ack || p->sequence != old->syn_sequence + 1 || p->ack_sequence != old->peer_sequence + 1)
            return BPF_DROP;
        old->state = FQDN_FLOW_ESTABLISHED;
        old->deadline = now + FQDN_TCP_IDLE_TIMEOUT;
    } else if (old->state != FQDN_FLOW_ESTABLISHED && old->state != FQDN_FLOW_CLOSING) {
        return BPF_DROP;
    }
    if (p->fin || p->rst) {
        if (old->state != FQDN_FLOW_CLOSING) {
            old->state = FQDN_FLOW_CLOSING;
            old->deadline = now + FQDN_CLOSE_TIMEOUT;
        }
    } else if (old->state == FQDN_FLOW_ESTABLISHED) {
        old->deadline = now + FQDN_TCP_IDLE_TIMEOUT;
    }
    old->last_seen = now;
    return BPF_OK;
}

static __always_inline int fqdn_reverse_flow(struct fqdn_endpoint *ep, struct fqdn_packet *p, struct fqdn_flow *flow, __u64 now)
{
    if (flow->generation != ep->generation)
        return BPF_DROP;
    if (p->tuple.protocol != IPPROTO_TCP) {
        /* Permit bounded replies to an admitted datagram, even across TTL zero. */
        return flow->state == FQDN_FLOW_DATAGRAM && now - flow->last_seen <= FQDN_REPLY_TIMEOUT ? BPF_OK : BPF_DROP;
    }
    if (flow->deadline <= now || now - flow->last_seen > FQDN_TCP_IDLE_TIMEOUT)
        return BPF_DROP;
    if (flow->state == FQDN_FLOW_SYN || flow->state == FQDN_FLOW_SYN_ACK) {
        if (!p->syn || !p->ack || p->fin || p->rst || p->ack_sequence != flow->syn_sequence + 1)
            return BPF_DROP;
        if (flow->state == FQDN_FLOW_SYN_ACK && flow->peer_sequence != p->sequence)
            return BPF_DROP;
        flow->state = FQDN_FLOW_SYN_ACK;
        flow->peer_sequence = p->sequence;
    } else if (flow->state == FQDN_FLOW_ESTABLISHED || flow->state == FQDN_FLOW_CLOSING) {
        if (p->syn)
            return BPF_DROP;
        if (p->fin || p->rst) {
            if (flow->state != FQDN_FLOW_CLOSING) {
                flow->state = FQDN_FLOW_CLOSING;
                flow->deadline = now + FQDN_CLOSE_TIMEOUT;
            }
        } else if (flow->state == FQDN_FLOW_ESTABLISHED) {
            flow->deadline = now + FQDN_TCP_IDLE_TIMEOUT;
        }
    } else {
        return BPF_DROP;
    }
    flow->last_seen = now;
    return BPF_OK;
}
#endif
