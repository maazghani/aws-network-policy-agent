/* FQDN ABI v1: all integers native-endian; addresses are network-order bytes.
 * IPv4 addresses occupy bytes 0..3 and bytes 4..15 are zero. Deadlines use
 * CLOCK_BOOTTIME, including suspend. Keep in sync with pkg/ebpf/fqdn*.go.
 */
#ifndef AWS_NPA_FQDN_H
#define AWS_NPA_FQDN_H
#define FQDN_SELECTED 1U
#define FQDN_READY 2U
#define FQDN_MAX_ENDPOINTS 4096
#define FQDN_MAX_GRANTS 65536
#define FQDN_MAX_FLOWS 65536
#define FQDN_MAX_DNS 16384
#define FQDN_MAX_PORTS 24
#define FQDN_NS_SECOND 1000000000ULL
#define FQDN_DNS_TIMEOUT (30ULL * FQDN_NS_SECOND)
#define FQDN_HANDSHAKE_TIMEOUT (30ULL * FQDN_NS_SECOND)
#define FQDN_TCP_IDLE_TIMEOUT (300ULL * FQDN_NS_SECOND)
#define FQDN_CLOSE_TIMEOUT (15ULL * FQDN_NS_SECOND)
#define FQDN_REPLY_TIMEOUT (5ULL * FQDN_NS_SECOND)
#define FQDN_FLOW_SYN 1
#define FQDN_FLOW_SYN_ACK 2
#define FQDN_FLOW_ESTABLISHED 3
#define FQDN_FLOW_CLOSING 4
#define FQDN_FLOW_DATAGRAM 5
#define FQDN_DEFER -1
struct fqdn_endpoint {
    __u64 lifetime;
    __u64 generation;
    __u8 address[16];
    __u32 family;
    __u32 flags;
};
struct fqdn_grant_key {
    __u64 lifetime;
    __u64 generation;
    __u8 address[16];
};
struct fqdn_l4_grant {
    __u64 deadline;
    __u16 start_port;
    __u16 end_port;
    __u8 protocol; /* 0 means any L4 protocol; otherwise IP protocol number. */
    __u8 pad[3];
};
struct fqdn_grant {
    struct fqdn_l4_grant ports[FQDN_MAX_PORTS];
};
struct fqdn_tuple {
    __u8 src[16];
    __u8 dst[16];
    __u16 sport;
    __u16 dport;
    __u8 protocol;
    __u8 family;
    __u8 pad[2];
};
struct fqdn_dns_value {
    __u64 lifetime;
    __u64 generation;
    __u64 deadline;
    __u32 ifindex;
    __u32 pad;
};
struct fqdn_proxy_config {
    __u32 port;
    __u32 mark;
    __u32 ready;
    __u32 reply_mark;
};
struct fqdn_flow_key {
    __u64 lifetime;
    struct fqdn_tuple tuple;
};
struct fqdn_flow {
    __u64 generation;
    __u64 deadline;
    __u64 last_seen;
    __u32 syn_sequence;
    __u32 peer_sequence;
    __u8 state;
    __u8 pad[7];
};
_Static_assert(sizeof(struct fqdn_endpoint) == 40, "endpoint ABI");
_Static_assert(sizeof(struct fqdn_grant_key) == 32, "grant key ABI");
_Static_assert(sizeof(struct fqdn_l4_grant) == 16, "L4 grant ABI");
_Static_assert(sizeof(struct fqdn_grant) == 384, "grant ABI");
_Static_assert(sizeof(struct fqdn_tuple) == 40, "DNS tuple ABI");
_Static_assert(sizeof(struct fqdn_dns_value) == 32, "DNS identity ABI");
_Static_assert(sizeof(struct fqdn_proxy_config) == 16, "proxy ABI");
_Static_assert(sizeof(struct fqdn_flow_key) == 48, "flow key ABI");
_Static_assert(sizeof(struct fqdn_flow) == 40, "flow value ABI");
#ifdef FQDN_DEFINE_MAPS
#define FQDN_MAP(name, map_type, key, value, capacity) \
struct bpf_map_def_pvt SEC("maps") name = { \
    .type = map_type, .key_size = sizeof(key), .value_size = sizeof(value), \
    .max_entries = capacity, .pinning = PIN_GLOBAL_NS, \
    .map_flags = map_type == BPF_MAP_TYPE_HASH ? 1 /* BPF_F_NO_PREALLOC */ : 0, \
}
/* Plain HASH avoids eviction of live authority under attacker-controlled churn.
 * Capacity exhaustion must fail the userspace barrier, never evict unrelated
 * endpoints. Flow eviction is restrictive, but HASH also exposes pressure.
 */
FQDN_MAP(fqdn_endpoints, BPF_MAP_TYPE_HASH, __u32, struct fqdn_endpoint, FQDN_MAX_ENDPOINTS);
FQDN_MAP(fqdn_grants, BPF_MAP_TYPE_HASH, struct fqdn_grant_key, struct fqdn_grant, FQDN_MAX_GRANTS);
FQDN_MAP(fqdn_flows, BPF_MAP_TYPE_HASH, struct fqdn_flow_key, struct fqdn_flow, FQDN_MAX_FLOWS);
FQDN_MAP(fqdn_dns, BPF_MAP_TYPE_HASH, struct fqdn_tuple, struct fqdn_dns_value, FQDN_MAX_DNS);
FQDN_MAP(fqdn_proxy, BPF_MAP_TYPE_ARRAY, __u32, struct fqdn_proxy_config, 1);
#undef FQDN_MAP
#else
struct bpf_map_def_pvt fqdn_endpoints;
struct bpf_map_def_pvt fqdn_grants;
struct bpf_map_def_pvt fqdn_flows;
struct bpf_map_def_pvt fqdn_dns;
struct bpf_map_def_pvt fqdn_proxy;
#endif
#endif
