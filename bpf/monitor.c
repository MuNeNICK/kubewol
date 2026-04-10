//go:build ignore

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Minimal ICMP header (avoid pulling in linux/icmp.h which has glibc dep issues)
struct icmphdr_min {
    __u8  type;
    __u8  code;
    __u16 checksum;
    __u32 un;
};

// Key: Service ClusterIP + port
struct svc_key {
    __u32 addr; // network byte order
    __u16 port; // network byte order
    __u16 pad;
};

// Ring buffer event: SYN detected for a scaled-to-zero service
struct syn_event {
    __u32 src_addr;
    __u32 dst_addr;
    __u16 src_port;
    __u16 dst_port;
};

// ── shared maps (used by both ingress and egress programs) ──

// Watched services: userspace populates with ClusterIP:port -> 1
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, struct svc_key);
    __type(value, __u8);
} watch_svc SEC(".maps");

// SYN counter per watched service (for Prometheus metrics)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, struct svc_key);
    __type(value, __u64);
} syn_count SEC(".maps");

// Proxy mode: SYN DROP when no endpoints (ingress)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, struct svc_key);
    __type(value, __u8);
} proxy_mode SEC(".maps");

// RST suppress mode: RST/ICMP DROP (egress). Kept ON slightly longer
// than proxy_mode to cover the kube-proxy rule propagation gap.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, struct svc_key);
    __type(value, __u8);
} rst_suppress SEC(".maps");

// NodePort proxy mode: SYN DROP (ingress)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u8);
} nodeport_mode SEC(".maps");

// NodePort RST suppress: RST/ICMP DROP (egress)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u8);
} nodeport_rst_suppress SEC(".maps");

// NodePort -> ClusterIP:port mapping for SYN counting
// key=nodePort (network byte order, padded to u32), value=svc_key (ClusterIP:port)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, struct svc_key);
} nodeport_to_svc SEC(".maps");

// Ring buffer for instant SYN notifications to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096);
} syn_events SEC(".maps");

// ─────────────────────────────────────────
// TC ingress: detect SYN, count, notify
// ─────────────────────────────────────────
SEC("tc")
int traffic_monitor(struct __sk_buff *skb)
{
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;
    if (ip->protocol != IPPROTO_TCP)
        return TC_ACT_OK;

    __u32 ip_hlen = ip->ihl * 4;
    if (ip_hlen < sizeof(struct iphdr))
        return TC_ACT_OK;

    struct tcphdr *tcp = (void *)ip + ip_hlen;
    if ((void *)(tcp + 1) > data_end)
        return TC_ACT_OK;

    // Only pure SYN (new connection attempt)
    if (!(tcp->syn) || tcp->ack)
        return TC_ACT_OK;

    struct svc_key key = {
        .addr = ip->daddr,
        .port = tcp->dest,
        .pad  = 0,
    };

    // Check ClusterIP:port match
    __u8 *watched = bpf_map_lookup_elem(&watch_svc, &key);

    // Fallback: NodePort -> resolve to ClusterIP key
    struct svc_key count_key = key;
    if (!watched) {
        __u32 dport = tcp->dest;
        struct svc_key *resolved = bpf_map_lookup_elem(&nodeport_to_svc, &dport);
        if (!resolved)
            return TC_ACT_OK;
        count_key = *resolved;
    }

    // Increment SYN counter (using ClusterIP key for both ClusterIP and NodePort SYNs)
    __u64 *cnt = bpf_map_lookup_elem(&syn_count, &count_key);
    if (cnt) {
        __sync_fetch_and_add(cnt, 1);
    } else {
        __u64 init = 1;
        bpf_map_update_elem(&syn_count, &count_key, &init, BPF_ANY);
    }

    // Check if scaled-to-zero (proxy_mode or nodeport_mode)
    __u8 scaled_to_zero = 0;
    __u8 *pmode = bpf_map_lookup_elem(&proxy_mode, &count_key);
    if (pmode && *pmode) {
        scaled_to_zero = 1;
    } else {
        __u32 dport3 = tcp->dest;
        __u8 *nmode3 = bpf_map_lookup_elem(&nodeport_mode, &dport3);
        if (nmode3 && *nmode3)
            scaled_to_zero = 1;
    }

    if (scaled_to_zero) {
        // Push ring buffer event for logging
        struct syn_event *evt;
        evt = bpf_ringbuf_reserve(&syn_events, sizeof(*evt), 0);
        if (evt) {
            evt->src_addr = ip->saddr;
            evt->dst_addr = ip->daddr;
            evt->src_port = tcp->source;
            evt->dst_port = tcp->dest;
            bpf_ringbuf_submit(evt, 0);
        }
        // DROP the SYN: prevents conntrack entry, client TCP stack retransmits.
        // When pod becomes ready and proxy_mode turns OFF, the retransmit
        // passes through, DNAT works, and the SAME TCP connection succeeds.
        return TC_ACT_SHOT;
    }

    return TC_ACT_OK;
}

// ─────────────────────────────────────────
// TC egress: suppress RST/ICMP for scaled-to-zero services
//
// When kube-proxy has no endpoints, it sends:
//   - TCP RST  (iptables REJECT --reject-with tcp-reset)
//   - ICMP port unreachable  (iptables REJECT)
//
// By dropping these, the client's TCP stack retransmits
// the SYN after ~1s, by which time the pod is up.
// ─────────────────────────────────────────
SEC("tc")
int egress_rst_filter(struct __sk_buff *skb)
{
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    __u32 ip_hlen = ip->ihl * 4;
    if (ip_hlen < sizeof(struct iphdr))
        return TC_ACT_OK;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + ip_hlen;
        if ((void *)(tcp + 1) > data_end)
            return TC_ACT_OK;

        // Only RST packets (not RST+ACK from normal connection teardown with data)
        if (!tcp->rst)
            return TC_ACT_OK;

        // Check 1: src is ClusterIP:port
        struct svc_key key = {
            .addr = ip->saddr,
            .port = tcp->source,
            .pad  = 0,
        };
        __u8 *rs = bpf_map_lookup_elem(&rst_suppress, &key);
        if (rs && *rs) {
            return TC_ACT_SHOT;
        }

        // Check 2: src port is a NodePort (reverse-NATed RST)
        __u32 sport = tcp->source;
        __u8 *nrs = bpf_map_lookup_elem(&nodeport_rst_suppress, &sport);
        if (nrs && *nrs) {
            return TC_ACT_SHOT;
        }
    } else if (ip->protocol == IPPROTO_ICMP) {
        // ICMP destination unreachable might also be sent
        struct icmphdr_min *icmp = (void *)ip + ip_hlen;
        if ((void *)(icmp + 1) > data_end)
            return TC_ACT_OK;

        // Type 3 = destination unreachable
        if (icmp->type != 3)
            return TC_ACT_OK;

        // The ICMP payload contains the original IP header + 8 bytes
        // Parse the embedded original packet to find the service
        struct iphdr *orig_ip = (void *)(icmp + 1);
        if ((void *)(orig_ip + 1) > data_end)
            return TC_ACT_OK;

        if (orig_ip->protocol != IPPROTO_TCP)
            return TC_ACT_OK;

        // First 4 bytes after IP header = src_port(2) + dst_port(2)
        __u16 *ports = (void *)orig_ip + (orig_ip->ihl * 4);
        if ((void *)(ports + 2) > data_end)
            return TC_ACT_OK;

        // Check ClusterIP match
        struct svc_key key = {
            .addr = orig_ip->daddr,
            .port = ports[1],
            .pad  = 0,
        };
        __u8 *rs = bpf_map_lookup_elem(&rst_suppress, &key);
        if (rs && *rs) {
            return TC_ACT_SHOT;
        }
        // Check NodePort match
        __u32 dport = ports[1];
        __u8 *nrs = bpf_map_lookup_elem(&nodeport_rst_suppress, &dport);
        if (nrs && *nrs) {
            return TC_ACT_SHOT;
        }
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
