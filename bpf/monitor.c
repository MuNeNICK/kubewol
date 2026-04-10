//go:build ignore

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Hermetic header constants. Previously this file pulled in linux/if_ether.h,
// linux/ip.h, linux/tcp.h and linux/in.h and walked the packet via direct
// data/data_end pointer arithmetic. That form requires CAP_PERFMON because
// the BPF verifier classifies dynamic pointer arithmetic as privileged and
// rejects it under the unprivileged policy with
//   "R1 has pointer with unsupported alu operation,
//    pointer arithmetic with it prohibited for !root"
//
// Every packet field is now read via bpf_skb_load_bytes() with a scalar byte
// offset. Scalars are bounded (ihl is masked and shifted, so <=60) so the
// verifier can prove the sums stay in range. The resulting programs load
// under kernel 6.6+ with only CAP_BPF + CAP_NET_ADMIN.
#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif
#ifndef ETH_P_8021Q
#define ETH_P_8021Q 0x8100
#endif
#ifndef ETH_P_8021AD
#define ETH_P_8021AD 0x88A8
#endif

#define IPPROTO_TCP  6
#define IPPROTO_ICMP 1

// TCP flag bits in the 13th byte of the TCP header.
#define TCP_FLAG_SYN 0x02
#define TCP_FLAG_RST 0x04
#define TCP_FLAG_ACK 0x10

// ICMP destination unreachable: only suppress code 3 (port unreachable),
// which is what kube-proxy REJECT emits. Other codes (e.g. 4 fragmentation
// needed) carry real network signals and must never be dropped.
#define ICMP_TYPE_DEST_UNREACH 3
#define ICMP_CODE_PORT_UNREACH 3

// Static offsets used with bpf_skb_load_bytes.
#define ETH_HLEN          14
#define ETH_P_OFF         12 /* ethertype field inside Ethernet header */
#define VLAN_HLEN         4
#define VLAN_NEXT_P_OFF   2  /* next ethertype inside a VLAN tag */

#define IP_TOTLEN_OFF     2
#define IP_PROTO_OFF      9
#define IP_SADDR_OFF      12
#define IP_DADDR_OFF      16
#define IP_MIN_HLEN       20

#define TCP_SPORT_OFF     0
#define TCP_DPORT_OFF     2
#define TCP_DOFF_OFF      12 /* high nibble = data offset in 32-bit words */
#define TCP_FLAGS_OFF     13
#define TCP_MIN_HLEN      20

#define ICMP_TYPE_OFF     0
#define ICMP_CODE_OFF     1
#define ICMP_INNER_OFF    8  /* inner IP starts at ICMP + 8 (RFC 792) */

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

// BPF drop counters: per-reason PERCPU_ARRAY that userspace aggregates and
// exposes as kubewol_bpf_drop_total{reason}. Keep indices in sync with
// DropReason* in internal/ebpf/loader.go.
#define DROP_SYN_COUNT_UPDATE 0
#define DROP_RINGBUF_RESERVE  1
#define DROP_REASON_MAX       3
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, DROP_REASON_MAX);
    __type(key, __u32);
    __type(value, __u64);
} drop_count SEC(".maps");

static __always_inline void drop_inc(__u32 reason)
{
    __u64 *c = bpf_map_lookup_elem(&drop_count, &reason);
    if (c)
        __sync_fetch_and_add(c, 1);
}

// parse_l3_off returns the L3 byte offset inside the skb, skipping Ethernet
// and up to two stacked VLAN tags. Returns 1 on success, 0 if the packet is
// not IPv4 or the headers cannot be read. Uses bpf_skb_load_bytes exclusively
// so the verifier never sees pointer arithmetic on data pointers.
static __always_inline int parse_l3_off(struct __sk_buff *skb, __u32 *l3_off_out)
{
    __u16 h_proto = 0;
    __u32 off = ETH_HLEN;

    if (bpf_skb_load_bytes(skb, ETH_P_OFF, &h_proto, sizeof(h_proto)) < 0)
        return 0;

    if (h_proto == bpf_htons(ETH_P_8021Q) || h_proto == bpf_htons(ETH_P_8021AD)) {
        if (bpf_skb_load_bytes(skb, off + VLAN_NEXT_P_OFF, &h_proto, sizeof(h_proto)) < 0)
            return 0;
        off += VLAN_HLEN;
        if (h_proto == bpf_htons(ETH_P_8021Q) || h_proto == bpf_htons(ETH_P_8021AD)) {
            if (bpf_skb_load_bytes(skb, off + VLAN_NEXT_P_OFF, &h_proto, sizeof(h_proto)) < 0)
                return 0;
            off += VLAN_HLEN;
        }
    }

    if (h_proto != bpf_htons(ETH_P_IP))
        return 0;

    *l3_off_out = off;
    return 1;
}

// read_ip_header loads version/ihl, protocol and both addresses at l3_off.
// Returns 1 on success, 0 on load failure or malformed IPv4 header.
static __always_inline int read_ip_header(
    struct __sk_buff *skb, __u32 l3_off,
    __u32 *ihl_out, __u8 *proto_out, __u32 *saddr_out, __u32 *daddr_out)
{
    __u8 vihl;
    if (bpf_skb_load_bytes(skb, l3_off, &vihl, sizeof(vihl)) < 0)
        return 0;
    if ((vihl >> 4) != 4)
        return 0;
    __u32 ihl = ((__u32)(vihl & 0x0F)) << 2;
    if (ihl < IP_MIN_HLEN)
        return 0;

    __u8 proto;
    if (bpf_skb_load_bytes(skb, l3_off + IP_PROTO_OFF, &proto, sizeof(proto)) < 0)
        return 0;
    __u32 saddr = 0, daddr = 0;
    if (bpf_skb_load_bytes(skb, l3_off + IP_SADDR_OFF, &saddr, sizeof(saddr)) < 0)
        return 0;
    if (bpf_skb_load_bytes(skb, l3_off + IP_DADDR_OFF, &daddr, sizeof(daddr)) < 0)
        return 0;

    *ihl_out = ihl;
    *proto_out = proto;
    *saddr_out = saddr;
    *daddr_out = daddr;
    return 1;
}

// ─────────────────────────────────────────
// TC ingress: detect SYN, count, notify
// ─────────────────────────────────────────
SEC("tc")
int traffic_monitor(struct __sk_buff *skb)
{
    __u32 l3_off;
    if (!parse_l3_off(skb, &l3_off))
        return TC_ACT_OK;

    __u32 ihl;
    __u8 proto;
    __u32 saddr, daddr;
    if (!read_ip_header(skb, l3_off, &ihl, &proto, &saddr, &daddr))
        return TC_ACT_OK;
    if (proto != IPPROTO_TCP)
        return TC_ACT_OK;

    __u32 l4_off = l3_off + ihl;
    __u16 sport = 0, dport = 0;
    __u8 flags = 0;
    if (bpf_skb_load_bytes(skb, l4_off + TCP_SPORT_OFF, &sport, sizeof(sport)) < 0)
        return TC_ACT_OK;
    if (bpf_skb_load_bytes(skb, l4_off + TCP_DPORT_OFF, &dport, sizeof(dport)) < 0)
        return TC_ACT_OK;
    if (bpf_skb_load_bytes(skb, l4_off + TCP_FLAGS_OFF, &flags, sizeof(flags)) < 0)
        return TC_ACT_OK;

    // Only pure SYN (new connection attempt)
    if (!(flags & TCP_FLAG_SYN) || (flags & TCP_FLAG_ACK))
        return TC_ACT_OK;

    struct svc_key key = {
        .addr = daddr,
        .port = dport,
        .pad  = 0,
    };

    // Check ClusterIP:port match
    __u8 *watched = bpf_map_lookup_elem(&watch_svc, &key);

    // Fallback: NodePort -> resolve to ClusterIP key
    struct svc_key count_key = key;
    if (!watched) {
        __u32 dport_pad = dport;
        struct svc_key *resolved = bpf_map_lookup_elem(&nodeport_to_svc, &dport_pad);
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
        if (bpf_map_update_elem(&syn_count, &count_key, &init, BPF_ANY) != 0)
            drop_inc(DROP_SYN_COUNT_UPDATE);
    }

    // Check if scaled-to-zero (proxy_mode or nodeport_mode)
    __u8 scaled_to_zero = 0;
    __u8 *pmode = bpf_map_lookup_elem(&proxy_mode, &count_key);
    if (pmode && *pmode) {
        scaled_to_zero = 1;
    } else {
        __u32 dport_pad = dport;
        __u8 *nmode = bpf_map_lookup_elem(&nodeport_mode, &dport_pad);
        if (nmode && *nmode)
            scaled_to_zero = 1;
    }

    if (scaled_to_zero) {
        // Push ring buffer event for logging
        struct syn_event *evt;
        evt = bpf_ringbuf_reserve(&syn_events, sizeof(*evt), 0);
        if (evt) {
            evt->src_addr = saddr;
            evt->dst_addr = daddr;
            evt->src_port = sport;
            evt->dst_port = dport;
            bpf_ringbuf_submit(evt, 0);
        } else {
            drop_inc(DROP_RINGBUF_RESERVE);
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
    __u32 l3_off;
    if (!parse_l3_off(skb, &l3_off))
        return TC_ACT_OK;

    __u32 ihl;
    __u8 proto;
    __u32 saddr, daddr;
    if (!read_ip_header(skb, l3_off, &ihl, &proto, &saddr, &daddr))
        return TC_ACT_OK;

    __u16 tot_len_be;
    if (bpf_skb_load_bytes(skb, l3_off + IP_TOTLEN_OFF, &tot_len_be, sizeof(tot_len_be)) < 0)
        return TC_ACT_OK;
    __u32 tot_len = bpf_ntohs(tot_len_be);

    __u32 l4_off = l3_off + ihl;

    if (proto == IPPROTO_TCP) {
        __u8 flags;
        if (bpf_skb_load_bytes(skb, l4_off + TCP_FLAGS_OFF, &flags, sizeof(flags)) < 0)
            return TC_ACT_OK;
        if (!(flags & TCP_FLAG_RST))
            return TC_ACT_OK;

        __u8 doff_byte;
        if (bpf_skb_load_bytes(skb, l4_off + TCP_DOFF_OFF, &doff_byte, sizeof(doff_byte)) < 0)
            return TC_ACT_OK;
        __u32 tcp_hlen = ((__u32)((doff_byte >> 4) & 0x0F)) << 2;
        if (tcp_hlen < TCP_MIN_HLEN)
            return TC_ACT_OK;

        // Filter to RSTs that look like kube-proxy REJECT responses (no payload):
        // ip_total_length - ip_hlen - tcp_hlen == 0. App-level resets that carry
        // queued data still pass through, so legitimate backend reset signals
        // are preserved during the suppression window.
        if (tot_len < ihl + tcp_hlen)
            return TC_ACT_OK;
        if (tot_len - ihl - tcp_hlen != 0)
            return TC_ACT_OK;

        __u16 sport;
        if (bpf_skb_load_bytes(skb, l4_off + TCP_SPORT_OFF, &sport, sizeof(sport)) < 0)
            return TC_ACT_OK;

        // Check 1: src is ClusterIP:port
        struct svc_key key = {
            .addr = saddr,
            .port = sport,
            .pad  = 0,
        };
        __u8 *rs = bpf_map_lookup_elem(&rst_suppress, &key);
        if (rs && *rs) {
            return TC_ACT_SHOT;
        }

        // Check 2: src port is a NodePort (reverse-NATed RST)
        __u32 sport_pad = sport;
        __u8 *nrs = bpf_map_lookup_elem(&nodeport_rst_suppress, &sport_pad);
        if (nrs && *nrs) {
            return TC_ACT_SHOT;
        }
    } else if (proto == IPPROTO_ICMP) {
        __u8 icmp_type, icmp_code;
        if (bpf_skb_load_bytes(skb, l4_off + ICMP_TYPE_OFF, &icmp_type, sizeof(icmp_type)) < 0)
            return TC_ACT_OK;
        if (bpf_skb_load_bytes(skb, l4_off + ICMP_CODE_OFF, &icmp_code, sizeof(icmp_code)) < 0)
            return TC_ACT_OK;
        if (icmp_type != ICMP_TYPE_DEST_UNREACH || icmp_code != ICMP_CODE_PORT_UNREACH)
            return TC_ACT_OK;

        // The ICMP payload contains the original IP header + at least 8 bytes
        // of the offending datagram (per RFC 792). Parse the embedded original
        // packet to find the service.
        __u32 inner_off = l4_off + ICMP_INNER_OFF;

        __u8 inner_vihl;
        if (bpf_skb_load_bytes(skb, inner_off, &inner_vihl, sizeof(inner_vihl)) < 0)
            return TC_ACT_OK;
        if ((inner_vihl >> 4) != 4)
            return TC_ACT_OK;
        __u32 inner_ihl = ((__u32)(inner_vihl & 0x0F)) << 2;
        if (inner_ihl < IP_MIN_HLEN)
            return TC_ACT_OK;

        __u8 inner_proto;
        if (bpf_skb_load_bytes(skb, inner_off + IP_PROTO_OFF, &inner_proto, sizeof(inner_proto)) < 0)
            return TC_ACT_OK;
        if (inner_proto != IPPROTO_TCP)
            return TC_ACT_OK;

        __u32 inner_daddr = 0;
        if (bpf_skb_load_bytes(skb, inner_off + IP_DADDR_OFF, &inner_daddr, sizeof(inner_daddr)) < 0)
            return TC_ACT_OK;

        __u16 inner_dport = 0;
        if (bpf_skb_load_bytes(skb, inner_off + inner_ihl + TCP_DPORT_OFF, &inner_dport, sizeof(inner_dport)) < 0)
            return TC_ACT_OK;

        // Check ClusterIP match
        struct svc_key key = {
            .addr = inner_daddr,
            .port = inner_dport,
            .pad  = 0,
        };
        __u8 *rs = bpf_map_lookup_elem(&rst_suppress, &key);
        if (rs && *rs) {
            return TC_ACT_SHOT;
        }
        // Check NodePort match
        __u32 dport_pad = inner_dport;
        __u8 *nrs = bpf_map_lookup_elem(&nodeport_rst_suppress, &dport_pad);
        if (nrs && *nrs) {
            return TC_ACT_SHOT;
        }
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
