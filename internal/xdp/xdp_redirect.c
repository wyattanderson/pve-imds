//go:build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// 169.254.169.254 as a little-endian __u32 (network bytes: a9 fe a9 fe)
#define TARGET_IP   0xfea9fea9u
#define TARGET_PORT 80

// ARP constants (subset of linux/if_arp.h, inlined to avoid deep glibc includes)
#define ARPHRD_ETHER    1
#define ARPOP_REQUEST   1

struct arphdr {
    __be16 ar_hrd;
    __be16 ar_pro;
    __u8   ar_hln;
    __u8   ar_pln;
    __be16 ar_op;
};

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u32);
} xsks_map SEC(".maps");

// Ethernet ARP body that follows struct arphdr for ARPHRD_ETHER / ETH_P_IP.
struct arp_eth_body {
    __u8 ar_sha[ETH_ALEN]; // sender hardware address
    __u8 ar_sip[4];        // sender IP address
    __u8 ar_tha[ETH_ALEN]; // target hardware address
    __u8 ar_tip[4];        // target IP address
} __attribute__((packed));

SEC("xdp")
int xdp_redirect_prog(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    // --- ARP interception ---
    // Redirect ARP requests whose target IP is 169.254.169.254 so that the
    // gvisor netstack can generate an ARP reply and the VM can reach us.
    if (eth->h_proto == bpf_htons(ETH_P_ARP)) {
        struct arphdr *arp = (void *)(eth + 1);
        if ((void *)(arp + 1) > data_end)
            return XDP_PASS;

        // Only handle standard Ethernet/IPv4 ARP requests.
        if (arp->ar_hrd != bpf_htons(ARPHRD_ETHER) ||
            arp->ar_pro != bpf_htons(ETH_P_IP)     ||
            arp->ar_hln != ETH_ALEN                 ||
            arp->ar_pln != 4                        ||
            arp->ar_op  != bpf_htons(ARPOP_REQUEST))
            return XDP_PASS;

        struct arp_eth_body *body = (void *)(arp + 1);
        if ((void *)(body + 1) > data_end)
            return XDP_PASS;

        // Compare target IP (network-byte-order bytes) as a little-endian u32.
        __u32 tip;
        __builtin_memcpy(&tip, body->ar_tip, 4);
        if (tip != TARGET_IP)
            return XDP_PASS;

        return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, XDP_DROP);
    }

    // --- TCP interception ---
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    if (ip->daddr != TARGET_IP)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)(ip + 1);
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    if (bpf_ntohs(tcp->dest) != TARGET_PORT)
        return XDP_PASS;

    return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, XDP_DROP);
}

char _license[] SEC("license") = "GPL";
