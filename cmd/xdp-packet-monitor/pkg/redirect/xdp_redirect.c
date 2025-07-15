//go:build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define TARGET_IP 0xfea9fea9  // 169.254.169.254 in network byte order
#define TARGET_PORT 80

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u32);
} xsks_map SEC(".maps");

SEC("xdp")
int xdp_redirect_prog(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;
    
    // Check if it's an IPv4 packet
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;
    
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    
    // Check if it's TCP
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;
    
    // // Check if destination IP matches 169.254.169.254
    // if (ip->daddr != TARGET_IP)
    //     return XDP_PASS;
    
    struct tcphdr *tcp = (void *)(ip + 1);
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;
    
    // Check if destination port is 80
    if (bpf_ntohs(tcp->dest) != TARGET_PORT)
        return XDP_PASS;
    
    // Redirect to AF_XDP socket (queue 0)
    int queue_id = 0;
    return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, XDP_DROP);
}

char _license[] SEC("license") = "GPL"; 