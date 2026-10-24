// Test tooling only (the Linux reference router of tests/kvm/fwd_bench.py,
// ROUTER=linux-xdp; it runs in a Linux test VM and is not part of RustROS).
// Its GPL license declaration is what the kernel requires of a program using
// bpf_fib_lookup.
//
// Forwarding analysis: the XDP reference router for RustROS. IPv4 packets
// are routed with the kernel FIB (bpf_fib_lookup), TTL decremented with an
// incremental checksum update, MACs rewritten and redirected to the
// outgoing NIC; anything else goes to the normal Linux path.
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef AF_INET
#define AF_INET 2
#endif

static __always_inline void ttl_dec(struct iphdr *ip)
{
	__u32 sum = ip->check;
	sum += bpf_htons(0x0100);
	ip->check = (__u16)(sum + (sum >= 0xFFFF));
	ip->ttl--;
}

SEC("xdp")
int xdp_fwd(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data, *end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	struct iphdr *ip = data + sizeof(*eth);
	struct bpf_fib_lookup fib = {};
	if ((void *)(ip + 1) > end || eth->h_proto != bpf_htons(ETH_P_IP) || ip->ttl <= 1)
		return XDP_PASS;
	fib.family = AF_INET;
	fib.tos = ip->tos;
	fib.l4_protocol = ip->protocol;
	fib.tot_len = bpf_ntohs(ip->tot_len);
	fib.ipv4_src = ip->saddr;
	fib.ipv4_dst = ip->daddr;
	fib.ifindex = ctx->ingress_ifindex;
	if (bpf_fib_lookup(ctx, &fib, sizeof(fib), 0) != BPF_FIB_LKUP_RET_SUCCESS)
		return XDP_PASS;
	ttl_dec(ip);
	__builtin_memcpy(eth->h_dest, fib.dmac, ETH_ALEN);
	__builtin_memcpy(eth->h_source, fib.smac, ETH_ALEN);
	return bpf_redirect(fib.ifindex, 0);
}

char _license[] SEC("license") = "GPL";
