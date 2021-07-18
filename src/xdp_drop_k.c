#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int  xdp_prog_hello(struct xdp_md *ctx)
{
	return XDP_DROP;
}