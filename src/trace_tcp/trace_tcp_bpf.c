#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

char __license[] SEC("license") = "Dual MIT/GPL";

#define READ_KERN_V(ptr)                                   \
	({                                                     \
		typeof(ptr) _val;                                  \
		__builtin_memset((void *)&_val, 0, sizeof(_val));  \
		bpf_probe_read((void *)&_val, sizeof(_val), &ptr); \
		_val;                                              \
	})

struct event_t
{
	u32 pid;
	u32 tid;
	u32 saddr;
	u32 daddr;
	u16 sport;
	u16 dport;
	char comm[80];
};

struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024 /* 256 KB */);
} events SEC(".maps");

SEC("kprobe/tcp_sendmsg")
int kprobe__tcp_sendmsg(struct pt_regs *ctx)
{
	struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
	struct inet_sock *inet = (struct inet_sock *)sk;

	struct event_t *task_info;
	task_info = bpf_ringbuf_reserve(&events, sizeof(struct event_t), 0);
	if (!task_info)
	{
		return 0;
	}
	
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 pid = pid_tgid >> 32;
	task_info->pid = pid;
	task_info->tid = pid_tgid;
	task_info->saddr = READ_KERN_V(inet->inet_saddr);
	task_info->daddr = READ_KERN_V(inet->sk.__sk_common.skc_daddr);
	task_info->sport = __bpf_ntohs(READ_KERN_V(inet->inet_sport));
	task_info->dport = __bpf_htons(READ_KERN_V(inet->sk.__sk_common.skc_dport));
	bpf_get_current_comm(&task_info->comm, 80);

	// bpf_printk("trace_tcp >> saddr: %d", task_info->saddr);
	// bpf_printk("trace_tcp >> daddr: %d", task_info->daddr);
	// bpf_printk("trace_tcp >> sport: %d", task_info->sport);
	// bpf_printk("trace_tcp >> dport: %d", task_info->dport);

	bpf_ringbuf_submit(task_info, 0);

	return 0;
}
