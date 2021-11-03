#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "hello_rb.h"
#include <string.h>

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

long ringbuffer_flags = 0;

SEC("kprobe/hello_rb_main")
int hello_rb_main(struct pt_regs *ctx)
{
    __u64 id = bpf_get_current_pid_tgid();
    __u32 tgid = id >> 32;
    proc_info *process;

    process = bpf_ringbuf_reserve(&events, sizeof(proc_info), ringbuffer_flags);
    if (!process)
    {
        return 0;
    }

    process->pid = tgid;
    strcpy(process->comment, "ABAY");

    bpf_ringbuf_submit(process, ringbuffer_flags);
    return 0;
}