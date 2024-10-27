//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_LINE_SIZE 500

struct bash_info {
    char content[MAX_LINE_SIZE];
    int pid;
};

struct {
    __uint(type, BPF_MAP_TYPE_QUEUE); 
    __type(value, struct bash_info);
    __uint(max_entries, 64);
} bash_input SEC(".maps");

SEC("uretprobe//bin/bash:readline")
int watch_bash(const void *ret) {
    struct bash_info info;
    info.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_probe_read_user_str(info.content, sizeof(info.content), ret);
    bpf_map_push_elem(&bash_input, &info, BPF_EXIST);

    bpf_printk("PID %d read: %s ", info.pid, info.content);

    return 0;
};

char LICENSE[] SEC("license") = "GPL";
