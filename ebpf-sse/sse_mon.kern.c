#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

const volatile pid_t target_pid = 0; 
char LICENSE[] SEC("license") = "GPL";

// Map: scratch flag per PID for sys_enter_openat
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u8);
    __uint(max_entries, 1024);
} open_scratch SEC(".maps");

// Map: record (pid,fd) pairs that belong to CSP files
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);    // pid<<32 | fd
    __type(value, __u8);
    __uint(max_entries, 4096);
} csp_fds SEC(".maps");

// Change this to your container’s actual mount path (with TRAILING slash!)
static __inline bool is_csp_file(const char *path) {
    // prefix remains the same
    const char prefix[] = "/linux-dev-env/SSE/searchable-encryption-database/cloud_service_provider";
    #pragma unroll
    for (int i = 0; i < sizeof(prefix)-1; i++) {
        // Load directly from buf on the BPF stack
        char c = path[i];
        if (c != prefix[i]) {
            return false;
        }
    }
    return true;
}


// 1) On entry, stash a 1 if the path matches our CSP folder (with slash)
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_enter_openat(struct trace_event_raw_sys_enter *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (target_pid != 0 && pid != target_pid) {
        return 0;  // filter out if target PID is set and doesn't match
    }

    const char *fn_ptr = (const char *)ctx->args[1];  // filename pointer (2nd arg of openat)
    char filename[256];
    if (fn_ptr) {
        bpf_probe_read_user_str(filename, sizeof(filename), fn_ptr);  // copy filename from user memory
    } else {
        filename[0] = '\0';
    }
    // bpf_printk("SSE PID %d calling openat: %s\n", pid, filename);
    if (is_csp_file(filename)) {
        __u8 one = 1;
        bpf_map_update_elem(&open_scratch, &pid, &one, BPF_ANY);
        bpf_printk("CSP PID %d calling openat: %s\n", pid, filename);
    }
    
    return 0;
}

// 2) On exit, if we saw a match, record (pid,fd) in csp_fds
SEC("tracepoint/syscalls/sys_exit_openat")
int trace_exit_openat(struct trace_event_raw_sys_exit *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u8 *flag = bpf_map_lookup_elem(&open_scratch, &pid);
    if (!flag) return 0;

    int fd = ctx->ret;
    if (fd >= 0) {
        u64 key = ((u64)pid << 32) | (u32)fd;
        u8 one = 1;
        bpf_map_update_elem(&csp_fds, &key, &one, BPF_ANY);
    }
    bpf_map_delete_elem(&open_scratch, &pid);
    return 0;
}

// 3) Trace reads only on CSP FDs
SEC("tracepoint/syscalls/sys_enter_read")
int trace_enter_read(struct trace_event_raw_sys_enter *ctx) {
    __u64 tg = bpf_get_current_pid_tgid();
    __u32 pid = tg >> 32;
    int fd  = (int)ctx->args[0];
    __u64 key = (tg & 0xffffffff00000000ULL) | (u32)fd;
    if (!bpf_map_lookup_elem(&csp_fds, &key)) return 0;

    size_t cnt = (size_t)ctx->args[2];
    bpf_printk("CSP READ pid=%d fd=%d cnt=%zu\n", pid, fd, cnt);
    return 0;
}

// 4) Trace writes only on CSP FDs
SEC("tracepoint/syscalls/sys_enter_write")
int trace_enter_write(struct trace_event_raw_sys_enter *ctx) {
    __u64 tg = bpf_get_current_pid_tgid();
    __u32 pid = tg >> 32;
    int fd  = (int)ctx->args[0];
    __u64 key = (tg & 0xffffffff00000000ULL) | (u32)fd;
    if (!bpf_map_lookup_elem(&csp_fds, &key)) return 0;

    size_t cnt = (size_t)ctx->args[2];
    bpf_printk("CSP WRITE pid=%d fd=%d cnt=%zu\n", pid, fd, cnt);
    return 0;
}

// 5) Trace deletes only if the path sits under the CSP folder
SEC("tracepoint/syscalls/sys_enter_unlinkat")
int trace_enter_unlinkat(struct trace_event_raw_sys_enter *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    const char *path = (const char*)ctx->args[1];
    if (!path) return 0;

    char buf[128];
    bpf_probe_read_user_str(buf, sizeof(buf), path);
    if (!is_csp_file(buf)) return 0;

    bpf_printk("CSP UNLINK pid=%d path=%s\n", pid, buf);
    return 0;
}
