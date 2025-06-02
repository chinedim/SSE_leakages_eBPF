#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

const volatile pid_t target_pid = 0;  // Optionally set this to the SSE process PID to filter (0 = no filter)

char LICENSE[] SEC("license") = "GPL";

// Tracepoint: sys_enter_openat (file open)
SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;               // extract PID
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
    bpf_printk("SSE PID %d calling openat: %s\n", pid, filename);
    return 0;
}

// Tracepoint: sys_enter_read (file read)
SEC("tracepoint/syscalls/sys_enter_read")
int handle_read(struct trace_event_raw_sys_enter *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    if (target_pid != 0 && pid != target_pid) {
        return 0;
    }
    int fd = (int)ctx->args[0];            // file descriptor being read
    size_t count = (size_t)ctx->args[2];   // number of bytes requested
    bpf_printk("SSE PID %d reading fd=%d, count=%zu bytes\n", pid, fd, count);
    return 0;
}

// Tracepoint: sys_enter_write (file write)
SEC("tracepoint/syscalls/sys_enter_write")
int handle_write(struct trace_event_raw_sys_enter *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    if (target_pid != 0 && pid != target_pid) {
        return 0;
    }
    int fd = (int)ctx->args[0];            // file descriptor being written
    size_t count = (size_t)ctx->args[2];   // number of bytes to write
    bpf_printk("SSE PID %d writing fd=%d, count=%zu bytes\n", pid, fd, count);
    return 0;
}

// Tracepoint: sys_enter_unlinkat (file delete)
SEC("tracepoint/syscalls/sys_enter_unlinkat")
int handle_unlinkat(struct trace_event_raw_sys_enter *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    if (target_pid != 0 && pid != target_pid) {
        return 0;
    }
    const char *fn_ptr = (const char *)ctx->args[1];  // pathname pointer (2nd arg of unlinkat)
    char filename[256];
    if (fn_ptr) {
        bpf_probe_read_user_str(filename, sizeof(filename), fn_ptr);
    } else {
        filename[0] = '\0';
    }
    bpf_printk("SSE PID %d unlinking file: %s\n", pid, filename);
    return 0;
}

