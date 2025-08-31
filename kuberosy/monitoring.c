//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <sys/syscall.h>
#include <errno.h>
#include "syscall_map.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define	EPERM 1
#define MAX_ENTRIES 3
#define AF_INET 2
#define MAX_PATH_LEN 16
#define MAX_DES_LEN 16
#define SYS_ENTER_TAIL 1

struct event {
    u32 pid;
	u8 comm[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

// Force emitting struct event into the ELF.
const struct event *unused __attribute__((unused));

struct pid_mount_ns {
    u64 mountns;
    u64 pidns;
};

struct pid_syscall_args {
    struct pid_mount_ns namespace;
    u32 syscall;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u8[16]);
    __type(value, __u32);
    __uint(max_entries, 64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} containerID_PID_map SEC(".maps");

/////////////////////////////////////////////////

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct pid_mount_ns);
    __type(value, __u64[9]);
    __uint(max_entries, 64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} policy_map SEC(".maps");

/////////////////////////////////////////////////

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct pid_mount_ns);
    __type(value, __u32[64]);
    __uint(max_entries, 1024);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} lsm_to_syscall SEC(".maps");

/////////////////////////////////////////////////

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct pid_syscall_args);
    __type(value, __u8[MAX_PATH_LEN * 16]);
    __uint(max_entries, 16);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} policy_params_bprm_check SEC(".maps");

/////////////////////////////////////////////////

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct pid_syscall_args);
    __type(value, __u32[16]);
    __uint(max_entries, 64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} policy_params_task_alloc SEC(".maps");

/////////////////////////////////////////////////

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct pid_syscall_args);
    __type(value, __u8[16]);
    __uint(max_entries, 64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} policy_params_ptrace_access SEC(".maps");

/////////////////////////////////////////////////

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct pid_syscall_args);
    __type(value, __u32[16]);
    __uint(max_entries, 64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} policy_params_file_mprotect SEC(".maps");

/////////////////////////////////////////////////

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct pid_syscall_args);
    __type(value, __u32[24]);
    __uint(max_entries, 64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} policy_params_fix_setgid SEC(".maps");

/////////////////////////////////////////////////

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct pid_syscall_args);
    __type(value, __u32[24]);
    __uint(max_entries, 64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} policy_params_fix_setuid SEC(".maps");

/////////////////////////////////////////////////

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct pid_syscall_args);
    __type(value, __u32[24]);
    __uint(max_entries, 64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} policy_params_socket_accept SEC(".maps");

/////////////////////////////////////////////////

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct pid_syscall_args);
    __type(value, __u32[24]);
    __uint(max_entries, 64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} policy_params_socket_listen SEC(".maps");

/////////////////////////////////////////////////

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct pid_syscall_args);
    __type(value, __u32[24]);
    __uint(max_entries, 64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} policy_params_socket_recvmsg SEC(".maps");

/////////////////////////////////////////////////

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct pid_syscall_args);
    __type(value, __u32[16]);
    __uint(max_entries, 64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} policy_params_socket_create SEC(".maps");

/////////////////////////////////////////////////

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct pid_syscall_args);
    __type(value, char[(MAX_PATH_LEN + 2) * 16]);
    __uint(max_entries, 16);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} policy_params_path_chmod SEC(".maps");

/////////////////////////////////////////////////

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct pid_syscall_args);
    __type(value, __u32[24]);
    __uint(max_entries, 16);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} policy_params_socket_bind SEC(".maps");

/////////////////////////////////////////////////

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct pid_syscall_args);
    __type(value, __u32[24]);
    __uint(max_entries, 16);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} policy_params_socket_connect SEC(".maps");

/////////////////////////////////////////////////

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct pid_mount_ns);
    __type(value, __u32);
    __uint(max_entries, 1024);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} monitoring_map SEC(".maps");

/////////////////////////////////////////////////

u32 lookup_syscall(struct pid_mount_ns ns, u32 lsm){
    u32 *syscall = bpf_map_lookup_elem(&lsm_to_syscall, &ns);
    if(!syscall)
        return 0;
    u32 val = syscall[lsm];
    if(!val)
        return 0;
    return val;
}

u32 lookup_policy(u32 pidns, u32 mntns, u32 syscall){
    struct pid_mount_ns ns;
    ns.pidns = pidns;
    ns.mountns = mntns;
    u64 mask = 1 << (syscall % 64);
    u32 share = syscall / 64;
    if(share > 9 || share < 0)
        return 0;
    if(syscall < 0 || syscall > 547)
        return 0;
    u64 *policy_arr = bpf_map_lookup_elem(&policy_map, &ns);
    if(!policy_arr)
        return 0;
    if(policy_arr[share] & mask)
        return 1;
    return 0;
}

u32 set_syscall_map(u32 pidns, u32 mntns, u32 lsm, u32 syscall_num){
    struct pid_mount_ns ns;
    ns.pidns = pidns;
    ns.mountns = mntns;
    if(!lsm){
        if(syscall_num < 0)
            return 0;
        if(syscall_num > 547)
            return 0;
        u32 lsm = syscall_map[syscall_num];
        if(lsm < 1)
            return 0;
        if(lsm > 26)
            return 0;
    }
    u32 *val = bpf_map_lookup_elem(&lsm_to_syscall, &ns);
    if(!val){ // Namespace struct does not exist yet
        u32 tmp[64];
        for(int i = 0; i < 64; i++)
            tmp[i] = 0;
        if(lsm < 1)
            return 0;
        if(lsm > 26)
            return 0;
        tmp[lsm] = syscall_num;
        bpf_map_update_elem(&lsm_to_syscall, &ns, tmp, BPF_ANY);
        return 0;
    }
    val[lsm] = syscall_num; // Namespace struct exist, updating lsm to syscall mapping
    bpf_map_update_elem(&lsm_to_syscall, &ns, val, BPF_ANY);
    return 0;
}

u32 getMntInum(struct task_struct *task){
    return BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
}

u32 getPidInum(struct task_struct *task) {
  return BPF_CORE_READ(task, nsproxy, pid_ns_for_children, ns.inum);
}


/////////////////////////////////////////////////

// SEC("raw_tracepoint/sys_enter_tail")
// int rtp_sys_enter_tail(struct bpf_raw_tracepoint_args *ctx){ 
//     struct task_struct *task = (struct task_struct *)bpf_get_current_task();
//     if(!task)
//         return 0;
//     u64 id = ctx->args[1];
//     u32 pidns = getPidInum(task);
//     u32 mntns = getMntInum(task);
//     bpf_printk("sys_enter_tail triggered! id : %u, pidns : %u, mntns : %u", id, pidns, mntns);
    
//     set_syscall_map(pidns, mntns, 0, id);

//     return 0;
// }

/////////////////////////////////////////////////

// struct {
//     __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
//     __uint(key_size, sizeof(u32));
// 	__uint(max_entries, 2);
// 	__array(values, u32 (void *));
// } prog_array SEC(".maps") = {
// 	.values = {
// 		[SYS_ENTER_TAIL] = (void *)&rtp_sys_enter_tail,
// 	},
// };

/////////////////////////////////////////////////

SEC("raw_tracepoint/sys_enter")
int rtp_sys_enter(struct bpf_raw_tracepoint_args *ctx){
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if(!task)
        return 0;
    struct pid_mount_ns ns;
    u64 pidns = getPidInum(task);
    u64 mntns = getMntInum(task);
    ns.pidns = pidns;
    ns.mountns = mntns;
    // bpf_printk("namespace is pidns %u", pidns);
    // bpf_printk("namespace is mntns %u", mntns);
    u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
    // bpf_printk("Within sys_enter 1");
    if(!is_container_process)
        return 0;
    // bpf_tail_call(ctx, &prog_array, SYS_ENTER_TAIL);
    u64 id = ctx->args[1];
    set_syscall_map(pidns, mntns, 0, id);
    // bpf_printk("Within sys_enter 2");
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_accept")
int sys_accept_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("accept syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_accept4")
int sys_accept4_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("accept4 syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_access")
int sys_access_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("access syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_acct")
int sys_acct_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("acct syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_add_key")
int sys_add_key_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("add_key syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_adjtimex")
int sys_adjtimex_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("adjtimex syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_alarm")
int sys_alarm_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("alarm syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_arch_prctl")
int sys_arch_prctl_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("arch_prctl syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_bind")
int sys_bind_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("bind syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_bpf")
int sys_bpf_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("bpf syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_brk")
int sys_brk_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("brk syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_capget")
int sys_capget_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("capget syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_capset")
int sys_capset_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("capset syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_chdir")
int sys_chdir_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("chdir syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_chmod")
int sys_chmod_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("chmod syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_chown")
int sys_chown_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("chown syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_chroot")
int sys_chroot_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("chroot syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_clock_adjtime")
int sys_clock_adjtime_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("clock_adjtime syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_clock_getres")
int sys_clock_getres_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("clock_getres syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_clock_gettime")
int sys_clock_gettime_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("clock_gettime syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_clock_nanosleep")
int sys_clock_nanosleep_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("clock_nanosleep syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_clock_settime")
int sys_clock_settime_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("clock_settime syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_clone")
int sys_clone_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("clone syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_clone3")
int sys_clone3_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("clone3 syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_close")
int sys_close_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("close syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_close_range")
int sys_close_range_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("close_range syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int sys_connect_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("connect syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_copy_file_range")
int sys_copy_file_range_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("copy_file_range syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_creat")
int sys_creat_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("creat syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_delete_module")
int sys_delete_module_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("delete_module syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_dup")
int sys_dup_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("dup syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_dup2")
int sys_dup2_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("dup2 syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_dup3")
int sys_dup3_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("dup3 syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_epoll_create")
int sys_epoll_create_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("epoll_create syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_epoll_create1")
int sys_epoll_create1_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("epoll_create1 syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_epoll_ctl")
int sys_epoll_ctl_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("epoll_ctl syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_epoll_pwait")
int sys_epoll_pwait_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("epoll_pwait syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_epoll_pwait2")
int sys_epoll_pwait2_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("epoll_pwait2 syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_epoll_wait")
int sys_epoll_wait_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("epoll_wait syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_eventfd")
int sys_eventfd_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("eventfd syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_eventfd2")
int sys_eventfd2_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("eventfd2 syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int sys_execve_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("execve syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_execveat")
int sys_execveat_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("execveat syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_exit")
int sys_exit_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("exit syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_exit_group")
int sys_exit_group_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("exit_group syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_faccessat")
int sys_faccessat_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("faccessat syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_faccessat2")
int sys_faccessat2_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("faccessat2 syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_fadvise64")
int sys_fadvise64_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("fadvise64 syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_fallocate")
int sys_fallocate_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("fallocate syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_fanotify_init")
int sys_fanotify_init_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("fanotify_init syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_fanotify_mark")
int sys_fanotify_mark_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("fanotify_mark syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_fchdir")
int sys_fchdir_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("fchdir syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_fchmod")
int sys_fchmod_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("fchmod syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_fchmodat")
int sys_fchmodat_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("fchmodat syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_fchown")
int sys_fchown_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("fchown syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_fchownat")
int sys_fchownat_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("fchownat syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_fcntl")
int sys_fcntl_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("fcntl syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_fdatasync")
int sys_fdatasync_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("fdatasync syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_fgetxattr")
int sys_fgetxattr_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("fgetxattr syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_finit_module")
int sys_finit_module_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("finit_module syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_flistxattr")
int sys_flistxattr_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("flistxattr syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_flock")
int sys_flock_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("flock syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_fork")
int sys_fork_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("fork syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_fremovexattr")
int sys_fremovexattr_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("fremovexattr syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_fsconfig")
int sys_fsconfig_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("fsconfig syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_fsetxattr")
int sys_fsetxattr_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("fsetxattr syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_fsmount")
int sys_fsmount_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("fsmount syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_fsopen")
int sys_fsopen_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("fsopen syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_fspick")
int sys_fspick_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("fspick syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_fstatfs")
int sys_fstatfs_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("fstatfs syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_fsync")
int sys_fsync_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("fsync syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_ftruncate")
int sys_ftruncate_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("ftruncate syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_futex")
int sys_futex_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("futex syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_futex_waitv")
int sys_futex_waitv_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("futex_waitv syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_futimesat")
int sys_futimesat_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("futimesat syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_getcpu")
int sys_getcpu_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("getcpu syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_getcwd")
int sys_getcwd_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("getcwd syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_getdents")
int sys_getdents_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("getdents syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_getdents64")
int sys_getdents64_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("getdents64 syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_getegid")
int sys_getegid_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("getegid syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_geteuid")
int sys_geteuid_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("geteuid syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_getgid")
int sys_getgid_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("getgid syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_getgroups")
int sys_getgroups_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("getgroups syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_getitimer")
int sys_getitimer_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("getitimer syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_get_mempolicy")
int sys_get_mempolicy_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("get_mempolicy syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_getpeername")
int sys_getpeername_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("getpeername syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_getpgid")
int sys_getpgid_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("getpgid syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_getpgrp")
int sys_getpgrp_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("getpgrp syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_getpid")
int sys_getpid_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("getpid syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_getppid")
int sys_getppid_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("getppid syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_getpriority")
int sys_getpriority_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("getpriority syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_getrandom")
int sys_getrandom_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("getrandom syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_getresgid")
int sys_getresgid_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("getresgid syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_getresuid")
int sys_getresuid_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("getresuid syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_getrlimit")
int sys_getrlimit_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("getrlimit syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_get_robust_list")
int sys_get_robust_list_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("get_robust_list syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_getrusage")
int sys_getrusage_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("getrusage syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_getsid")
int sys_getsid_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("getsid syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_getsockname")
int sys_getsockname_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("getsockname syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_getsockopt")
int sys_getsockopt_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("getsockopt syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_gettid")
int sys_gettid_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("gettid syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_gettimeofday")
int sys_gettimeofday_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("gettimeofday syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_getuid")
int sys_getuid_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("getuid syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_getxattr")
int sys_getxattr_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("getxattr syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_init_module")
int sys_init_module_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("init_module syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_inotify_add_watch")
int sys_inotify_add_watch_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("inotify_add_watch syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_inotify_init")
int sys_inotify_init_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("inotify_init syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_inotify_init1")
int sys_inotify_init1_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("inotify_init1 syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_inotify_rm_watch")
int sys_inotify_rm_watch_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("inotify_rm_watch syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_io_cancel")
int sys_io_cancel_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("io_cancel syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_ioctl")
int sys_ioctl_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("ioctl syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_io_destroy")
int sys_io_destroy_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("io_destroy syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_io_getevents")
int sys_io_getevents_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("io_getevents syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_ioperm")
int sys_ioperm_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("ioperm syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_io_pgetevents")
int sys_io_pgetevents_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("io_pgetevents syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_iopl")
int sys_iopl_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("iopl syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_ioprio_get")
int sys_ioprio_get_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("ioprio_get syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_ioprio_set")
int sys_ioprio_set_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("ioprio_set syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_io_setup")
int sys_io_setup_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("io_setup syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_io_submit")
int sys_io_submit_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("io_submit syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_io_uring_enter")
int sys_io_uring_enter_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("io_uring_enter syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_io_uring_register")
int sys_io_uring_register_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("io_uring_register syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_io_uring_setup")
int sys_io_uring_setup_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("io_uring_setup syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_kcmp")
int sys_kcmp_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("kcmp syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_kexec_file_load")
int sys_kexec_file_load_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("kexec_file_load syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_kexec_load")
int sys_kexec_load_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("kexec_load syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_keyctl")
int sys_keyctl_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("keyctl syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_kill")
int sys_kill_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("kill syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_landlock_add_rule")
int sys_landlock_add_rule_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("landlock_add_rule syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_landlock_create_ruleset")
int sys_landlock_create_ruleset_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("landlock_create_ruleset syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_landlock_restrict_self")
int sys_landlock_restrict_self_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("landlock_restrict_self syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_lchown")
int sys_lchown_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("lchown syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_lgetxattr")
int sys_lgetxattr_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("lgetxattr syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_link")
int sys_link_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("link syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_linkat")
int sys_linkat_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("linkat syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_listen")
int sys_listen_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("listen syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_listxattr")
int sys_listxattr_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("listxattr syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_llistxattr")
int sys_llistxattr_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("llistxattr syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_lremovexattr")
int sys_lremovexattr_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("lremovexattr syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_lseek")
int sys_lseek_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("lseek syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_lsetxattr")
int sys_lsetxattr_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("lsetxattr syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_madvise")
int sys_madvise_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("madvise syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_mbind")
int sys_mbind_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("mbind syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_membarrier")
int sys_membarrier_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("membarrier syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_memfd_create")
int sys_memfd_create_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("memfd_create syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_memfd_secret")
int sys_memfd_secret_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("memfd_secret syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_migrate_pages")
int sys_migrate_pages_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("migrate_pages syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_mincore")
int sys_mincore_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("mincore syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_mkdir")
int sys_mkdir_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("mkdir syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_mkdirat")
int sys_mkdirat_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("mkdirat syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_mknod")
int sys_mknod_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("mknod syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_mknodat")
int sys_mknodat_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("mknodat syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_mlock")
int sys_mlock_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("mlock syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_mlock2")
int sys_mlock2_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("mlock2 syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_mlockall")
int sys_mlockall_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("mlockall syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_mmap")
int sys_mmap_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("mmap syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_modify_ldt")
int sys_modify_ldt_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("modify_ldt syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_mount")
int sys_mount_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("mount syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_mount_setattr")
int sys_mount_setattr_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("mount_setattr syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_move_mount")
int sys_move_mount_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("move_mount syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_move_pages")
int sys_move_pages_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("move_pages syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_mprotect")
int sys_mprotect_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("mprotect syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_mq_getsetattr")
int sys_mq_getsetattr_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("mq_getsetattr syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_mq_notify")
int sys_mq_notify_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("mq_notify syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_mq_open")
int sys_mq_open_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("mq_open syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_mq_timedreceive")
int sys_mq_timedreceive_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("mq_timedreceive syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_mq_timedsend")
int sys_mq_timedsend_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("mq_timedsend syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_mq_unlink")
int sys_mq_unlink_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("mq_unlink syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_mremap")
int sys_mremap_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("mremap syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_msgctl")
int sys_msgctl_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("msgctl syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_msgget")
int sys_msgget_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("msgget syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_msgrcv")
int sys_msgrcv_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("msgrcv syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_msgsnd")
int sys_msgsnd_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("msgsnd syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_msync")
int sys_msync_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("msync syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_munlock")
int sys_munlock_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("munlock syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_munlockall")
int sys_munlockall_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("munlockall syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_munmap")
int sys_munmap_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("munmap syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_name_to_handle_at")
int sys_name_to_handle_at_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("name_to_handle_at syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_nanosleep")
int sys_nanosleep_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("nanosleep syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_newfstat")
int sys_newfstat_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("newfstat syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_newfstatat")
int sys_newfstatat_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("newfstatat syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_newlstat")
int sys_newlstat_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("newlstat syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_newstat")
int sys_newstat_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("newstat syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_newuname")
int sys_newuname_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("newuname syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_open")
int sys_open_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("open syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int sys_openat_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("openat syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat2")
int sys_openat2_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("openat2 syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_open_by_handle_at")
int sys_open_by_handle_at_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("open_by_handle_at syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_open_tree")
int sys_open_tree_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("open_tree syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_pause")
int sys_pause_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("pause syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_perf_event_open")
int sys_perf_event_open_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("perf_event_open syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_personality")
int sys_personality_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("personality syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_pidfd_getfd")
int sys_pidfd_getfd_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("pidfd_getfd syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_pidfd_open")
int sys_pidfd_open_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("pidfd_open syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_pidfd_send_signal")
int sys_pidfd_send_signal_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("pidfd_send_signal syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_pipe")
int sys_pipe_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("pipe syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_pipe2")
int sys_pipe2_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("pipe2 syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_pivot_root")
int sys_pivot_root_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("pivot_root syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_pkey_alloc")
int sys_pkey_alloc_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("pkey_alloc syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_pkey_free")
int sys_pkey_free_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("pkey_free syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_pkey_mprotect")
int sys_pkey_mprotect_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("pkey_mprotect syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_poll")
int sys_poll_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("poll syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_ppoll")
int sys_ppoll_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("ppoll syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_prctl")
int sys_prctl_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("prctl syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_pread64")
int sys_pread64_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("pread64 syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_preadv")
int sys_preadv_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("preadv syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_preadv2")
int sys_preadv2_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("preadv2 syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_prlimit64")
int sys_prlimit64_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("prlimit64 syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_process_madvise")
int sys_process_madvise_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("process_madvise syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_process_mrelease")
int sys_process_mrelease_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("process_mrelease syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_process_vm_readv")
int sys_process_vm_readv_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("process_vm_readv syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_process_vm_writev")
int sys_process_vm_writev_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("process_vm_writev syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_pselect6")
int sys_pselect6_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("pselect6 syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_ptrace")
int sys_ptrace_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("ptrace syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_pwrite64")
int sys_pwrite64_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("pwrite64 syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_pwritev")
int sys_pwritev_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("pwritev syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_pwritev2")
int sys_pwritev2_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("pwritev2 syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_quotactl")
int sys_quotactl_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("quotactl syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_quotactl_fd")
int sys_quotactl_fd_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("quotactl_fd syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_read")
int sys_read_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("read syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_readahead")
int sys_readahead_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("readahead syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_readlink")
int sys_readlink_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("readlink syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_readlinkat")
int sys_readlinkat_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("readlinkat syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_readv")
int sys_readv_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("readv syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_reboot")
int sys_reboot_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("reboot syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_recvfrom")
int sys_recvfrom_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("recvfrom syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_recvmmsg")
int sys_recvmmsg_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("recvmmsg syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_recvmsg")
int sys_recvmsg_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("recvmsg syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_remap_file_pages")
int sys_remap_file_pages_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("remap_file_pages syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_removexattr")
int sys_removexattr_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("removexattr syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_rename")
int sys_rename_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("rename syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_renameat")
int sys_renameat_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("renameat syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_renameat2")
int sys_renameat2_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("renameat2 syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_request_key")
int sys_request_key_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("request_key syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_restart_syscall")
int sys_restart_syscall_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("restart_syscall syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_rmdir")
int sys_rmdir_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("rmdir syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_rseq")
int sys_rseq_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("rseq syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_rt_sigaction")
int sys_rt_sigaction_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("rt_sigaction syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_rt_sigpending")
int sys_rt_sigpending_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("rt_sigpending syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_rt_sigprocmask")
int sys_rt_sigprocmask_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("rt_sigprocmask syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_rt_sigqueueinfo")
int sys_rt_sigqueueinfo_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("rt_sigqueueinfo syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_rt_sigreturn")
int sys_rt_sigreturn_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("rt_sigreturn syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_rt_sigsuspend")
int sys_rt_sigsuspend_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("rt_sigsuspend syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_rt_sigtimedwait")
int sys_rt_sigtimedwait_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("rt_sigtimedwait syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_rt_tgsigqueueinfo")
int sys_rt_tgsigqueueinfo_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("rt_tgsigqueueinfo syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_sched_getaffinity")
int sys_sched_getaffinity_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("sched_getaffinity syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_sched_getattr")
int sys_sched_getattr_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("sched_getattr syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_sched_getparam")
int sys_sched_getparam_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("sched_getparam syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_sched_get_priority_max")
int sys_sched_get_priority_max_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("sched_get_priority_max syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_sched_get_priority_min")
int sys_sched_get_priority_min_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("sched_get_priority_min syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_sched_getscheduler")
int sys_sched_getscheduler_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("sched_getscheduler syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_sched_rr_get_interval")
int sys_sched_rr_get_interval_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("sched_rr_get_interval syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_sched_setaffinity")
int sys_sched_setaffinity_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("sched_setaffinity syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_sched_setattr")
int sys_sched_setattr_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("sched_setattr syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_sched_setparam")
int sys_sched_setparam_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("sched_setparam syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_sched_setscheduler")
int sys_sched_setscheduler_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("sched_setscheduler syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_sched_yield")
int sys_sched_yield_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("sched_yield syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_seccomp")
int sys_seccomp_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("seccomp syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_select")
int sys_select_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("select syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_semctl")
int sys_semctl_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("semctl syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_semget")
int sys_semget_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("semget syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_semop")
int sys_semop_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("semop syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_semtimedop")
int sys_semtimedop_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("semtimedop syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendfile64")
int sys_sendfile64_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("sendfile64 syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendmmsg")
int sys_sendmmsg_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("sendmmsg syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendmsg")
int sys_sendmsg_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("sendmsg syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendto")
int sys_sendto_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("sendto syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_setdomainname")
int sys_setdomainname_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("setdomainname syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_setfsgid")
int sys_setfsgid_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("setfsgid syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_setfsuid")
int sys_setfsuid_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("setfsuid syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_setgid")
int sys_setgid_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("setgid syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_setgroups")
int sys_setgroups_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("setgroups syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_sethostname")
int sys_sethostname_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("sethostname syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_setitimer")
int sys_setitimer_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("setitimer syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_set_mempolicy")
int sys_set_mempolicy_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("set_mempolicy syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_set_mempolicy_home_node")
int sys_set_mempolicy_home_node_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("set_mempolicy_home_node syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_setns")
int sys_setns_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("setns syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_setpgid")
int sys_setpgid_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("setpgid syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_setpriority")
int sys_setpriority_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("setpriority syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_setregid")
int sys_setregid_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("setregid syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_setresgid")
int sys_setresgid_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("setresgid syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_setresuid")
int sys_setresuid_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("setresuid syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_setreuid")
int sys_setreuid_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("setreuid syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_setrlimit")
int sys_setrlimit_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("setrlimit syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_set_robust_list")
int sys_set_robust_list_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("set_robust_list syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_setsid")
int sys_setsid_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("setsid syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_setsockopt")
int sys_setsockopt_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("setsockopt syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_set_tid_address")
int sys_set_tid_address_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("set_tid_address syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_settimeofday")
int sys_settimeofday_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("settimeofday syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_setuid")
int sys_setuid_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("setuid syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_setxattr")
int sys_setxattr_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("setxattr syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_shmat")
int sys_shmat_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("shmat syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_shmctl")
int sys_shmctl_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("shmctl syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_shmdt")
int sys_shmdt_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("shmdt syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_shmget")
int sys_shmget_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("shmget syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_shutdown")
int sys_shutdown_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("shutdown syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_sigaltstack")
int sys_sigaltstack_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("sigaltstack syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_signalfd")
int sys_signalfd_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("signalfd syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_signalfd4")
int sys_signalfd4_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("signalfd4 syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_socket")
int sys_socket_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("socket syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_socketpair")
int sys_socketpair_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("socketpair syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_splice")
int sys_splice_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("splice syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_statfs")
int sys_statfs_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("statfs syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_statx")
int sys_statx_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("statx syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_swapoff")
int sys_swapoff_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("swapoff syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_swapon")
int sys_swapon_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("swapon syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_symlink")
int sys_symlink_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("symlink syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_symlinkat")
int sys_symlinkat_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("symlinkat syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_sync")
int sys_sync_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("sync syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_sync_file_range")
int sys_sync_file_range_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("sync_file_range syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_syncfs")
int sys_syncfs_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("syncfs syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_sysfs")
int sys_sysfs_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("sysfs syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_sysinfo")
int sys_sysinfo_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("sysinfo syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_syslog")
int sys_syslog_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("syslog syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_tee")
int sys_tee_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("tee syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_tgkill")
int sys_tgkill_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("tgkill syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_time")
int sys_time_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("time syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_timer_create")
int sys_timer_create_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("timer_create syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_timer_delete")
int sys_timer_delete_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("timer_delete syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_timerfd_create")
int sys_timerfd_create_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("timerfd_create syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_timerfd_gettime")
int sys_timerfd_gettime_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("timerfd_gettime syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_timerfd_settime")
int sys_timerfd_settime_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("timerfd_settime syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_timer_getoverrun")
int sys_timer_getoverrun_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("timer_getoverrun syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_timer_gettime")
int sys_timer_gettime_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("timer_gettime syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_timer_settime")
int sys_timer_settime_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("timer_settime syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_times")
int sys_times_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("times syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_tkill")
int sys_tkill_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("tkill syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_truncate")
int sys_truncate_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("truncate syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_umask")
int sys_umask_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("umask syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_umount")
int sys_umount_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("umount syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_unlink")
int sys_unlink_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("unlink syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int sys_unlinkat_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("unlinkat syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_unshare")
int sys_unshare_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("unshare syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_userfaultfd")
int sys_userfaultfd_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("userfaultfd syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_ustat")
int sys_ustat_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("ustat syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_utime")
int sys_utime_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("utime syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_utimensat")
int sys_utimensat_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("utimensat syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_utimes")
int sys_utimes_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("utimes syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_vfork")
int sys_vfork_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("vfork syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_vhangup")
int sys_vhangup_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("vhangup syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_vmsplice")
int sys_vmsplice_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("vmsplice syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_wait4")
int sys_wait4_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("wait4 syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_waitid")
int sys_waitid_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("waitid syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int sys_write_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("write syscall triggered for pidns %u", pidns);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_writev")
int sys_writev_callback(struct trace_event_raw_sys_enter* ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u8 comm[16] = {0};
	bpf_get_current_comm(comm, 16);
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	if(!task)
		return 0;
	struct pid_mount_ns ns;
	u32 pidns = getPidInum(task);
	u32 mntns = getMntInum(task);
	ns.pidns = pidns;
	ns.mountns = mntns;
	u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
	if(!is_container_process)
		return 0;
	bpf_printk("writev syscall triggered for pidns %u", pidns);
	return 0;
}






/*mmap*/
/*mprotect*/
/*pread64*/
/*pwrite64*/
/*readv*/
/*writev*/
/*shmat*/
/*sendfile*/
/*socket*/
/*connect*/
/*accept*/
/*sendto*/
/*recvfrom*/
/*sendmsg*/
/*recvmsg*/
/*shutdown*/
/*bind*/
/*listen*/
/*getpeername*/
/*socketpair*/
/*setsockopt*/
/*clone*/
/*fork*/
/*vfork*/
/*execve*/
/*fcntl*/
/*ftruncate*/
/*rename*/
/*mkdir*/
/*rmdir*/
/*creat*/
/*link*/
/*unlink*/
/*symlink*/
/*chmod*/
/*fchmod*/
/*chown*/
/*fchown*/
/*lchown*/
/*ptrace*/
/*syslog*/
/*setuid*/
/*setgid*/
/*setpgid*/
/*getpgrp*/
/*setreuid*/
/*setregid*/
/*setgroups*/
/*setresuid*/
/*setresgid*/
/*getsid*/
/*capget*/
/*capset*/
/*mknod*/
/*ustat*/
/*statfs*/
/*fstatfs*/
/*pivot_root*/
/*chroot*/
/*settimeofday*/
/*swapon*/
/*swapoff*/
/*acct*/
/*quotactl*/
/*io_setup*/
/*remap_file_pages*/
/*clock_settime*/
/*inotify_add_watch*/
/*openat*/
/*mkdirat*/
/*fchownat*/
/*renameat*/
/*linkat*/
/*symlinkat*/
/*fchmodat*/
/*unshare*/
/*fallocate*/
/*accept4*/
/*preadv*/
/*pwritev*/
/*recvmmsg*/
/*fanotify_mark*/
/*open_by_handle_at*/
/*sendmmsg*/
/*setns*/
/*renameat2*/
/*execveat*/
/*copy_file_range*/
/*preadv2*/
/*pwritev2*/
/*pkey_mprotect*/
/*io_uring_setup*/
/*move_mount*/
/*fsconfig*/
/*fsmount*/




/*
    LSM Hooks
        task_alloc
        bprm_check_security
        ptrace_access_check
        path_chmod
        file_mprotect
        task_fix_setgid
        task_fix_setuid
        socket_accept
        sock_bind
        sock_connect
        socket_listen
        socket_recvmsg
        sock_create
*/

// SEC("lsm/file_permission")
// int BPF_PROG(file_permission, struct file *file, int mask){
//     u32 pid = bpf_get_current_pid_tgid() >> 32;
//     u8 comm[16] = {0};
//     bpf_get_current_comm(comm, 16);
//     struct task_struct *task = (struct task_struct*)bpf_get_current_task();
//     if(!task)
//         return 0;
//     struct pid_mount_ns ns;
//     u32 pidns = getPidInum(task);
//     u32 mntns = getMntInum(task);
//     ns.pidns = pidns;
//     ns.mountns = mntns;
//     u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
//     if(!is_container_process)
//         return 0;
//     u32 syscall = lookup_syscall(ns, FILE_PERMISSION); //For each name space there is only one syscall associated with it?
    
//     u32 init_failed = set_syscall_map(pidns, mntns, FILE_PERMISSION, 0);
//     if(init_failed)
//         return 0;

//     bpf_printk("file_permission triggered with syscall number %d and comm %s", syscall, comm);
        
//     u32 policy = lookup_policy(pidns, mntns, syscall);
//     if(!policy){
//         bpf_printk("file_permission triggered! policy allowed");
//         return 0;
//     }

//     struct event *new_event = NULL;
//     new_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
//     if (new_event == NULL) {
//         return 0;
//     }
//     new_event->pid = pid;
//     for (u8 i = 0 ; i < 16 ; i++) new_event->comm[i] = comm[i];
//     bpf_ringbuf_submit(new_event, 0);
//     return 0;
// }

// SEC("lsm/task_alloc")
// int BPF_PROG(task_alloc, struct task_struct *task, unsigned long clone_flags, int ret){
//     if (ret != 0)
//         return ret;

//     u8 comm[16] = {0};
//     bpf_get_current_comm(comm, 16);
//     struct task_struct *process_task = (struct task_struct*)bpf_get_current_task();
//     if(!process_task)
//         return 0;
//     struct pid_mount_ns ns;
//     u32 pidns = getPidInum(process_task);
//     u32 mntns = getMntInum(process_task);
//     ns.pidns = pidns;
//     ns.mountns = mntns;
//     u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
//     if(!is_container_process)
//         return 0;
//     u32 syscall = lookup_syscall(ns, TASK_ALLOC);
    
//     u32 init_failed = set_syscall_map(pidns, mntns, TASK_ALLOC, 0);
//     if(init_failed)
//         return 0;
//     bpf_printk("task_alloc LSM Hook triggered! clone_flags = %u", clone_flags);
        
//     u32 policy = lookup_policy(pidns, mntns, syscall);
//     if(!policy){
//         bpf_printk("task_alloc triggered! policy allowed");
//         return 0;
//     }
//     bpf_printk("task_alloc triggered! policy blocked");
//     struct pid_syscall_args key;
//     key.syscall = syscall;
//     key.namespace = ns;
//     u32 *flag = bpf_map_lookup_elem(&policy_params_task_alloc, &key);
//     if(flag){
//         for(int i = 0; i < 16; i++){
//             if(flag[i] == 0)
//                 break;
//             if(flag[i] == clone_flags){
//                 return 0;
//             }
//         }
//     }
//     u32 pid = bpf_get_current_pid_tgid() >> 32;
//     bpf_printk("lsm: detected PID: %d, comm: %s - blocked PID", pid, comm);
//     struct event *new_event = NULL;
//     new_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
//     if (new_event == NULL) {
//         return 0;
//     }
//     new_event->pid = pid;
//     for (u8 i = 0 ; i < 16 ; i++) new_event->comm[i] = comm[i];
//     bpf_ringbuf_submit(new_event, 0);

//     return -EPERM;
// }

// SEC("lsm/bprm_check_security")
// int BPF_PROG(bprm_check, struct linux_binprm *bprm, int ret){
//     if (ret != 0)
//         return ret;
//     u8 comm[16] = {0};
//     bpf_get_current_comm(comm, 16);
//     struct task_struct *task = (struct task_struct*)bpf_get_current_task();
//     if(!task)
//         return 0;
//     struct pid_mount_ns ns;
//     u32 pidns = getPidInum(task);
//     u32 mntns = getMntInum(task);
//     ns.pidns = pidns;
//     ns.mountns = mntns;
//     u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
//     if(!is_container_process)
//         return 0;
//     u32 syscall = lookup_syscall(ns, BPRM_CHECK_SECURITY);
    
//     u32 init_failed = set_syscall_map(pidns, mntns, BPRM_CHECK_SECURITY, 0);
//     if(init_failed)
//         return 0;
    
//     u8 filename[MAX_PATH_LEN];
//     bpf_core_read_str(&filename, sizeof(filename), bprm->filename);
//     bpf_printk("bprm_check_security LSM Hook triggered! filename = %s", filename);

//     u32 policy = lookup_policy(pidns, mntns, syscall);
//     if(!policy)
//         return 0;
    
//     struct pid_syscall_args key;
//     key.syscall = syscall;
//     key.namespace = ns;
//     // bool is_empty = false;
//     u32 is_allowed = 1;
//     char *filepath = bpf_map_lookup_elem(&policy_params_bprm_check, &key);
//     if(filepath){
//         for(int i = 0; i < 16; i++){
//             if(filepath[i * MAX_PATH_LEN] != '/')
//                 break;
//             is_allowed = 1;
//             for(int j = 0; j < MAX_PATH_LEN; j++){
//                 // if(!filepath || !(bprm->filename)){
//                 //     if(!j)
//                 //         is_empty = true;
//                 //     break;
//                 // }
//                 if(filepath[i * MAX_PATH_LEN + j] == '\0'){
//                     is_allowed = 0;
//                     // if(!j)
//                     //     is_empty = true;
//                     break;
//                 }
//                 if(filename[j] == '\0'){
//                     // if(!j)
//                     //     is_empty = true;
//                     // is_allowed = 0;
//                     break;
//                 }
//                 if(filepath[i * MAX_PATH_LEN + j] != filename[j]){
//                     is_allowed = 0;
//                     break;
//                 }
//             }
//             if(is_allowed)
//                 return 0;
//         }
//     }
        
    
    
//     if (is_allowed) {
//         u32 pid = bpf_get_current_pid_tgid() >> 32;
//         bpf_printk("lsm: detected PID: %d, comm: %s - blocked PID", pid, comm);
        
//         struct event *new_event = NULL;
//         new_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
//         if (new_event == NULL) {
//             return 0;
//         }
//         new_event->pid = pid;
//         for (u8 i = 0 ; i < 16 ; i++) new_event->comm[i] = comm[i];
//         bpf_ringbuf_submit(new_event, 0);

//         return -EPERM;
//     }
    
//     return 0;
// }

// SEC("lsm/ptrace_access_check")
// int BPF_PROG(ptrace_check, struct task_struct *child, unsigned int mode, int ret){
//     if (ret != 0)
//         return ret;

//     u8 comm[16] = {0};
//     bpf_get_current_comm(comm, 16);
//     struct task_struct *task = (struct task_struct*)bpf_get_current_task();
//     if(!task)
//         return 0;
//     struct pid_mount_ns ns;
//     u32 pidns = getPidInum(task);
//     u32 mntns = getMntInum(task);
//     ns.pidns = pidns;
//     ns.mountns = mntns;
//     u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
//     if(!is_container_process)
//         return 0;
//     u32 syscall = lookup_syscall(ns, PTRACE_ACCESS_CHECK);
    
//     u32 init_failed = set_syscall_map(pidns, mntns, PTRACE_ACCESS_CHECK, 0);
//     if(init_failed)
//         return 0;
//     bpf_printk("ptrace_access_check LSM Hook triggered! mode = %u", mode);

//     u32 policy = lookup_policy(pidns, mntns, syscall);
//     if(!policy)
//         return 0;

//     struct pid_syscall_args key;
//     key.syscall = syscall;
//     key.namespace = ns;
//     u8 *allow_policy = bpf_map_lookup_elem(&policy_params_ptrace_access, &key);
//     if(allow_policy && mode){
//         for(int i = 0; i < 16; i++){
//             if(allow_policy[i] == 0)
//                 break;
//             if((allow_policy[i] & mode) == mode){
//                 return 0;
//             }
//         }
//     }
//     u32 pid = bpf_get_current_pid_tgid() >> 32;
//     bpf_printk("lsm: detected PID: %d, comm: %s - blocked PID", pid, comm);
//     // Create event, we are going to send this over to userspace.
    
//     struct event *new_event = NULL;
//     new_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
//     if (new_event == NULL) {
//         return 0;
//     }
//     new_event->pid = pid;
//     for (u8 i = 0 ; i < 16 ; i++) new_event->comm[i] = comm[i];
//     bpf_ringbuf_submit(new_event, 0);

//     return -EPERM;
    
//     return 0;
// }

// SEC("lsm/path_chmod")
// int BPF_PROG(path_chmod, struct path *path, umode_t mode, int ret){
//     if (ret != 0)
//         return ret;

//     u8 comm[16] = {0};
//     bpf_get_current_comm(comm, 16);
//     struct task_struct *task = (struct task_struct*)bpf_get_current_task();
//     if(!task)
//         return 0;
//     struct pid_mount_ns ns;
//     u32 pidns = getPidInum(task);
//     u32 mntns = getMntInum(task);
//     ns.pidns = pidns;
//     ns.mountns = mntns;
//     u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
//     if(!is_container_process)
//         return 0;
//     bpf_printk("path_chmod triggered! in container process");
//     if(*is_container_process){
//         u32 syscall = lookup_syscall(ns, PATH_CHMOD);
        
//         u32 init_failed = set_syscall_map(pidns, mntns, PATH_CHMOD, 0);
//         if(init_failed)
//             return 0;
//         struct pid_syscall_args key;
//         key.syscall = syscall;
//         key.namespace = ns;
//         bpf_printk("path_chmod #1");
//         ///
//         u8 global_path_buf[MAX_PATH_LEN];

//         struct dentry *d = path->dentry;
//         int top = 0;
//         if(!d)
//             return 0;
//         // Reset global buffer
//         for (int i = 0; i < MAX_PATH_LEN; i++)
//             global_path_buf[i] = '\0';
//         bpf_printk("path_chmod #2");

//         for(int j = 0; j < 10; j++) {
//             if(d == d->d_parent || top >= MAX_PATH_LEN - 1 || !d)
//                 break;
            
//             u8 name_tmp[MAX_PATH_LEN];
//             bpf_core_read_str(&name_tmp, sizeof(name_tmp), d->d_name.name);
//             int len = 0;
//             while (name_tmp[len] != '\0' && len < MAX_PATH_LEN - 2) {
//                 len++;
//             }
//             if(len < 1)
//                 return 0;
//             bpf_printk("path_chmod #2-1 d_name.name : %s", name_tmp);
//             for (int i = len - 1; i >= 0 && top < MAX_PATH_LEN - 2; i--) {
//                 global_path_buf[top++] = name_tmp[i];
//             }
//             if (top < MAX_PATH_LEN - 1) {
//                 global_path_buf[top++] = '/';
//             }
//             d = d->d_parent;
//         }

//         bpf_printk("path_chmod #3");
//         // Reverse the whole path
//         for (int i = 0; i < top / 2; i++) {
//             u8 temp = global_path_buf[i];
//             global_path_buf[i] = global_path_buf[top - 1 - i];
//             global_path_buf[top - 1 - i] = temp;
//         }
//         ///
//         bpf_printk("path_chmod #3-1 global_path_buf : %s", global_path_buf);

//         u32 policy = lookup_policy(pidns, mntns, syscall);
//         if(!policy){
//             bpf_printk("path_chmod triggered! policy allowed");
//             return 0;
//         }
//         char *chmod_allow = bpf_map_lookup_elem(&policy_params_path_chmod, &key);
//         if(chmod_allow){
//             int is_allowed = 1;
//             for(int i = 0; i < 16; i++){
//                 if(chmod_allow[i * (MAX_PATH_LEN + 2)] != '/')
//                     break;
//                 is_allowed = 1;
//                 u16 policy_mode = (((u16)(chmod_allow[i * (MAX_PATH_LEN + 2) + 16]) & 0x00FF) << 8) | ((u16)(chmod_allow[i * (MAX_PATH_LEN + 2) + 17]) & 0x00FF);
//                 bpf_printk("policy_mode : %d", policy_mode);
//                 for(int j = 0; j < MAX_PATH_LEN; j++){
//                     if(chmod_allow[i * (MAX_PATH_LEN + 2) + j] == '\0')
//                         is_allowed = 0;
//                         break;
//                     if(global_path_buf[j] == '\0'){
//                         break;
//                     }
//                     if(chmod_allow[i * (MAX_PATH_LEN + 2) + j] != global_path_buf[j]){
//                         is_allowed = 0;
//                         break;
//                     }
//                 }
//                 if(is_allowed){
//                     if(policy_mode == mode)
//                         return 0;
//                     if(policy_mode == 65535)
//                         return 0;
//                 }
//             }
//         }

//         ///
//         u32 pid = bpf_get_current_pid_tgid() >> 32;
//         bpf_printk("lsm: detected PID: %d, comm: %s - blocked PID", pid, comm);
//         // Create event, we are going to send this over to userspace.
        
//         struct event *new_event = NULL;
//         new_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
//         if (new_event == NULL) {
//             return 0;
//         }
//         new_event->pid = pid;
//         for (u8 i = 0 ; i < 16 ; i++) new_event->comm[i] = comm[i];
//         bpf_ringbuf_submit(new_event, 0);

//         return -EPERM;
//     }
//     return 0;
// }

// SEC("lsm/file_mprotect")
// int BPF_PROG(file_mprotect, struct vm_area_struct *vma, unsigned long reqprot, unsigned long prot, int ret){
//     if (ret != 0)
//         return ret;

//     u8 comm[16] = {0};
//     bpf_get_current_comm(comm, 16);
    
//     struct task_struct *task = (struct task_struct*)bpf_get_current_task();
//     if(!task)
//         return 0;
//     struct pid_mount_ns ns;
//     u32 pidns = getPidInum(task);
//     u32 mntns = getMntInum(task);
//     ns.pidns = pidns;
//     ns.mountns = mntns;
//     u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
//     if(!is_container_process)
//         return 0;
//     u32 syscall = lookup_syscall(ns, FILE_MPROTECT);
    
//     u32 init_failed = set_syscall_map(pidns, mntns, FILE_MPROTECT, 0);
//     if(init_failed)
//         return 0;
//     bpf_printk("file_mprotect LSM Hook triggered! prot = %u, reqprot = %u", prot, reqprot);
//     u32 policy = lookup_policy(pidns, mntns, syscall);
//     if(!policy)
//         return 0;
    
//     struct pid_syscall_args psa;
//     psa.syscall = syscall;
//     psa.namespace = ns;
//     u32 *arr = bpf_map_lookup_elem(&policy_params_file_mprotect, &psa);
//     if(!arr){
//         for(int i = 0; i < 8; i++){
//             if(!arr[i*2] && !arr[i*2 + 1])
//                 break;
//             if(arr[i*2] == 0xFFFFFFFF){
//                 if(arr[i*2 + 1] == 0xFFFFFFFF){
//                     return 0;
//                 }
//                 else if(arr[i*2 + 1] == prot){
//                     return 0;
//                 }
//             }
//             else if(arr[i*2 + 1] == 0xFFFFFFFF){
//                 if(arr[i*2] == reqprot){
//                     return 0;
//                 }
//             }
//             else if(arr[i*2] == reqprot && arr[i*2 + 1] == prot){
//                 return 0;
//             }
//         }
//     }
    

//     u32 pid = bpf_get_current_pid_tgid() >> 32;
//     bpf_printk("lsm: detected PID: %d, comm: %s - blocked PID", pid, comm);
//     // Create event, we are going to send this over to userspace.
    
//     struct event *new_event = NULL;
//     new_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
//     if (new_event == NULL) {
//         return 0;
//     }
//     new_event->pid = pid;
//     for (u8 i = 0 ; i < 16 ; i++) new_event->comm[i] = comm[i];
//     bpf_ringbuf_submit(new_event, 0);

//     return -EPERM;
// }

// SEC("lsm/task_fix_setgid")
// int BPF_PROG(fix_setgid, struct cred *new, const struct cred *old, int flags, int ret){
//     if (ret != 0)
//         return ret;

//     u8 comm[16] = {0};
//     bpf_get_current_comm(comm, 16);
//     struct task_struct *task = (struct task_struct*)bpf_get_current_task();
//     if(!task)
//         return 0;
//     struct pid_mount_ns ns;
//     u32 pidns = getPidInum(task);
//     u32 mntns = getMntInum(task);
//     ns.pidns = pidns;
//     ns.mountns = mntns;
//     u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
//     if(!is_container_process)
//         return 0;
//     u32 syscall = lookup_syscall(ns, TASK_FIX_SETGID);
    
//     u32 init_failed = set_syscall_map(pidns, mntns, TASK_FIX_SETGID, 0);
//     if(init_failed)
//         return 0;
//     bpf_printk("task_fix_setgid LSM Hook triggered! uid = %u, euid = %u, suid = %u", new->gid.val, new->egid.val, new->sgid.val);
//     u32 policy = lookup_policy(pidns, mntns, syscall);
//     if(!policy)
//         return 0;
//     struct pid_syscall_args psa;
//     psa.syscall = syscall;
//     psa.namespace = ns;

//     u32 *arr = bpf_map_lookup_elem(&policy_params_fix_setgid, &psa);
//     if(arr){
//         for(int i = 0; i < 8; i++){
//             if(arr[i*3 + 2] == 0xFFFFFFFF){
//                 if(arr[i*3 + 1] == 0xFFFFFFFF){
//                     if(arr[i*3] == 0xFFFFFFFF){
//                         return 0;
//                     }
//                     else if(arr[i*3] == new->gid.val){
//                         return 0;
//                     }
//                 }
//                 else if(arr[i*3 + 1] == new->egid.val){
//                     if(arr[i*3] == 0xFFFFFFFF){
//                         return 0;
//                     }
//                     else if(arr[i*3] == new->gid.val){
//                         return 0;
//                     }
//                 }
//             }
//             else if(arr[i*3 + 2] == new->sgid.val){
//                 if(arr[i*3 + 1] == 0xFFFFFFFF){
//                     if(arr[i*3] == 0xFFFFFFFF){
//                         return 0;
//                     }
//                     else if(arr[i*3] == new->gid.val){
//                         return 0;
//                     }
//                 }
//                 else if(arr[i*3 + 1] == new->egid.val){
//                     if(arr[i*3] == 0xFFFFFFFF){
//                         return 0;
//                     }
//                     else if(arr[i*3] == new->gid.val){
//                         return 0;
//                     }
//                 }
//             }
//         }
//     }
    

//     u32 pid = bpf_get_current_pid_tgid() >> 32;
//     bpf_printk("lsm: detected PID: %d, comm: %s - blocked PID", pid, comm);
//     // Create event, we are going to send this over to userspace.
    
//     struct event *new_event = NULL;
//     new_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
//     if (new_event == NULL) {
//         return 0;
//     }
//     new_event->pid = pid;
//     for (u8 i = 0 ; i < 16 ; i++) new_event->comm[i] = comm[i];
//     bpf_ringbuf_submit(new_event, 0);

//     return -EPERM;
// }

// SEC("lsm/task_fix_setuid")
// int BPF_PROG(fix_setuid, struct cred *new, const struct cred *old, int flags, int ret){
//     if (ret != 0)
//         return ret;

//     u8 comm[16] = {0};
//     bpf_get_current_comm(comm, 16);
    
//     struct task_struct *task = (struct task_struct*)bpf_get_current_task();
//     if(!task)
//         return 0;
//     struct pid_mount_ns ns;
//     u32 pidns = getPidInum(task);
//     u32 mntns = getMntInum(task);
//     ns.pidns = pidns;
//     ns.mountns = mntns;
//     u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
//     if(!is_container_process)
//         return 0;
//     u32 syscall = lookup_syscall(ns, TASK_FIX_SETUID);
    
//     u32 init_failed = set_syscall_map(pidns, mntns, TASK_FIX_SETUID, 0);
//     if(init_failed)
//         return 0;
//     bpf_printk("task_fix_setuid LSM Hook triggered! uid = %u, euid = %u, suid = %u", new->uid.val, new->euid.val, new->suid.val);
//     u32 policy = lookup_policy(pidns, mntns, syscall);
//     if(!policy)
//         return 0;

//     struct pid_syscall_args psa;
//     psa.syscall = syscall;
//     psa.namespace = ns;

//     u32 *arr = bpf_map_lookup_elem(&policy_params_fix_setuid, &psa);
//     if(arr){
//         for(int i = 0; i < 8; i++){
//             if(arr[i*3 + 2] == 0xFFFFFFFF){
//                 if(arr[i*3 + 1] == 0xFFFFFFFF){
//                     if(arr[i*3] == 0xFFFFFFFF){
//                         return 0;
//                     }
//                     else if(arr[i*3] == new->uid.val){
//                         return 0;
//                     }
//                 }
//                 else if(arr[i*3 + 1] == new->euid.val){
//                     if(arr[i*3] == 0xFFFFFFFF){
//                         return 0;
//                     }
//                     else if(arr[i*3] == new->uid.val){
//                         return 0;
//                     }
//                 }
//             }
//             else if(arr[i*3 + 2] == new->suid.val){
//                 if(arr[i*3 + 1] == 0xFFFFFFFF){
//                     if(arr[i*3] == 0xFFFFFFFF){
//                         return 0;
//                     }
//                     else if(arr[i*3] == new->uid.val){
//                         return 0;
//                     }
//                 }
//                 else if(arr[i*3 + 1] == new->euid.val){
//                     if(arr[i*3] == 0xFFFFFFFF){
//                         return 0;
//                     }
//                     else if(arr[i*3] == new->uid.val){
//                         return 0;
//                     }
//                 }
//             }
//         }
//     }
    

//     u32 pid = bpf_get_current_pid_tgid() >> 32;
//     bpf_printk("lsm: detected PID: %d, comm: %s - blocked PID", pid, comm);
//     // Create event, we are going to send this over to userspace.
    
//     struct event *new_event = NULL;
//     new_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
//     if (new_event == NULL) {
//         return 0;
//     }
//     new_event->pid = pid;
//     for (u8 i = 0 ; i < 16 ; i++) new_event->comm[i] = comm[i];
//     bpf_ringbuf_submit(new_event, 0);

//     return -EPERM;
// }

// SEC("lsm/socket_accept")
// int BPF_PROG(socket_accept, struct socket *sock, struct socket *newsock, int ret){
//     if (ret != 0)
//         return ret;

//     u8 comm[16] = {0};
//     bpf_get_current_comm(comm, 16);
//     struct task_struct *task = (struct task_struct*)bpf_get_current_task();
//     if(!task)
//         return 0;
//     struct pid_mount_ns ns;
//     u32 pidns = getPidInum(task);
//     u32 mntns = getMntInum(task);
//     ns.pidns = pidns;
//     ns.mountns = mntns;
//     u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
//     if(!is_container_process)
//         return 0;
//     u32 syscall = lookup_syscall(ns, SOCKET_ACCEPT);
    
//     u32 init_failed = set_syscall_map(pidns, mntns, SOCKET_ACCEPT, 0);
//     if(init_failed)
//         return 0;
//     // u32 policy = lookup_policy(pidns, mntns, syscall);
//     // if(!policy)
//     //     return 0;
//     u32 ip_dest = sock->sk->__sk_common.skc_daddr;
//     u32 port_dest = (u32)(sock->sk->__sk_common.skc_dport);
//     u32 proto_dest = (u32)(sock->sk->sk_protocol);
//     bpf_printk("socket_accept LSM Hook triggered! ip_dest = %u, port_dest = %u", ip_dest, port_dest);
//     u32 policy = lookup_policy(pidns, mntns, syscall);
//     if(!policy)
//         return 0;
//     struct pid_syscall_args psa;
//     psa.syscall = syscall;
//     psa.namespace = ns;

//     u32 *arr = bpf_map_lookup_elem(&policy_params_socket_accept, &psa);
//     if(arr){
//         u16 flag = 0;
//         u32 policy_ip, policy_port, policy_proto;
//         for(int i = 0 ; i < 8; i++){
//             if(!arr[i * 3]&& !arr[i * 3 + 1] && !arr[i*3 + 2]){
//                 break;
//             }
//             policy_ip = arr[i*3];
//             policy_port = arr[i*3 + 1] & 0x0000FFFF;
//             policy_proto = arr[i*3 + 2];
//             flag = arr[i*3 + 1] >> 16;
            
//             if(flag == 0x00){
//                 if(policy_ip == ip_dest && policy_port == port_dest && policy_proto == proto_dest){
//                     return 0;
//                 }
//             }
//             else if(flag == 0xfe){
//                 if(!ip_dest && !port_dest && !proto_dest){
//                     return 0;
//                 }
//             }
//             else if(flag == 0xfd){
//                 if(policy_port == port_dest && policy_proto == proto_dest){
//                     return 0;
//                 }
//             }
//             else if(flag == 0xfb){
//                 if(policy_ip == ip_dest && policy_proto == proto_dest){
//                     return 0;
//                 }
//             }
//             else if(flag == 0xf7){
//                 if(policy_ip == ip_dest && policy_port == port_dest){
//                     return 0;
//                 }
//             }
//             else if(flag == 0xef){
//                 if(policy_proto == proto_dest){
//                     return 0;
//                 }
//             }
//             else if(flag == 0xdf){
//                 if(policy_port == port_dest){
//                     return 0;
//                 }
//             }
//             else if(flag == 0xbf){
//                 if(policy_ip == ip_dest){
//                     return 0;
//                 }
//             }
//             else if(flag == 0x7f){
//                 return 0;
//             }
//         } 
//     }
//     ///
    
    
//     u32 pid = bpf_get_current_pid_tgid() >> 32;
//     bpf_printk("lsm: detected PID: %d, comm: %s - blocked PID", pid, comm);
//     // Create event, we are going to send this over to userspace.
    
//     struct event *new_event = NULL;
//     new_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
//     if (new_event == NULL) {
//         return 0;
//     }
//     new_event->pid = pid;
//     for (u8 i = 0 ; i < 16 ; i++) new_event->comm[i] = comm[i];
//     bpf_ringbuf_submit(new_event, 0);

//     return -EPERM;
// } 

// SEC("lsm/socket_bind")
// int BPF_PROG(socket_bind, struct socket *sock, struct sockaddr *address, int addrlen, int ret){
//     if (ret != 0)
//         return ret;

//     u8 comm[16] = {0};
//     bpf_get_current_comm(comm, 16);
//     struct task_struct *task = (struct task_struct*)bpf_get_current_task();
//     if(!task)
//         return 0;
//     bpf_printk("bind triggered!");
//     struct pid_mount_ns ns;
//     u32 pidns = getPidInum(task);
//     u32 mntns = getMntInum(task);
//     ns.pidns = pidns;
//     ns.mountns = mntns;
//     u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
//     bpf_printk("Check if container process");
//     if(!is_container_process)
//         return 0;
//     bpf_printk("bind triggered2!");
//     u32 syscall = lookup_syscall(ns, SOCKET_BIND);
//     u32 init_failed = set_syscall_map(pidns, mntns, SOCKET_BIND, 0);
//     if(init_failed)
//         return 0;
//     bpf_printk("bind triggered!3");
//     struct sockaddr_in *addr = (struct sockaddr_in *)address;
//     if(!addr)
//         return 0;
//     u32 ip_dest = addr->sin_addr.s_addr;
//     u32 port_dest = (u32)(addr->sin_port);
//     u32 proto_dest = (u32)(sock->sk->sk_protocol);
//     bpf_printk("socket_bind LSM Hook triggered! ip_dest = %u, port_dest = %u", ip_dest, port_dest);
//     if (address->sa_family != AF_INET)
//     {
//         return 0;
//     }
//     u32 policy = lookup_policy(pidns, mntns, syscall);
//     if(!policy)
//         return 0;
//     struct pid_syscall_args psa;
//     psa.syscall = syscall;
//     psa.namespace = ns;

//     u32 *arr = bpf_map_lookup_elem(&policy_params_socket_bind, &psa);
//     if(arr){
//         u16 flag = 0;
//         u32 policy_ip, policy_port, policy_proto;
//         for(int i = 0 ; i < 8; i++){
//             if(!arr[i * 3]&& !arr[i * 3 + 1] && !arr[i*3 + 2]){
//                 break;
//             }
//             policy_ip = arr[i*3];
//             policy_port = arr[i*3 + 1] & 0x0000FFFF;
//             policy_proto = arr[i*3 + 2];
//             flag = arr[i*3 + 1] >> 16;
            
//             if(flag == 0x00){
//                 if(policy_ip == ip_dest && policy_port == port_dest && policy_proto == proto_dest){
//                     return 0;
//                 }
//             }
//             else if(flag == 0xfe){
//                 if(!ip_dest && !port_dest && !proto_dest){
//                     return 0;
//                 }
//             }
//             else if(flag == 0xfd){
//                 if(policy_port == port_dest && policy_proto == proto_dest){
//                     return 0;
//                 }
//             }
//             else if(flag == 0xfb){
//                 if(policy_ip == ip_dest && policy_proto == proto_dest){
//                     return 0;
//                 }
//             }
//             else if(flag == 0xf7){
//                 if(policy_ip == ip_dest && policy_port == port_dest){
//                     return 0;
//                 }
//             }
//             else if(flag == 0xef){
//                 if(policy_proto == proto_dest){
//                     return 0;
//                 }
//             }
//             else if(flag == 0xdf){
//                 if(policy_port == port_dest){
//                     return 0;
//                 }
//             }
//             else if(flag == 0xbf){
//                 if(policy_ip == ip_dest){
//                     return 0;
//                 }
//             }
//             else if(flag == 0x7f){
//                 return 0;
//             }
//         }
//     }
//     ///
    
    
//     u32 pid = bpf_get_current_pid_tgid() >> 32;
//     bpf_printk("lsm: detected PID: %d, comm: %s - blocked PID", pid, comm);
//     // Create event, we are going to send this over to userspace.
    
//     struct event *new_event = NULL;
//     new_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
//     if (new_event == NULL) {
//         return 0;
//     }
//     new_event->pid = pid;
//     for (u8 i = 0 ; i < 16 ; i++) new_event->comm[i] = comm[i];
//     bpf_ringbuf_submit(new_event, 0);

//     return -EPERM;
// }

// SEC("lsm/socket_connect")
// int BPF_PROG(socket_connect, struct socket *sock, struct sockaddr *address, int addrlen, int ret){
//     if (ret != 0)
//         return ret;

//     u8 comm[16] = {0};
//     bpf_get_current_comm(comm, 16);
//     struct task_struct *task = (struct task_struct*)bpf_get_current_task();
//     if(!task)
//         return 0;
//     struct pid_mount_ns ns;
//     u32 pidns = getPidInum(task);
//     u32 mntns = getMntInum(task);
//     ns.pidns = pidns;
//     ns.mountns = mntns;
//     u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
//     if(!is_container_process)
//         return 0;
//     u32 syscall = lookup_syscall(ns, SOCKET_CONNECT);
//     u32 init_failed = set_syscall_map(pidns, mntns, SOCKET_CONNECT, 0);
//     bpf_printk("socket_connect triggered! syscall : %d, ret : %d", syscall, ret);
//     if(init_failed)
//         return 0;
//     if (address->sa_family != AF_INET)
//     {
//         return 0;
//     }
//     struct sockaddr_in *addr = (struct sockaddr_in *)address;
//     if(!addr)
//         return 0;
//     u32 ip_dest = addr->sin_addr.s_addr;
//     u32 port_dest = (u32)(addr->sin_port);
//     u32 proto_dest = (u32)(sock->sk->sk_protocol);
//     bpf_printk("socket_connect LSM Hook triggered! ip_dest = %d, port_dest = %d", ip_dest, port_dest);
//     u32 policy = lookup_policy(pidns, mntns, syscall);
//     if(!policy)
//         return 0;
//     struct pid_syscall_args psa;
//     psa.syscall = syscall;
//     psa.namespace = ns;

//     u32 *arr = bpf_map_lookup_elem(&policy_params_socket_connect, &psa);
//     if(!arr){
//         u16 flag = 0;
//         u32 policy_ip, policy_port, policy_proto;
//         for(int i = 0 ; i < 8; i++){
//             if(!arr[i * 3]&& !arr[i * 3 + 1] && !arr[i*3 + 2]){
//                 break;
//             }
//             policy_ip = arr[i*3];
//             policy_port = arr[i*3 + 1] & 0x0000FFFF;
//             policy_proto = arr[i*3 + 2];
//             flag = arr[i*3 + 1] >> 16;
            
//             if(flag == 0x00){
//                 if(policy_ip == ip_dest && policy_port == port_dest && policy_proto == proto_dest){
//                     return 0;
//                 }
//             }
//             else if(flag == 0xfe){
//                 if(!ip_dest && !port_dest && !proto_dest){
//                     return 0;
//                 }
//             }
//             else if(flag == 0xfd){
//                 if(policy_port == port_dest && policy_proto == proto_dest){
//                     return 0;
//                 }
//             }
//             else if(flag == 0xfb){
//                 if(policy_ip == ip_dest && policy_proto == proto_dest){
//                     return 0;
//                 }
//             }
//             else if(flag == 0xf7){
//                 if(policy_ip == ip_dest && policy_port == port_dest){
//                     return 0;
//                 }
//             }
//             else if(flag == 0xef){
//                 if(policy_proto == proto_dest){
//                     return 0;
//                 }
//             }
//             else if(flag == 0xdf){
//                 if(policy_port == port_dest){
//                     return 0;
//                 }
//             }
//             else if(flag == 0xbf){
//                 if(policy_ip == ip_dest){
//                     return 0;
//                 }
//             }
//             else if(flag == 0x7f){
//                 return 0;
//             }
//         }   
        
//     }
//     ///
    
//     u32 pid = bpf_get_current_pid_tgid() >> 32;
//     bpf_printk("lsm: detected PID: %d, comm: %s - blocked PID", pid, comm);
//     // Create event, we are going to send this over to userspace.
    
//     struct event *new_event = NULL;
//     new_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
//     if (new_event == NULL) {
//         return 0;
//     }
//     new_event->pid = pid;
//     for (u8 i = 0 ; i < 16 ; i++) new_event->comm[i] = comm[i];
//     bpf_ringbuf_submit(new_event, 0);

//     return -EPERM;
// }

// SEC("lsm/socket_listen")
// int BPF_PROG(socket_listen, struct socket *sock, int backlog, int ret){
//     if (ret != 0)
//         return ret;

//     u8 comm[16] = {0};
//     bpf_get_current_comm(comm, 16);
//     struct task_struct *task = (struct task_struct*)bpf_get_current_task();
//     if(!task)
//         return 0;
//     struct pid_mount_ns ns;
//     u32 pidns = getPidInum(task);
//     u32 mntns = getMntInum(task);
//     ns.pidns = pidns;
//     ns.mountns = mntns;
//     u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
//     if(!is_container_process)
//         return 0;
//     u32 syscall = lookup_syscall(ns, SOCKET_LISTEN);
    
//     u32 init_failed = set_syscall_map(pidns, mntns, SOCKET_LISTEN, 0);
//     if(init_failed)
//         return 0;
//     // u32 policy = lookup_policy(pidns, mntns, syscall);
//     // if(!policy)
//     //     return 0;
//     u32 ip_dest = sock->sk->__sk_common.skc_daddr;
//     u32 port_dest = (u32)(sock->sk->__sk_common.skc_dport);
//     u32 proto_dest = (u32)(sock->sk->sk_protocol);
//     bpf_printk("socket_listen LSM Hook triggered! ip_dest = %u, port_dest = %u", ip_dest, port_dest);
//     u32 policy = lookup_policy(pidns, mntns, syscall);
//     if(!policy)
//         return 0;
//     struct pid_syscall_args psa;
//     psa.syscall = syscall;
//     psa.namespace = ns;

//     u32 *arr = bpf_map_lookup_elem(&policy_params_socket_listen, &psa);
//     if(arr){
//         u16 flag = 0;
//         u32 policy_ip, policy_port, policy_proto;
//         for(int i = 0 ; i < 8; i++){
//             if(!arr[i * 3]&& !arr[i * 3 + 1] && !arr[i*3 + 2]){
//                 break;
//             }
//             policy_ip = arr[i*3];
//             policy_port = arr[i*3 + 1] & 0x0000FFFF;
//             policy_proto = arr[i*3 + 2];
//             flag = arr[i*3 + 1] >> 16;
            
//             if(flag == 0x00){
//                 if(policy_ip == ip_dest && policy_port == port_dest && policy_proto == proto_dest){
//                     return 0;
//                 }
//             }
//             else if(flag == 0xfe){
//                 if(!ip_dest && !port_dest && !proto_dest){
//                     return 0;
//                 }
//             }
//             else if(flag == 0xfd){
//                 if(policy_port == port_dest && policy_proto == proto_dest){
//                     return 0;
//                 }
//             }
//             else if(flag == 0xfb){
//                 if(policy_ip == ip_dest && policy_proto == proto_dest){
//                     return 0;
//                 }
//             }
//             else if(flag == 0xf7){
//                 if(policy_ip == ip_dest && policy_port == port_dest){
//                     return 0;
//                 }
//             }
//             else if(flag == 0xef){
//                 if(policy_proto == proto_dest){
//                     return 0;
//                 }
//             }
//             else if(flag == 0xdf){
//                 if(policy_port == port_dest){
//                     return 0;
//                 }
//             }
//             else if(flag == 0xbf){
//                 if(policy_ip == ip_dest){
//                     return 0;
//                 }
//             }
//             else if(flag == 0x7f){
//                 return 0;
//             }
//         }   
//     }
//     ///
    

//     u32 pid = bpf_get_current_pid_tgid() >> 32;
//     bpf_printk("lsm: detected PID: %d, comm: %s - blocked PID", pid, comm);
//     // Create event, we are going to send this over to userspace.
    
//     struct event *new_event = NULL;
//     new_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
//     if (new_event == NULL) {
//         return 0;
//     }
//     new_event->pid = pid;
//     for (u8 i = 0 ; i < 16 ; i++) new_event->comm[i] = comm[i];
//     bpf_ringbuf_submit(new_event, 0);

//     return -EPERM;
// }

// SEC("lsm/socket_recvmsg")
// int BPF_PROG(socket_recvmsg, struct socket *sock, struct msghdr *msg, int size, int flags, int ret){
//     if (ret != 0)
//         return ret;

//     u8 comm[16] = {0};
//     bpf_get_current_comm(comm, 16);
//     struct task_struct *task = (struct task_struct*)bpf_get_current_task();
//     if(!task)
//         return 0;
//     struct pid_mount_ns ns;
//     u32 pidns = getPidInum(task);
//     u32 mntns = getMntInum(task);
//     ns.pidns = pidns;
//     ns.mountns = mntns;
//     u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
//     if(!is_container_process)
//         return 0;
//     u32 syscall = lookup_syscall(ns, SOCKET_RECVMSG);
    
//     u32 init_failed = set_syscall_map(pidns, mntns, SOCKET_RECVMSG, 0);
//     if(init_failed)
//         return 0;
//     // u32 policy = lookup_policy(pidns, mntns, syscall);
//     // if(!policy)
//     //     return 0;
//     u32 ip_dest = sock->sk->__sk_common.skc_daddr;
//     u32 port_dest = (u32)(sock->sk->__sk_common.skc_dport);
//     u32 proto_dest = (u32)(sock->sk->sk_protocol);
//     bpf_printk("socket_recvmsg LSM Hook triggered! ip_dest = %u, port_dest = %u", ip_dest, port_dest);
//     u32 policy = lookup_policy(pidns, mntns, syscall);
//     if(!policy)
//         return 0;
//     struct pid_syscall_args psa;
//     psa.syscall = syscall;
//     psa.namespace = ns;

//     u32 *arr = bpf_map_lookup_elem(&policy_params_socket_recvmsg, &psa);
//     if(arr){
//         u16 flag = 0;
//         u32 policy_ip, policy_port, policy_proto;
//         for(int i = 0 ; i < 8; i++){
//             if(!arr[i * 3]&& !arr[i * 3 + 1] && !arr[i*3 + 2]){
//                 break;
//             }
//             policy_ip = arr[i*3];
//             policy_port = arr[i*3 + 1] & 0x0000FFFF;
//             policy_proto = arr[i*3 + 2];
//             flag = arr[i*3 + 1] >> 16;
            
//             if(flag == 0x00){
//                 if(policy_ip == ip_dest && policy_port == port_dest && policy_proto == proto_dest){
//                     return 0;
//                 }
//             }
//             else if(flag == 0xfe){
//                 if(!ip_dest && !port_dest && !proto_dest){
//                     return 0;
//                 }
//             }
//             else if(flag == 0xfd){
//                 if(policy_port == port_dest && policy_proto == proto_dest){
//                     return 0;
//                 }
//             }
//             else if(flag == 0xfb){
//                 if(policy_ip == ip_dest && policy_proto == proto_dest){
//                     return 0;
//                 }
//             }
//             else if(flag == 0xf7){
//                 if(policy_ip == ip_dest && policy_port == port_dest){
//                     return 0;
//                 }
//             }
//             else if(flag == 0xef){
//                 if(policy_proto == proto_dest){
//                     return 0;
//                 }
//             }
//             else if(flag == 0xdf){
//                 if(policy_port == port_dest){
//                     return 0;
//                 }
//             }
//             else if(flag == 0xbf){
//                 if(policy_ip == ip_dest){
//                     return 0;
//                 }
//             }
//             else if(flag == 0x7f){
//                 return 0;
//             }
//         }
//     }
//     ///
       

    
//     u32 pid = bpf_get_current_pid_tgid() >> 32;
//     bpf_printk("lsm: detected PID: %d, comm: %s - blocked PID", pid, comm);
//     // Create event, we are going to send this over to userspace.
    
//     struct event *new_event = NULL;
//     new_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
//     if (new_event == NULL) {
//         return 0;
//     }
//     new_event->pid = pid;
//     for (u8 i = 0 ; i < 16 ; i++) new_event->comm[i] = comm[i];
//     bpf_ringbuf_submit(new_event, 0);

//     return -EPERM;
// }

// SEC("lsm/socket_create")
// int BPF_PROG(socket_create, int family, int type, int protocol, int kern, int ret){
//     if (ret != 0)
//         return ret;
//     u8 comm[16] = {0};
//     bpf_get_current_comm(comm, 16);
//     struct task_struct *task = (struct task_struct*)bpf_get_current_task();
//     if(!task)
//         return 0;
//     struct pid_mount_ns ns;
//     u32 pidns = getPidInum(task);
//     u32 mntns = getMntInum(task);
//     ns.pidns = pidns;
//     ns.mountns = mntns;
//     u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
//     if(!is_container_process)
//         return 0;
//     u32 syscall = lookup_syscall(ns, SOCKET_CREATE);

//     u32 init_failed = set_syscall_map(pidns, mntns, SOCKET_CREATE, 0);
//     if(init_failed)
//         return 0;
//     bpf_printk("socket_create LSM Hook triggered! protocol = %u, type = %u", protocol, type);
//     u32 policy = lookup_policy(pidns, mntns, syscall);
//     if(!policy)
//         return 0;
//     struct pid_syscall_args psa;
//     psa.syscall = syscall;
//     psa.namespace = ns;

//     u32 *arr = bpf_map_lookup_elem(&policy_params_socket_create, &psa);
//     if(arr){
//         for(int i = 0; i < 8; i++){
//         if(!arr[i*2] && !arr[i*2 + 1])
//             break;
//         else if(arr[i*2] == 7){
//             if(arr[i*2 + 1] == protocol){
//                 return 0;
//             }
//             else if(arr[i*2 + 1] == 7){
//                 return 0;
//             }
//         }
//         else if(arr[i*2 + 1] == 7){
//             if(arr[i * 2] == type){
//                 return 0;
//             }
//         }
//             else if(arr[i*2] == type && arr[i*2 + 1] == protocol){
//                 return 0;
//             }
//         }
//     }

//     u32 pid = bpf_get_current_pid_tgid() >> 32;
//     bpf_printk("lsm: detected PID: %d, comm: %s - blocked PID", pid, comm);
//     // Create event, we are going to send this over to userspace.
    
//     struct event *new_event = NULL;
//     new_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
//     if (new_event == NULL) {
//         return 0;
//     }
//     new_event->pid = pid;
//     for (u8 i = 0 ; i < 16 ; i++) new_event->comm[i] = comm[i];
//     bpf_ringbuf_submit(new_event, 0);

//     return -EPERM;
// }

// SEC("lsm/socket_getpeername")
// int BPF_PROG(socket_getpeername, struct socket *sock){
//     u32 pid = bpf_get_current_pid_tgid() >> 32;
//     u8 comm[16] = {0};
//     bpf_get_current_comm(comm, 16);
//     struct task_struct *task = (struct task_struct*)bpf_get_current_task();
//     if(!task)
//         return 0;
//     struct pid_mount_ns ns;
//     u32 pidns = getPidInum(task);
//     u32 mntns = getMntInum(task);
//     ns.pidns = pidns;
//     ns.mountns = mntns;
//     u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
//     if(!is_container_process)
//         return 0;
//     u32 syscall = lookup_syscall(ns, SOCKET_GETPEERNAME);
    
//     u32 init_failed = set_syscall_map(pidns, mntns, SOCKET_GETPEERNAME, 0);
//     if(init_failed)
//         return 0;
        
//     u32 policy = lookup_policy(pidns, mntns, syscall);
//     if(!policy){
//         return 0;
//     }

//     struct event *new_event = NULL;
//     new_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
//     if (new_event == NULL) {
//         return 0;
//     }
//     new_event->pid = pid;
//     for (u8 i = 0 ; i < 16 ; i++) new_event->comm[i] = comm[i];
//     bpf_ringbuf_submit(new_event, 0);
//     return 0;
// }

// SEC("lsm/socket_sendmsg")
// int BPF_PROG(socket_sendmsg, struct socket *sock, struct msghdr *msg, int size){
//     u32 pid = bpf_get_current_pid_tgid() >> 32;
//     u8 comm[16] = {0};
//     bpf_get_current_comm(comm, 16);
//     struct task_struct *task = (struct task_struct*)bpf_get_current_task();
//     if(!task)
//         return 0;
//     struct pid_mount_ns ns;
//     u32 pidns = getPidInum(task);
//     u32 mntns = getMntInum(task);
//     ns.pidns = pidns;
//     ns.mountns = mntns;
//     u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
//     if(!is_container_process)
//         return 0;
//     u32 syscall = lookup_syscall(ns, SOCKET_SENDMSG);
    
//     u32 init_failed = set_syscall_map(pidns, mntns, SOCKET_SENDMSG, 0);
//     if(init_failed)
//         return 0;
        
//     u32 policy = lookup_policy(pidns, mntns, syscall);
//     if(!policy){
//         return 0;
//     }

//     struct event *new_event = NULL;
//     new_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
//     if (new_event == NULL) {
//         return 0;
//     }
//     new_event->pid = pid;
//     for (u8 i = 0 ; i < 16 ; i++) new_event->comm[i] = comm[i];
//     bpf_ringbuf_submit(new_event, 0);
//     return 0;
// }

// SEC("lsm/socket_setsockopt")
// int BPF_PROG(socket_setsockopt, struct socket *sock, int level, int optname){
//     u32 pid = bpf_get_current_pid_tgid() >> 32;
//     u8 comm[16] = {0};
//     bpf_get_current_comm(comm, 16);
//     struct task_struct *task = (struct task_struct*)bpf_get_current_task();
//     if(!task)
//         return 0;
//     struct pid_mount_ns ns;
//     u32 pidns = getPidInum(task);
//     u32 mntns = getMntInum(task);
//     ns.pidns = pidns;
//     ns.mountns = mntns;
//     u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
//     if(!is_container_process)
//         return 0;
//     u32 syscall = lookup_syscall(ns, SOCKET_SETSOCKOPT);
    
//     u32 init_failed = set_syscall_map(pidns, mntns, SOCKET_SETSOCKOPT, 0);
//     if(init_failed)
//         return 0;
        
//     u32 policy = lookup_policy(pidns, mntns, syscall);
//     if(!policy){
//         return 0;
//     }

//     struct event *new_event = NULL;
//     new_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
//     if (new_event == NULL) {
//         return 0;
//     }
//     new_event->pid = pid;
//     for (u8 i = 0 ; i < 16 ; i++) new_event->comm[i] = comm[i];
//     bpf_ringbuf_submit(new_event, 0);
//     return 0;
// }

// SEC("lsm/socket_shutdown")
// int BPF_PROG(socket_shutdown, struct socket *sock, int how){
//     u32 pid = bpf_get_current_pid_tgid() >> 32;
//     u8 comm[16] = {0};
//     bpf_get_current_comm(comm, 16);
//     struct task_struct *task = (struct task_struct*)bpf_get_current_task();
//     if(!task)
//         return 0;
//     struct pid_mount_ns ns;
//     u32 pidns = getPidInum(task);
//     u32 mntns = getMntInum(task);
//     ns.pidns = pidns;
//     ns.mountns = mntns;
//     u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
//     if(!is_container_process)
//         return 0;
//     u32 syscall = lookup_syscall(ns, SOCKET_SHUTDOWN);
    
//     u32 init_failed = set_syscall_map(pidns, mntns, SOCKET_SHUTDOWN, 0);
//     if(init_failed)
//         return 0;
        
//     u32 policy = lookup_policy(pidns, mntns, syscall);
//     if(!policy){
//         return 0;
//     }

//     struct event *new_event = NULL;
//     new_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
//     if (new_event == NULL) {
//         return 0;
//     }
//     new_event->pid = pid;
//     for (u8 i = 0 ; i < 16 ; i++) new_event->comm[i] = comm[i];
//     bpf_ringbuf_submit(new_event, 0);
//     return 0;
// }

// SEC("lsm/capable")
// int BPF_PROG(capable, const struct cred *cred, struct user_namespace *ns, int cap, unsigned int opts){
//     u32 pid = bpf_get_current_pid_tgid() >> 32;
//     u8 comm[16] = {0};
//     bpf_get_current_comm(comm, 16);
//     struct task_struct *task = (struct task_struct*)bpf_get_current_task();
//     if(!task)
//         return 0;
//     struct pid_mount_ns nss;
//     u32 pidns = getPidInum(task);
//     u32 mntns = getMntInum(task);
//     nss.pidns = pidns;
//     nss.mountns = mntns;
//     u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &nss);
//     if(!is_container_process)
//         return 0;
//     u32 syscall = lookup_syscall(nss, CAPABLE);
    
//     u32 init_failed = set_syscall_map(pidns, mntns, CAPABLE, 0);
//     if(init_failed)
//         return 0;
        
//     u32 policy = lookup_policy(pidns, mntns, syscall);
//     if(!policy){
//         return 0;
//     }

//     struct event *new_event = NULL;
//     new_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
//     if (new_event == NULL) {
//         return 0;
//     }
//     new_event->pid = pid;
//     for (u8 i = 0 ; i < 16 ; i++) new_event->comm[i] = comm[i];
//     bpf_ringbuf_submit(new_event, 0);
//     return 0;
// }

// SEC("lsm/capget")
// int BPF_PROG(capget, struct task_struct *target, kernel_cap_t *effective, kernel_cap_t *inheritable, kernel_cap_t *permitted){
//     u32 pid = bpf_get_current_pid_tgid() >> 32;
//     u8 comm[16] = {0};
//     bpf_get_current_comm(comm, 16);
//     struct task_struct *task = (struct task_struct*)bpf_get_current_task();
//     if(!task)
//         return 0;
//     struct pid_mount_ns ns;
//     u32 pidns = getPidInum(task);
//     u32 mntns = getMntInum(task);
//     ns.pidns = pidns;
//     ns.mountns = mntns;
//     u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
//     if(!is_container_process)
//         return 0;
//     u32 syscall = lookup_syscall(ns, CAPGET);
    
//     u32 init_failed = set_syscall_map(pidns, mntns, CAPGET, 0);
//     if(init_failed)
//         return 0;
        
//     u32 policy = lookup_policy(pidns, mntns, syscall);
//     if(!policy){
//         return 0;
//     }

//     struct event *new_event = NULL;
//     new_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
//     if (new_event == NULL) {
//         return 0;
//     }
//     new_event->pid = pid;
//     for (u8 i = 0 ; i < 16 ; i++) new_event->comm[i] = comm[i];
//     bpf_ringbuf_submit(new_event, 0);
//     return 0;
// }

// SEC("lsm/capset")
// int BPF_PROG(capset, struct cred *new, const struct cred *old, const kernel_cap_t *effective, const kernel_cap_t *inheritable, const kernel_cap_t *permitted){
//     u32 pid = bpf_get_current_pid_tgid() >> 32;
//     u8 comm[16] = {0};
//     bpf_get_current_comm(comm, 16);
//     struct task_struct *task = (struct task_struct*)bpf_get_current_task();
//     if(!task)
//         return 0;
//     struct pid_mount_ns ns;
//     u32 pidns = getPidInum(task);
//     u32 mntns = getMntInum(task);
//     ns.pidns = pidns;
//     ns.mountns = mntns;
//     u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
//     if(!is_container_process)
//         return 0;
//     u32 syscall = lookup_syscall(ns, CAPSET);
    
//     u32 init_failed = set_syscall_map(pidns, mntns, CAPSET, 0);
//     if(init_failed)
//         return 0;
        
//     u32 policy = lookup_policy(pidns, mntns, syscall);
//     if(!policy){
//         return 0;
//     }

//     struct event *new_event = NULL;
//     new_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
//     if (new_event == NULL) {
//         return 0;
//     }
//     new_event->pid = pid;
//     for (u8 i = 0 ; i < 16 ; i++) new_event->comm[i] = comm[i];
//     bpf_ringbuf_submit(new_event, 0);
//     return 0;
// }

// SEC("lsm/quotactl")
// int BPF_PROG(quotactl, int cmds, int type, int id, struct super_block *sb){
//     u32 pid = bpf_get_current_pid_tgid() >> 32;
//     u8 comm[16] = {0};
//     bpf_get_current_comm(comm, 16);
//     struct task_struct *task = (struct task_struct*)bpf_get_current_task();
//     if(!task)
//         return 0;
//     struct pid_mount_ns ns;
//     u32 pidns = getPidInum(task);
//     u32 mntns = getMntInum(task);
//     ns.pidns = pidns;
//     ns.mountns = mntns;
//     u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
//     if(!is_container_process)
//         return 0;
//     u32 syscall = lookup_syscall(ns, QUOTACTL);
    
//     u32 init_failed = set_syscall_map(pidns, mntns, QUOTACTL, 0);
//     if(init_failed)
//         return 0;
        
//     u32 policy = lookup_policy(pidns, mntns, syscall);
//     if(!policy){
//         return 0;
//     }

//     struct event *new_event = NULL;
//     new_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
//     if (new_event == NULL) {
//         return 0;
//     }
//     new_event->pid = pid;
//     for (u8 i = 0 ; i < 16 ; i++) new_event->comm[i] = comm[i];
//     bpf_ringbuf_submit(new_event, 0);
//     return 0;
// }

// SEC("lsm/syslog")
// int BPF_PROG(syslog, int type){
//     u32 pid = bpf_get_current_pid_tgid() >> 32;
//     u8 comm[16] = {0};
//     bpf_get_current_comm(comm, 16);
//     struct task_struct *task = (struct task_struct*)bpf_get_current_task();
//     if(!task)
//         return 0;
//     struct pid_mount_ns ns;
//     u32 pidns = getPidInum(task);
//     u32 mntns = getMntInum(task);
//     ns.pidns = pidns;
//     ns.mountns = mntns;
//     u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
//     if(!is_container_process)
//         return 0;
//     u32 syscall = lookup_syscall(ns, SYSLOG);
    
//     u32 init_failed = set_syscall_map(pidns, mntns, SYSLOG, 0);
//     if(init_failed)
//         return 0;
        
//     u32 policy = lookup_policy(pidns, mntns, syscall);
//     if(!policy){
//         return 0;
//     }

//     struct event *new_event = NULL;
//     new_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
//     if (new_event == NULL) {
//         return 0;
//     }
//     new_event->pid = pid;
//     for (u8 i = 0 ; i < 16 ; i++) new_event->comm[i] = comm[i];
//     bpf_ringbuf_submit(new_event, 0);
//     return 0;
// }

// SEC("lsm/settime")
// int BPF_PROG(settime, const struct timespec64 *ts, const struct timezone *tz){
//     u32 pid = bpf_get_current_pid_tgid() >> 32;
//     u8 comm[16] = {0};
//     bpf_get_current_comm(comm, 16);
//     struct task_struct *task = (struct task_struct*)bpf_get_current_task();
//     if(!task)
//         return 0;
//     struct pid_mount_ns ns;
//     u32 pidns = getPidInum(task);
//     u32 mntns = getMntInum(task);
//     ns.pidns = pidns;
//     ns.mountns = mntns;
//     u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
//     if(!is_container_process)
//         return 0;
//     u32 syscall = lookup_syscall(ns, SETTIME);
    
//     u32 init_failed = set_syscall_map(pidns, mntns, SETTIME, 0);
//     if(init_failed)
//         return 0;
        
//     u32 policy = lookup_policy(pidns, mntns, syscall);
//     if(!policy){
//         return 0;
//     }

//     struct event *new_event = NULL;
//     new_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
//     if (new_event == NULL) {
//         return 0;
//     }
//     new_event->pid = pid;
//     for (u8 i = 0 ; i < 16 ; i++) new_event->comm[i] = comm[i];
//     bpf_ringbuf_submit(new_event, 0);
//     return 0;
// }



// SEC("lsm/sb_free_mnt_opts")
// int BPF_PROG(sb_free_mnt_opts, void **mnt_opts){
//     u32 pid = bpf_get_current_pid_tgid() >> 32;
//     u8 comm[16] = {0};
//     bpf_get_current_comm(comm, 16);
//     struct task_struct *task = (struct task_struct*)bpf_get_current_task();
//     if(!task)
//         return 0;
//     struct pid_mount_ns ns;
//     u32 pidns = getPidInum(task);
//     u32 mntns = getMntInum(task);
//     ns.pidns = pidns;
//     ns.mountns = mntns;
//     u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
//     if(!is_container_process)
//         return 0;
//     u32 syscall = lookup_syscall(ns, SB_FREE_MNT_OPTS);
    
//     u32 init_failed = set_syscall_map(pidns, mntns, SB_FREE_MNT_OPTS, 0);
//     if(init_failed)
//         return 0;
        
//     u32 policy = lookup_policy(pidns, mntns, syscall);
//     if(!policy){
//         return 0;
//     }

//     struct event *new_event = NULL;
//     new_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
//     if (new_event == NULL) {
//         return 0;
//     }
//     new_event->pid = pid;
//     for (u8 i = 0 ; i < 16 ; i++) new_event->comm[i] = comm[i];
//     bpf_ringbuf_submit(new_event, 0);
//     return 0;
// }


// SEC("lsm/sb_statfs")
// int BPF_PROG(sb_statfs, struct dentry *dentry){
//     u32 pid = bpf_get_current_pid_tgid() >> 32;
//     u8 comm[16] = {0};
//     bpf_get_current_comm(comm, 16);
//     struct task_struct *task = (struct task_struct*)bpf_get_current_task();
//     if(!task)
//         return 0;
//     struct pid_mount_ns ns;
//     u32 pidns = getPidInum(task);
//     u32 mntns = getMntInum(task);
//     ns.pidns = pidns;
//     ns.mountns = mntns;
//     u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
//     if(!is_container_process)
//         return 0;
//     u32 syscall = lookup_syscall(ns, SB_STATFS);
    
//     u32 init_failed = set_syscall_map(pidns, mntns, SB_STATFS, 0);
//     if(init_failed)
//         return 0;
        
//     u32 policy = lookup_policy(pidns, mntns, syscall);
//     if(!policy){
//         return 0;
//     }

//     struct event *new_event = NULL;
//     new_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
//     if (new_event == NULL) {
//         return 0;
//     }
//     new_event->pid = pid;
//     for (u8 i = 0 ; i < 16 ; i++) new_event->comm[i] = comm[i];
//     bpf_ringbuf_submit(new_event, 0);
//     return 0;
// }


// SEC("lsm/sb_pivotroot")
// int BPF_PROG(sb_pivotroot, const struct path *old_path, const struct path *new_path){
//     u32 pid = bpf_get_current_pid_tgid() >> 32;
//     u8 comm[16] = {0};
//     bpf_get_current_comm(comm, 16);
//     struct task_struct *task = (struct task_struct*)bpf_get_current_task();
//     if(!task)
//         return 0;
//     struct pid_mount_ns ns;
//     u32 pidns = getPidInum(task);
//     u32 mntns = getMntInum(task);
//     ns.pidns = pidns;
//     ns.mountns = mntns;
//     u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
//     if(!is_container_process)
//         return 0;
//     u32 syscall = lookup_syscall(ns, SB_PIVOTROOT);
    
//     u32 init_failed = set_syscall_map(pidns, mntns, SB_PIVOTROOT, 0);
//     if(init_failed)
//         return 0;
        
//     u32 policy = lookup_policy(pidns, mntns, syscall);
//     if(!policy){
//         return 0;
//     }

//     struct event *new_event = NULL;
//     new_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
//     if (new_event == NULL) {
//         return 0;
//     }
//     new_event->pid = pid;
//     for (u8 i = 0 ; i < 16 ; i++) new_event->comm[i] = comm[i];
//     bpf_ringbuf_submit(new_event, 0);
//     return 0;
// }


// SEC("lsm/move_mount")
// int BPF_PROG(move_mount, const struct path *from_path, const struct path *to_path){
//     u32 pid = bpf_get_current_pid_tgid() >> 32;
//     u8 comm[16] = {0};
//     bpf_get_current_comm(comm, 16);
//     struct task_struct *task = (struct task_struct*)bpf_get_current_task();
//     if(!task)
//         return 0;
//     struct pid_mount_ns ns;
//     u32 pidns = getPidInum(task);
//     u32 mntns = getMntInum(task);
//     ns.pidns = pidns;
//     ns.mountns = mntns;
//     u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
//     if(!is_container_process)
//         return 0;
//     u32 syscall = lookup_syscall(ns, MOVE_MOUNT);
    
//     u32 init_failed = set_syscall_map(pidns, mntns, MOVE_MOUNT, 0);
//     if(init_failed)
//         return 0;
        
//     u32 policy = lookup_policy(pidns, mntns, syscall);
//     if(!policy){
//         return 0;
//     }

//     struct event *new_event = NULL;
//     new_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
//     if (new_event == NULL) {
//         return 0;
//     }
//     new_event->pid = pid;
//     for (u8 i = 0 ; i < 16 ; i++) new_event->comm[i] = comm[i];
//     bpf_ringbuf_submit(new_event, 0);
//     return 0;
// }


// SEC("lsm/path_notify")
// int BPF_PROG(path_notify, const struct path *path, u64 mask, unsigned int obj_type){
//     u32 pid = bpf_get_current_pid_tgid() >> 32;
//     u8 comm[16] = {0};
//     bpf_get_current_comm(comm, 16);
//     struct task_struct *task = (struct task_struct*)bpf_get_current_task();
//     if(!task)
//         return 0;
//     struct pid_mount_ns ns;
//     u32 pidns = getPidInum(task);
//     u32 mntns = getMntInum(task);
//     ns.pidns = pidns;
//     ns.mountns = mntns;
//     u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
//     if(!is_container_process)
//         return 0;
//     u32 syscall = lookup_syscall(ns, PATH_NOTIFY);
    
//     u32 init_failed = set_syscall_map(pidns, mntns, PATH_NOTIFY, 0);
//     if(init_failed)
//         return 0;
        
//     u32 policy = lookup_policy(pidns, mntns, syscall);
//     if(!policy){
//         return 0;
//     }

//     struct event *new_event = NULL;
//     new_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
//     if (new_event == NULL) {
//         return 0;
//     }
//     new_event->pid = pid;
//     for (u8 i = 0 ; i < 16 ; i++) new_event->comm[i] = comm[i];
//     bpf_ringbuf_submit(new_event, 0);
//     return 0;
// }


// SEC("lsm/path_mkdir")
// int BPF_PROG(path_mkdir, const struct path *dir, struct dentry *dentry, umode_t mode){
//     u32 pid = bpf_get_current_pid_tgid() >> 32;
//     u8 comm[16] = {0};
//     bpf_get_current_comm(comm, 16);
//     struct task_struct *task = (struct task_struct*)bpf_get_current_task();
//     if(!task)
//         return 0;
//     struct pid_mount_ns ns;
//     u32 pidns = getPidInum(task);
//     u32 mntns = getMntInum(task);
//     ns.pidns = pidns;
//     ns.mountns = mntns;
//     u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
//     if(!is_container_process)
//         return 0;
//     u32 syscall = lookup_syscall(ns, PATH_MKDIR);
    
//     u32 init_failed = set_syscall_map(pidns, mntns, PATH_MKDIR, 0);
//     if(init_failed)
//         return 0;
        
//     u32 policy = lookup_policy(pidns, mntns, syscall);
//     if(!policy){
//         return 0;
//     }

//     struct event *new_event = NULL;
//     new_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
//     if (new_event == NULL) {
//         return 0;
//     }
//     new_event->pid = pid;
//     for (u8 i = 0 ; i < 16 ; i++) new_event->comm[i] = comm[i];
//     bpf_ringbuf_submit(new_event, 0);
//     return 0;
// }


// SEC("lsm/path_rmdir")
// int BPF_PROG(path_rmdir, const struct path *dir, struct dentry *dentry){
//     u32 pid = bpf_get_current_pid_tgid() >> 32;
//     u8 comm[16] = {0};
//     bpf_get_current_comm(comm, 16);
//     struct task_struct *task = (struct task_struct*)bpf_get_current_task();
//     if(!task)
//         return 0;
//     struct pid_mount_ns ns;
//     u32 pidns = getPidInum(task);
//     u32 mntns = getMntInum(task);
//     ns.pidns = pidns;
//     ns.mountns = mntns;
//     u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
//     if(!is_container_process)
//         return 0;
//     u32 syscall = lookup_syscall(ns, PATH_RMDIR);
    
//     u32 init_failed = set_syscall_map(pidns, mntns, PATH_RMDIR, 0);
//     if(init_failed)
//         return 0;
        
//     u32 policy = lookup_policy(pidns, mntns, syscall);
//     if(!policy){
//         return 0;
//     }

//     struct event *new_event = NULL;
//     new_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
//     if (new_event == NULL) {
//         return 0;
//     }
//     new_event->pid = pid;
//     for (u8 i = 0 ; i < 16 ; i++) new_event->comm[i] = comm[i];
//     bpf_ringbuf_submit(new_event, 0);
//     return 0;
// }


// SEC("lsm/path_unlink")
// int BPF_PROG(path_unlink, const struct path *dir, struct dentry *dentry){
//     u32 pid = bpf_get_current_pid_tgid() >> 32;
//     u8 comm[16] = {0};
//     bpf_get_current_comm(comm, 16);
//     struct task_struct *task = (struct task_struct*)bpf_get_current_task();
//     if(!task)
//         return 0;
//     struct pid_mount_ns ns;
//     u32 pidns = getPidInum(task);
//     u32 mntns = getMntInum(task);
//     ns.pidns = pidns;
//     ns.mountns = mntns;
//     u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
//     if(!is_container_process)
//         return 0;
//     u32 syscall = lookup_syscall(ns, PATH_UNLINK);
    
//     u32 init_failed = set_syscall_map(pidns, mntns, PATH_UNLINK, 0);
//     if(init_failed)
//         return 0;
        
//     u32 policy = lookup_policy(pidns, mntns, syscall);
//     if(!policy){
//         return 0;
//     }

//     struct event *new_event = NULL;
//     new_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
//     if (new_event == NULL) {
//         return 0;
//     }
//     new_event->pid = pid;
//     for (u8 i = 0 ; i < 16 ; i++) new_event->comm[i] = comm[i];
//     bpf_ringbuf_submit(new_event, 0);
//     return 0;
// }


// SEC("lsm/path_symlink")
// int BPF_PROG(path_symlink, const struct path *dir, struct dentry *dentry, const char *old_name){
//     u32 pid = bpf_get_current_pid_tgid() >> 32;
//     u8 comm[16] = {0};
//     bpf_get_current_comm(comm, 16);
//     struct task_struct *task = (struct task_struct*)bpf_get_current_task();
//     if(!task)
//         return 0;
//     struct pid_mount_ns ns;
//     u32 pidns = getPidInum(task);
//     u32 mntns = getMntInum(task);
//     ns.pidns = pidns;
//     ns.mountns = mntns;
//     u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
//     if(!is_container_process)
//         return 0;
//     u32 syscall = lookup_syscall(ns, PATH_SYMLINK);
    
//     u32 init_failed = set_syscall_map(pidns, mntns, PATH_SYMLINK, 0);
//     if(init_failed)
//         return 0;
        
//     u32 policy = lookup_policy(pidns, mntns, syscall);
//     if(!policy){
//         return 0;
//     }

//     struct event *new_event = NULL;
//     new_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
//     if (new_event == NULL) {
//         return 0;
//     }
//     new_event->pid = pid;
//     for (u8 i = 0 ; i < 16 ; i++) new_event->comm[i] = comm[i];
//     bpf_ringbuf_submit(new_event, 0);
//     return 0;
// }


// SEC("lsm/path_link")
// int BPF_PROG(path_link, struct dentry *old_dentry, const struct path *new_dir, struct dentry *new_dentry){
//     u32 pid = bpf_get_current_pid_tgid() >> 32;
//     u8 comm[16] = {0};
//     bpf_get_current_comm(comm, 16);
//     struct task_struct *task = (struct task_struct*)bpf_get_current_task();
//     if(!task)
//         return 0;
//     struct pid_mount_ns ns;
//     u32 pidns = getPidInum(task);
//     u32 mntns = getMntInum(task);
//     ns.pidns = pidns;
//     ns.mountns = mntns;
//     u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
//     if(!is_container_process)
//         return 0;
//     u32 syscall = lookup_syscall(ns, PATH_LINK);
    
//     u32 init_failed = set_syscall_map(pidns, mntns, PATH_LINK, 0);
//     if(init_failed)
//         return 0;
        
//     u32 policy = lookup_policy(pidns, mntns, syscall);
//     if(!policy){
//         return 0;
//     }

//     struct event *new_event = NULL;
//     new_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
//     if (new_event == NULL) {
//         return 0;
//     }
//     new_event->pid = pid;
//     for (u8 i = 0 ; i < 16 ; i++) new_event->comm[i] = comm[i];
//     bpf_ringbuf_submit(new_event, 0);
//     return 0;
// }


// SEC("lsm/path_rename")
// int BPF_PROG(path_rename, const struct path *old_dir, struct dentry *old_dentry, const struct path *new_dir, struct dentry *new_dentry, unsigned int flags){
//     u32 pid = bpf_get_current_pid_tgid() >> 32;
//     u8 comm[16] = {0};
//     bpf_get_current_comm(comm, 16);
//     struct task_struct *task = (struct task_struct*)bpf_get_current_task();
//     if(!task)
//         return 0;
//     struct pid_mount_ns ns;
//     u32 pidns = getPidInum(task);
//     u32 mntns = getMntInum(task);
//     ns.pidns = pidns;
//     ns.mountns = mntns;
//     u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
//     if(!is_container_process)
//         return 0;
//     u32 syscall = lookup_syscall(ns, PATH_RENAME);
    
//     u32 init_failed = set_syscall_map(pidns, mntns, PATH_RENAME, 0);
//     if(init_failed)
//         return 0;
        
//     u32 policy = lookup_policy(pidns, mntns, syscall);
//     if(!policy){
//         return 0;
//     }

//     struct event *new_event = NULL;
//     new_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
//     if (new_event == NULL) {
//         return 0;
//     }
//     new_event->pid = pid;
//     for (u8 i = 0 ; i < 16 ; i++) new_event->comm[i] = comm[i];
//     bpf_ringbuf_submit(new_event, 0);
//     return 0;
// }


// SEC("lsm/path_truncate")
// int BPF_PROG(path_truncate, const struct path *path){
//     u32 pid = bpf_get_current_pid_tgid() >> 32;
//     u8 comm[16] = {0};
//     bpf_get_current_comm(comm, 16);
//     struct task_struct *task = (struct task_struct*)bpf_get_current_task();
//     if(!task)
//         return 0;
//     struct pid_mount_ns ns;
//     u32 pidns = getPidInum(task);
//     u32 mntns = getMntInum(task);
//     ns.pidns = pidns;
//     ns.mountns = mntns;
//     u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
//     if(!is_container_process)
//         return 0;
//     u32 syscall = lookup_syscall(ns, PATH_TRUNCATE);
    
//     u32 init_failed = set_syscall_map(pidns, mntns, PATH_TRUNCATE, 0);
//     if(init_failed)
//         return 0;
        
//     u32 policy = lookup_policy(pidns, mntns, syscall);
//     if(!policy){
//         return 0;
//     }

//     struct event *new_event = NULL;
//     new_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
//     if (new_event == NULL) {
//         return 0;
//     }
//     new_event->pid = pid;
//     for (u8 i = 0 ; i < 16 ; i++) new_event->comm[i] = comm[i];
//     bpf_ringbuf_submit(new_event, 0);
//     return 0;
// }


// SEC("lsm/path_chown")
// int BPF_PROG(path_chown, const struct path *path, kuid_t uid, kgid_t gid){
//     u32 pid = bpf_get_current_pid_tgid() >> 32;
//     u8 comm[16] = {0};
//     bpf_get_current_comm(comm, 16);
//     struct task_struct *task = (struct task_struct*)bpf_get_current_task();
//     if(!task)
//         return 0;
//     struct pid_mount_ns ns;
//     u32 pidns = getPidInum(task);
//     u32 mntns = getMntInum(task);
//     ns.pidns = pidns;
//     ns.mountns = mntns;
//     u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
//     if(!is_container_process)
//         return 0;
//     u32 syscall = lookup_syscall(ns, PATH_CHOWN);
    
//     u32 init_failed = set_syscall_map(pidns, mntns, PATH_CHOWN, 0);
//     if(init_failed)
//         return 0;
        
//     u32 policy = lookup_policy(pidns, mntns, syscall);
//     if(!policy){
//         return 0;
//     }

//     struct event *new_event = NULL;
//     new_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
//     if (new_event == NULL) {
//         return 0;
//     }
//     new_event->pid = pid;
//     for (u8 i = 0 ; i < 16 ; i++) new_event->comm[i] = comm[i];
//     bpf_ringbuf_submit(new_event, 0);
//     return 0;
// }


// SEC("lsm/path_chroot")
// int BPF_PROG(path_chroot, const struct path *path){
//     u32 pid = bpf_get_current_pid_tgid() >> 32;
//     u8 comm[16] = {0};
//     bpf_get_current_comm(comm, 16);
//     struct task_struct *task = (struct task_struct*)bpf_get_current_task();
//     if(!task)
//         return 0;
//     struct pid_mount_ns ns;
//     u32 pidns = getPidInum(task);
//     u32 mntns = getMntInum(task);
//     ns.pidns = pidns;
//     ns.mountns = mntns;
//     u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
//     if(!is_container_process)
//         return 0;
//     u32 syscall = lookup_syscall(ns, PATH_CHROOT);
    
//     u32 init_failed = set_syscall_map(pidns, mntns, PATH_CHROOT, 0);
//     if(init_failed)
//         return 0;
        
//     u32 policy = lookup_policy(pidns, mntns, syscall);
//     if(!policy){
//         return 0;
//     }

//     struct event *new_event = NULL;
//     new_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
//     if (new_event == NULL) {
//         return 0;
//     }
//     new_event->pid = pid;
//     for (u8 i = 0 ; i < 16 ; i++) new_event->comm[i] = comm[i];
//     bpf_ringbuf_submit(new_event, 0);
//     return 0;
// }


// SEC("lsm/mmap_file")
// int BPF_PROG(mmap_file, struct file *file, unsigned long prot, unsigned long flags){
//     u32 pid = bpf_get_current_pid_tgid() >> 32;
//     u8 comm[16] = {0};
//     bpf_get_current_comm(comm, 16);
//     struct task_struct *task = (struct task_struct*)bpf_get_current_task();
//     if(!task)
//         return 0;
//     struct pid_mount_ns ns;
//     u32 pidns = getPidInum(task);
//     u32 mntns = getMntInum(task);
//     ns.pidns = pidns;
//     ns.mountns = mntns;
//     u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
//     if(!is_container_process)
//         return 0;
//     u32 syscall = lookup_syscall(ns, MMAP_FILE);
    
//     u32 init_failed = set_syscall_map(pidns, mntns, MMAP_FILE, 0);
//     if(init_failed)
//         return 0;
        
//     u32 policy = lookup_policy(pidns, mntns, syscall);
//     if(!policy){
//         return 0;
//     }

//     struct event *new_event = NULL;
//     new_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
//     if (new_event == NULL) {
//         return 0;
//     }
//     new_event->pid = pid;
//     for (u8 i = 0 ; i < 16 ; i++) new_event->comm[i] = comm[i];
//     bpf_ringbuf_submit(new_event, 0);
//     return 0;
// }


// SEC("lsm/mmap_addr")
// int BPF_PROG(mmap_addr, unsigned long addr){
//     u32 pid = bpf_get_current_pid_tgid() >> 32;
//     u8 comm[16] = {0};
//     bpf_get_current_comm(comm, 16);
//     struct task_struct *task = (struct task_struct*)bpf_get_current_task();
//     if(!task)
//         return 0;
//     struct pid_mount_ns ns;
//     u32 pidns = getPidInum(task);
//     u32 mntns = getMntInum(task);
//     ns.pidns = pidns;
//     ns.mountns = mntns;
//     u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
//     if(!is_container_process)
//         return 0;
//     u32 syscall = lookup_syscall(ns, MMAP_ADDR);
    
//     u32 init_failed = set_syscall_map(pidns, mntns, MMAP_ADDR, 0);
//     if(init_failed)
//         return 0;
        
//     u32 policy = lookup_policy(pidns, mntns, syscall);
//     if(!policy){
//         return 0;
//     }

//     struct event *new_event = NULL;
//     new_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
//     if (new_event == NULL) {
//         return 0;
//     }
//     new_event->pid = pid;
//     for (u8 i = 0 ; i < 16 ; i++) new_event->comm[i] = comm[i];
//     bpf_ringbuf_submit(new_event, 0);
//     return 0;
// }


// SEC("lsm/file_fcntl")
// int BPF_PROG(file_fcntl, struct file *file, unsigned int cmd, unsigned long arg){
//     u32 pid = bpf_get_current_pid_tgid() >> 32;
//     u8 comm[16] = {0};
//     bpf_get_current_comm(comm, 16);
//     struct task_struct *task = (struct task_struct*)bpf_get_current_task();
//     if(!task)
//         return 0;
//     struct pid_mount_ns ns;
//     u32 pidns = getPidInum(task);
//     u32 mntns = getMntInum(task);
//     ns.pidns = pidns;
//     ns.mountns = mntns;
//     u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
//     if(!is_container_process)
//         return 0;
//     u32 syscall = lookup_syscall(ns, FILE_FCNTL);
    
//     u32 init_failed = set_syscall_map(pidns, mntns, FILE_FCNTL, 0);
//     if(init_failed)
//         return 0;
        
//     u32 policy = lookup_policy(pidns, mntns, syscall);
//     if(!policy){
//         return 0;
//     }

//     struct event *new_event = NULL;
//     new_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
//     if (new_event == NULL) {
//         return 0;
//     }
//     new_event->pid = pid;
//     for (u8 i = 0 ; i < 16 ; i++) new_event->comm[i] = comm[i];
//     bpf_ringbuf_submit(new_event, 0);
//     return 0;
// }


// SEC("lsm/task_setpgid")
// int BPF_PROG(task_setpgid, struct task_struct *p, pid_t pgid){
//     u32 pid = bpf_get_current_pid_tgid() >> 32;
//     u8 comm[16] = {0};
//     bpf_get_current_comm(comm, 16);
//     struct task_struct *task = (struct task_struct*)bpf_get_current_task();
//     if(!task)
//         return 0;
//     struct pid_mount_ns ns;
//     u32 pidns = getPidInum(task);
//     u32 mntns = getMntInum(task);
//     ns.pidns = pidns;
//     ns.mountns = mntns;
//     u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
//     if(!is_container_process)
//         return 0;
//     u32 syscall = lookup_syscall(ns, TASK_SETPGID);
    
//     u32 init_failed = set_syscall_map(pidns, mntns, TASK_SETPGID, 0);
//     if(init_failed)
//         return 0;
        
//     u32 policy = lookup_policy(pidns, mntns, syscall);
//     if(!policy){
//         return 0;
//     }

//     struct event *new_event = NULL;
//     new_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
//     if (new_event == NULL) {
//         return 0;
//     }
//     new_event->pid = pid;
//     for (u8 i = 0 ; i < 16 ; i++) new_event->comm[i] = comm[i];
//     bpf_ringbuf_submit(new_event, 0);
//     return 0;
// }


// SEC("lsm/task_getpgid")
// int BPF_PROG(task_getpgid, struct task_struct *p){
//     u32 pid = bpf_get_current_pid_tgid() >> 32;
//     u8 comm[16] = {0};
//     bpf_get_current_comm(comm, 16);
//     struct task_struct *task = (struct task_struct*)bpf_get_current_task();
//     if(!task)
//         return 0;
//     struct pid_mount_ns ns;
//     u32 pidns = getPidInum(task);
//     u32 mntns = getMntInum(task);
//     ns.pidns = pidns;
//     ns.mountns = mntns;
//     u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
//     if(!is_container_process)
//         return 0;
//     u32 syscall = lookup_syscall(ns, TASK_GETPGID);
    
//     u32 init_failed = set_syscall_map(pidns, mntns, TASK_GETPGID, 0);
//     if(init_failed)
//         return 0;
        
//     u32 policy = lookup_policy(pidns, mntns, syscall);
//     if(!policy){
//         return 0;
//     }

//     struct event *new_event = NULL;
//     new_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
//     if (new_event == NULL) {
//         return 0;
//     }
//     new_event->pid = pid;
//     for (u8 i = 0 ; i < 16 ; i++) new_event->comm[i] = comm[i];
//     bpf_ringbuf_submit(new_event, 0);
//     return 0;
// }


// SEC("lsm/task_getsid")
// int BPF_PROG(task_getsid, struct task_struct *p){
//     u32 pid = bpf_get_current_pid_tgid() >> 32;
//     u8 comm[16] = {0};
//     bpf_get_current_comm(comm, 16);
//     struct task_struct *task = (struct task_struct*)bpf_get_current_task();
//     if(!task)
//         return 0;
//     struct pid_mount_ns ns;
//     u32 pidns = getPidInum(task);
//     u32 mntns = getMntInum(task);
//     ns.pidns = pidns;
//     ns.mountns = mntns;
//     u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
//     if(!is_container_process)
//         return 0;
//     u32 syscall = lookup_syscall(ns, TASK_GETSID);
    
//     u32 init_failed = set_syscall_map(pidns, mntns, TASK_GETSID, 0);
//     if(init_failed)
//         return 0;
        
//     u32 policy = lookup_policy(pidns, mntns, syscall);
//     if(!policy){
//         return 0;
//     }

//     struct event *new_event = NULL;
//     new_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
//     if (new_event == NULL) {
//         return 0;
//     }
//     new_event->pid = pid;
//     for (u8 i = 0 ; i < 16 ; i++) new_event->comm[i] = comm[i];
//     bpf_ringbuf_submit(new_event, 0);
//     return 0;
// }