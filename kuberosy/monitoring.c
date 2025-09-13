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
    __type(key, __u64);
    __type(value, __u32);
    __uint(max_entries, 512);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} syscall_used SEC(".maps");

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

u32 set_syscall_map(u64 syscall_num){
    u32 val = 1; // Namespace struct exist, updating lsm to syscall mapping
    bpf_map_update_elem(&syscall_used, &syscall_num, &val, BPF_ANY);
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
    bpf_printk("Within sys_enter 1");
    if(!is_container_process)
        return 0;
    // bpf_tail_call(ctx, &prog_array, SYS_ENTER_TAIL);
    u64 id = ctx->args[1];
    set_syscall_map(id);
    bpf_printk("Within sys_enter 2");
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("accept syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("accept4 syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("access syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("acct syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("add_key syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("adjtimex syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("alarm syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("arch_prctl syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("bind syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("bpf syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("brk syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("capget syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("capset syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("chdir syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("chmod syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("chown syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("chroot syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("clock_adjtime syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("clock_getres syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("clock_gettime syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("clock_nanosleep syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("clock_settime syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("clone syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("clone3 syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("close syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("close_range syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("connect syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("copy_file_range syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("creat syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("delete_module syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("dup syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("dup2 syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("dup3 syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("epoll_create syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("epoll_create1 syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("epoll_ctl syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("epoll_pwait syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("epoll_pwait2 syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("epoll_wait syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("eventfd syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("eventfd2 syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("execve syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("execveat syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("exit syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("exit_group syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("faccessat syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("faccessat2 syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("fadvise64 syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("fallocate syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("fanotify_init syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("fanotify_mark syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("fchdir syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("fchmod syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("fchmodat syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("fchown syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("fchownat syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("fcntl syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("fdatasync syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("fgetxattr syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("finit_module syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("flistxattr syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("flock syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("fork syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("fremovexattr syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("fsconfig syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("fsetxattr syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("fsmount syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("fsopen syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("fspick syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("fstatfs syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("fsync syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("ftruncate syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("futex syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("futex_waitv syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("futimesat syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("getcpu syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("getcwd syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("getdents syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("getdents64 syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("getegid syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("geteuid syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("getgid syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("getgroups syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("getitimer syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("get_mempolicy syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("getpeername syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("getpgid syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("getpgrp syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("getpid syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("getppid syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("getpriority syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("getrandom syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("getresgid syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("getresuid syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("getrlimit syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("get_robust_list syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("getrusage syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("getsid syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("getsockname syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("getsockopt syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("gettid syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("gettimeofday syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("getuid syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("getxattr syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("init_module syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("inotify_add_watch syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("inotify_init syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("inotify_init1 syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("inotify_rm_watch syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("io_cancel syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("ioctl syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("io_destroy syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("io_getevents syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("ioperm syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("io_pgetevents syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("iopl syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("ioprio_get syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("ioprio_set syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("io_setup syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("io_submit syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("io_uring_enter syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("io_uring_register syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("io_uring_setup syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("kcmp syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("kexec_file_load syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("kexec_load syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("keyctl syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("kill syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("landlock_add_rule syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("landlock_create_ruleset syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("landlock_restrict_self syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("lchown syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("lgetxattr syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("link syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("linkat syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("listen syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("listxattr syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("llistxattr syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("lremovexattr syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("lseek syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("lsetxattr syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("madvise syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("mbind syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("membarrier syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("memfd_create syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("memfd_secret syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("migrate_pages syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("mincore syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("mkdir syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("mkdirat syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("mknod syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("mknodat syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("mlock syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("mlock2 syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("mlockall syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("mmap syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("modify_ldt syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("mount syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("mount_setattr syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("move_mount syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("move_pages syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("mprotect syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("mq_getsetattr syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("mq_notify syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("mq_open syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("mq_timedreceive syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("mq_timedsend syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("mq_unlink syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("mremap syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("msgctl syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("msgget syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("msgrcv syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("msgsnd syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("msync syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("munlock syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("munlockall syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("munmap syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("name_to_handle_at syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("nanosleep syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("newfstat syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("newfstatat syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("newlstat syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("newstat syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("newuname syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("open syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("openat syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("openat2 syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("open_by_handle_at syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("open_tree syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("pause syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("perf_event_open syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("personality syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("pidfd_getfd syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("pidfd_open syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("pidfd_send_signal syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("pipe syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("pipe2 syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("pivot_root syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("pkey_alloc syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("pkey_free syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("pkey_mprotect syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("poll syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("ppoll syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("prctl syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("pread64 syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("preadv syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("preadv2 syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("prlimit64 syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("process_madvise syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("process_mrelease syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("process_vm_readv syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("process_vm_writev syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("pselect6 syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("ptrace syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("pwrite64 syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("pwritev syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("pwritev2 syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("quotactl syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("quotactl_fd syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("read syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("readahead syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("readlink syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("readlinkat syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("readv syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("reboot syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("recvfrom syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("recvmmsg syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("recvmsg syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("remap_file_pages syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("removexattr syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("rename syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("renameat syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("renameat2 syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("request_key syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("restart_syscall syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("rmdir syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("rseq syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("rt_sigaction syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("rt_sigpending syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("rt_sigprocmask syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("rt_sigqueueinfo syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("rt_sigreturn syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("rt_sigsuspend syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("rt_sigtimedwait syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("rt_tgsigqueueinfo syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("sched_getaffinity syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("sched_getattr syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("sched_getparam syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("sched_get_priority_max syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("sched_get_priority_min syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("sched_getscheduler syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("sched_rr_get_interval syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("sched_setaffinity syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("sched_setattr syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("sched_setparam syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("sched_setscheduler syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("sched_yield syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("seccomp syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("select syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("semctl syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("semget syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("semop syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("semtimedop syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("sendfile64 syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("sendmmsg syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("sendmsg syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("sendto syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("setdomainname syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("setfsgid syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("setfsuid syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("setgid syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("setgroups syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("sethostname syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("setitimer syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("set_mempolicy syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("set_mempolicy_home_node syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("setns syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("setpgid syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("setpriority syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("setregid syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("setresgid syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("setresuid syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("setreuid syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("setrlimit syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("set_robust_list syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("setsid syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("setsockopt syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("set_tid_address syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("settimeofday syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("setuid syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("setxattr syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("shmat syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("shmctl syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("shmdt syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("shmget syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("shutdown syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("sigaltstack syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("signalfd syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("signalfd4 syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("socket syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("socketpair syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("splice syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("statfs syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("statx syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("swapoff syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("swapon syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("symlink syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("symlinkat syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("sync syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("sync_file_range syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("syncfs syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("sysfs syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("sysinfo syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("syslog syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("tee syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("tgkill syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("time syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("timer_create syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("timer_delete syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("timerfd_create syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("timerfd_gettime syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("timerfd_settime syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("timer_getoverrun syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("timer_gettime syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("timer_settime syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("times syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("tkill syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("truncate syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("umask syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("umount syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("unlink syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("unlinkat syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("unshare syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("userfaultfd syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("ustat syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("utime syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("utimensat syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("utimes syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("vfork syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("vhangup syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("vmsplice syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("wait4 syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("waitid syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("write syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
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
	//if(!ctx) {
		//bpf_printk("ctx is null");
		//return 0;}
	//u64 id = ctx->id;
	//bpf_printk("writev syscall triggered for syscall num %u", id);
	//set_syscall_map(id);
	return 0;
}

