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
    bpf_printk("namespace is pidns %u", pidns);
    bpf_printk("namespace is mntns %u", mntns);
    u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
    bpf_printk("Within sys_enter 1");
    if(!is_container_process)
        return 0;
    // bpf_tail_call(ctx, &prog_array, SYS_ENTER_TAIL);
    u64 id = ctx->args[1];
    set_syscall_map(pidns, mntns, 0, id);
    bpf_printk("Within sys_enter 2");
    return 0;
}

SEC("kprobe/sys_write_entry")
int BPF_KPROBE(temp_write_callback, unsigned int fd, const char *buf, size_t count)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u8 comm[16] = {0};
    bpf_get_current_comm(comm, 16);
    struct task_struct *task = (struct task_struct*)bpf_get_current_task();
    if(!task)
        return 0;
    struct pid_mount_ns ns;
    u32 pidns = getPidInum(task);
    u32 mntns = getMntInum(task);
    ns.pidns = pidns;
    ns.mountns = mntns;
    u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
    if(!is_container_process)
        return 0;

    bpf_printk("Write syscall 2 triggered for fd %u", fd);
    return 0;
}



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

SEC("lsm/file_permission")
int BPF_PROG(file_permission, struct file *file, int mask){
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u8 comm[16] = {0};
    bpf_get_current_comm(comm, 16);
    struct task_struct *task = (struct task_struct*)bpf_get_current_task();
    if(!task)
        return 0;
    struct pid_mount_ns ns;
    u32 pidns = getPidInum(task);
    u32 mntns = getMntInum(task);
    ns.pidns = pidns;
    ns.mountns = mntns;
    u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
    if(!is_container_process)
        return 0;
    u32 syscall = lookup_syscall(ns, FILE_PERMISSION); //For each name space there is only one syscall associated with it?
    
    u32 init_failed = set_syscall_map(pidns, mntns, FILE_PERMISSION, 0);
    if(init_failed)
        return 0;

    bpf_printk("file_permission triggered with syscall number %d and comm %s", syscall, comm);
        
    u32 policy = lookup_policy(pidns, mntns, syscall);
    if(!policy){
        bpf_printk("file_permission triggered! policy allowed");
        return 0;
    }

    struct event *new_event = NULL;
    new_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (new_event == NULL) {
        return 0;
    }
    new_event->pid = pid;
    for (u8 i = 0 ; i < 16 ; i++) new_event->comm[i] = comm[i];
    bpf_ringbuf_submit(new_event, 0);
    return 0;
}

SEC("lsm/task_alloc")
int BPF_PROG(task_alloc, struct task_struct *task, unsigned long clone_flags, int ret){
    if (ret != 0)
        return ret;

    u8 comm[16] = {0};
    bpf_get_current_comm(comm, 16);
    struct task_struct *process_task = (struct task_struct*)bpf_get_current_task();
    if(!process_task)
        return 0;
    struct pid_mount_ns ns;
    u32 pidns = getPidInum(process_task);
    u32 mntns = getMntInum(process_task);
    ns.pidns = pidns;
    ns.mountns = mntns;
    u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
    if(!is_container_process)
        return 0;
    u32 syscall = lookup_syscall(ns, TASK_ALLOC);
    
    u32 init_failed = set_syscall_map(pidns, mntns, TASK_ALLOC, 0);
    if(init_failed)
        return 0;
    bpf_printk("task_alloc LSM Hook triggered! clone_flags = %u", clone_flags);
        
    u32 policy = lookup_policy(pidns, mntns, syscall);
    if(!policy){
        bpf_printk("task_alloc triggered! policy allowed");
        return 0;
    }
    bpf_printk("task_alloc triggered! policy blocked");
    struct pid_syscall_args key;
    key.syscall = syscall;
    key.namespace = ns;
    u32 *flag = bpf_map_lookup_elem(&policy_params_task_alloc, &key);
    if(flag){
        for(int i = 0; i < 16; i++){
            if(flag[i] == 0)
                break;
            if(flag[i] == clone_flags){
                return 0;
            }
        }
    }
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("lsm: detected PID: %d, comm: %s - blocked PID", pid, comm);
    struct event *new_event = NULL;
    new_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (new_event == NULL) {
        return 0;
    }
    new_event->pid = pid;
    for (u8 i = 0 ; i < 16 ; i++) new_event->comm[i] = comm[i];
    bpf_ringbuf_submit(new_event, 0);

    return -EPERM;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(bprm_check, struct linux_binprm *bprm, int ret){
    if (ret != 0)
        return ret;
    u8 comm[16] = {0};
    bpf_get_current_comm(comm, 16);
    struct task_struct *task = (struct task_struct*)bpf_get_current_task();
    if(!task)
        return 0;
    struct pid_mount_ns ns;
    u32 pidns = getPidInum(task);
    u32 mntns = getMntInum(task);
    ns.pidns = pidns;
    ns.mountns = mntns;
    u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
    if(!is_container_process)
        return 0;
    u32 syscall = lookup_syscall(ns, BPRM_CHECK_SECURITY);
    
    u32 init_failed = set_syscall_map(pidns, mntns, BPRM_CHECK_SECURITY, 0);
    if(init_failed)
        return 0;
    
    u8 filename[MAX_PATH_LEN];
    bpf_core_read_str(&filename, sizeof(filename), bprm->filename);
    bpf_printk("bprm_check_security LSM Hook triggered! filename = %s", filename);

    u32 policy = lookup_policy(pidns, mntns, syscall);
    if(!policy)
        return 0;
    
    struct pid_syscall_args key;
    key.syscall = syscall;
    key.namespace = ns;
    // bool is_empty = false;
    u32 is_allowed = 1;
    char *filepath = bpf_map_lookup_elem(&policy_params_bprm_check, &key);
    if(filepath){
        for(int i = 0; i < 16; i++){
            if(filepath[i * MAX_PATH_LEN] != '/')
                break;
            is_allowed = 1;
            for(int j = 0; j < MAX_PATH_LEN; j++){
                // if(!filepath || !(bprm->filename)){
                //     if(!j)
                //         is_empty = true;
                //     break;
                // }
                if(filepath[i * MAX_PATH_LEN + j] == '\0'){
                    is_allowed = 0;
                    // if(!j)
                    //     is_empty = true;
                    break;
                }
                if(filename[j] == '\0'){
                    // if(!j)
                    //     is_empty = true;
                    // is_allowed = 0;
                    break;
                }
                if(filepath[i * MAX_PATH_LEN + j] != filename[j]){
                    is_allowed = 0;
                    break;
                }
            }
            if(is_allowed)
                return 0;
        }
    }
        
    
    
    if (is_allowed) {
        u32 pid = bpf_get_current_pid_tgid() >> 32;
        bpf_printk("lsm: detected PID: %d, comm: %s - blocked PID", pid, comm);
        
        struct event *new_event = NULL;
        new_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
        if (new_event == NULL) {
            return 0;
        }
        new_event->pid = pid;
        for (u8 i = 0 ; i < 16 ; i++) new_event->comm[i] = comm[i];
        bpf_ringbuf_submit(new_event, 0);

        return -EPERM;
    }
    
    return 0;
}

SEC("lsm/ptrace_access_check")
int BPF_PROG(ptrace_check, struct task_struct *child, unsigned int mode, int ret){
    if (ret != 0)
        return ret;

    u8 comm[16] = {0};
    bpf_get_current_comm(comm, 16);
    struct task_struct *task = (struct task_struct*)bpf_get_current_task();
    if(!task)
        return 0;
    struct pid_mount_ns ns;
    u32 pidns = getPidInum(task);
    u32 mntns = getMntInum(task);
    ns.pidns = pidns;
    ns.mountns = mntns;
    u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
    if(!is_container_process)
        return 0;
    u32 syscall = lookup_syscall(ns, PTRACE_ACCESS_CHECK);
    
    u32 init_failed = set_syscall_map(pidns, mntns, PTRACE_ACCESS_CHECK, 0);
    if(init_failed)
        return 0;
    bpf_printk("ptrace_access_check LSM Hook triggered! mode = %u", mode);

    u32 policy = lookup_policy(pidns, mntns, syscall);
    if(!policy)
        return 0;

    struct pid_syscall_args key;
    key.syscall = syscall;
    key.namespace = ns;
    u8 *allow_policy = bpf_map_lookup_elem(&policy_params_ptrace_access, &key);
    if(allow_policy && mode){
        for(int i = 0; i < 16; i++){
            if(allow_policy[i] == 0)
                break;
            if((allow_policy[i] & mode) == mode){
                return 0;
            }
        }
    }
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("lsm: detected PID: %d, comm: %s - blocked PID", pid, comm);
    // Create event, we are going to send this over to userspace.
    
    struct event *new_event = NULL;
    new_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (new_event == NULL) {
        return 0;
    }
    new_event->pid = pid;
    for (u8 i = 0 ; i < 16 ; i++) new_event->comm[i] = comm[i];
    bpf_ringbuf_submit(new_event, 0);

    return -EPERM;
    
    return 0;
}

SEC("lsm/path_chmod")
int BPF_PROG(path_chmod, struct path *path, umode_t mode, int ret){
    if (ret != 0)
        return ret;

    u8 comm[16] = {0};
    bpf_get_current_comm(comm, 16);
    struct task_struct *task = (struct task_struct*)bpf_get_current_task();
    if(!task)
        return 0;
    struct pid_mount_ns ns;
    u32 pidns = getPidInum(task);
    u32 mntns = getMntInum(task);
    ns.pidns = pidns;
    ns.mountns = mntns;
    u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
    if(!is_container_process)
        return 0;
    bpf_printk("path_chmod triggered! in container process");
    if(*is_container_process){
        u32 syscall = lookup_syscall(ns, PATH_CHMOD);
        
        u32 init_failed = set_syscall_map(pidns, mntns, PATH_CHMOD, 0);
        if(init_failed)
            return 0;
        struct pid_syscall_args key;
        key.syscall = syscall;
        key.namespace = ns;
        bpf_printk("path_chmod #1");
        ///
        u8 global_path_buf[MAX_PATH_LEN];

        struct dentry *d = path->dentry;
        int top = 0;
        if(!d)
            return 0;
        // Reset global buffer
        for (int i = 0; i < MAX_PATH_LEN; i++)
            global_path_buf[i] = '\0';
        bpf_printk("path_chmod #2");

        for(int j = 0; j < 10; j++) {
            if(d == d->d_parent || top >= MAX_PATH_LEN - 1 || !d)
                break;
            
            u8 name_tmp[MAX_PATH_LEN];
            bpf_core_read_str(&name_tmp, sizeof(name_tmp), d->d_name.name);
            int len = 0;
            while (name_tmp[len] != '\0' && len < MAX_PATH_LEN - 2) {
                len++;
            }
            if(len < 1)
                return 0;
            bpf_printk("path_chmod #2-1 d_name.name : %s", name_tmp);
            for (int i = len - 1; i >= 0 && top < MAX_PATH_LEN - 2; i--) {
                global_path_buf[top++] = name_tmp[i];
            }
            if (top < MAX_PATH_LEN - 1) {
                global_path_buf[top++] = '/';
            }
            d = d->d_parent;
        }

        bpf_printk("path_chmod #3");
        // Reverse the whole path
        for (int i = 0; i < top / 2; i++) {
            u8 temp = global_path_buf[i];
            global_path_buf[i] = global_path_buf[top - 1 - i];
            global_path_buf[top - 1 - i] = temp;
        }
        ///
        bpf_printk("path_chmod #3-1 global_path_buf : %s", global_path_buf);

        u32 policy = lookup_policy(pidns, mntns, syscall);
        if(!policy){
            bpf_printk("path_chmod triggered! policy allowed");
            return 0;
        }
        char *chmod_allow = bpf_map_lookup_elem(&policy_params_path_chmod, &key);
        if(chmod_allow){
            int is_allowed = 1;
            for(int i = 0; i < 16; i++){
                if(chmod_allow[i * (MAX_PATH_LEN + 2)] != '/')
                    break;
                is_allowed = 1;
                u16 policy_mode = (((u16)(chmod_allow[i * (MAX_PATH_LEN + 2) + 16]) & 0x00FF) << 8) | ((u16)(chmod_allow[i * (MAX_PATH_LEN + 2) + 17]) & 0x00FF);
                bpf_printk("policy_mode : %d", policy_mode);
                for(int j = 0; j < MAX_PATH_LEN; j++){
                    if(chmod_allow[i * (MAX_PATH_LEN + 2) + j] == '\0')
                        is_allowed = 0;
                        break;
                    if(global_path_buf[j] == '\0'){
                        break;
                    }
                    if(chmod_allow[i * (MAX_PATH_LEN + 2) + j] != global_path_buf[j]){
                        is_allowed = 0;
                        break;
                    }
                }
                if(is_allowed){
                    if(policy_mode == mode)
                        return 0;
                    if(policy_mode == 65535)
                        return 0;
                }
            }
        }

        ///
        u32 pid = bpf_get_current_pid_tgid() >> 32;
        bpf_printk("lsm: detected PID: %d, comm: %s - blocked PID", pid, comm);
        // Create event, we are going to send this over to userspace.
        
        struct event *new_event = NULL;
        new_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
        if (new_event == NULL) {
            return 0;
        }
        new_event->pid = pid;
        for (u8 i = 0 ; i < 16 ; i++) new_event->comm[i] = comm[i];
        bpf_ringbuf_submit(new_event, 0);

        return -EPERM;
    }
    return 0;
}

SEC("lsm/file_mprotect")
int BPF_PROG(file_mprotect, struct vm_area_struct *vma, unsigned long reqprot, unsigned long prot, int ret){
    if (ret != 0)
        return ret;

    u8 comm[16] = {0};
    bpf_get_current_comm(comm, 16);
    
    struct task_struct *task = (struct task_struct*)bpf_get_current_task();
    if(!task)
        return 0;
    struct pid_mount_ns ns;
    u32 pidns = getPidInum(task);
    u32 mntns = getMntInum(task);
    ns.pidns = pidns;
    ns.mountns = mntns;
    u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
    if(!is_container_process)
        return 0;
    u32 syscall = lookup_syscall(ns, FILE_MPROTECT);
    
    u32 init_failed = set_syscall_map(pidns, mntns, FILE_MPROTECT, 0);
    if(init_failed)
        return 0;
    bpf_printk("file_mprotect LSM Hook triggered! prot = %u, reqprot = %u", prot, reqprot);
    u32 policy = lookup_policy(pidns, mntns, syscall);
    if(!policy)
        return 0;
    
    struct pid_syscall_args psa;
    psa.syscall = syscall;
    psa.namespace = ns;
    u32 *arr = bpf_map_lookup_elem(&policy_params_file_mprotect, &psa);
    if(!arr){
        for(int i = 0; i < 8; i++){
            if(!arr[i*2] && !arr[i*2 + 1])
                break;
            if(arr[i*2] == 0xFFFFFFFF){
                if(arr[i*2 + 1] == 0xFFFFFFFF){
                    return 0;
                }
                else if(arr[i*2 + 1] == prot){
                    return 0;
                }
            }
            else if(arr[i*2 + 1] == 0xFFFFFFFF){
                if(arr[i*2] == reqprot){
                    return 0;
                }
            }
            else if(arr[i*2] == reqprot && arr[i*2 + 1] == prot){
                return 0;
            }
        }
    }
    

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("lsm: detected PID: %d, comm: %s - blocked PID", pid, comm);
    // Create event, we are going to send this over to userspace.
    
    struct event *new_event = NULL;
    new_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (new_event == NULL) {
        return 0;
    }
    new_event->pid = pid;
    for (u8 i = 0 ; i < 16 ; i++) new_event->comm[i] = comm[i];
    bpf_ringbuf_submit(new_event, 0);

    return -EPERM;
}

SEC("lsm/task_fix_setgid")
int BPF_PROG(fix_setgid, struct cred *new, const struct cred *old, int flags, int ret){
    if (ret != 0)
        return ret;

    u8 comm[16] = {0};
    bpf_get_current_comm(comm, 16);
    struct task_struct *task = (struct task_struct*)bpf_get_current_task();
    if(!task)
        return 0;
    struct pid_mount_ns ns;
    u32 pidns = getPidInum(task);
    u32 mntns = getMntInum(task);
    ns.pidns = pidns;
    ns.mountns = mntns;
    u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
    if(!is_container_process)
        return 0;
    u32 syscall = lookup_syscall(ns, TASK_FIX_SETGID);
    
    u32 init_failed = set_syscall_map(pidns, mntns, TASK_FIX_SETGID, 0);
    if(init_failed)
        return 0;
    bpf_printk("task_fix_setgid LSM Hook triggered! uid = %u, euid = %u, suid = %u", new->gid.val, new->egid.val, new->sgid.val);
    u32 policy = lookup_policy(pidns, mntns, syscall);
    if(!policy)
        return 0;
    struct pid_syscall_args psa;
    psa.syscall = syscall;
    psa.namespace = ns;

    u32 *arr = bpf_map_lookup_elem(&policy_params_fix_setgid, &psa);
    if(arr){
        for(int i = 0; i < 8; i++){
            if(arr[i*3 + 2] == 0xFFFFFFFF){
                if(arr[i*3 + 1] == 0xFFFFFFFF){
                    if(arr[i*3] == 0xFFFFFFFF){
                        return 0;
                    }
                    else if(arr[i*3] == new->gid.val){
                        return 0;
                    }
                }
                else if(arr[i*3 + 1] == new->egid.val){
                    if(arr[i*3] == 0xFFFFFFFF){
                        return 0;
                    }
                    else if(arr[i*3] == new->gid.val){
                        return 0;
                    }
                }
            }
            else if(arr[i*3 + 2] == new->sgid.val){
                if(arr[i*3 + 1] == 0xFFFFFFFF){
                    if(arr[i*3] == 0xFFFFFFFF){
                        return 0;
                    }
                    else if(arr[i*3] == new->gid.val){
                        return 0;
                    }
                }
                else if(arr[i*3 + 1] == new->egid.val){
                    if(arr[i*3] == 0xFFFFFFFF){
                        return 0;
                    }
                    else if(arr[i*3] == new->gid.val){
                        return 0;
                    }
                }
            }
        }
    }
    

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("lsm: detected PID: %d, comm: %s - blocked PID", pid, comm);
    // Create event, we are going to send this over to userspace.
    
    struct event *new_event = NULL;
    new_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (new_event == NULL) {
        return 0;
    }
    new_event->pid = pid;
    for (u8 i = 0 ; i < 16 ; i++) new_event->comm[i] = comm[i];
    bpf_ringbuf_submit(new_event, 0);

    return -EPERM;
}

SEC("lsm/task_fix_setuid")
int BPF_PROG(fix_setuid, struct cred *new, const struct cred *old, int flags, int ret){
    if (ret != 0)
        return ret;

    u8 comm[16] = {0};
    bpf_get_current_comm(comm, 16);
    
    struct task_struct *task = (struct task_struct*)bpf_get_current_task();
    if(!task)
        return 0;
    struct pid_mount_ns ns;
    u32 pidns = getPidInum(task);
    u32 mntns = getMntInum(task);
    ns.pidns = pidns;
    ns.mountns = mntns;
    u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
    if(!is_container_process)
        return 0;
    u32 syscall = lookup_syscall(ns, TASK_FIX_SETUID);
    
    u32 init_failed = set_syscall_map(pidns, mntns, TASK_FIX_SETUID, 0);
    if(init_failed)
        return 0;
    bpf_printk("task_fix_setuid LSM Hook triggered! uid = %u, euid = %u, suid = %u", new->uid.val, new->euid.val, new->suid.val);
    u32 policy = lookup_policy(pidns, mntns, syscall);
    if(!policy)
        return 0;

    struct pid_syscall_args psa;
    psa.syscall = syscall;
    psa.namespace = ns;

    u32 *arr = bpf_map_lookup_elem(&policy_params_fix_setuid, &psa);
    if(arr){
        for(int i = 0; i < 8; i++){
            if(arr[i*3 + 2] == 0xFFFFFFFF){
                if(arr[i*3 + 1] == 0xFFFFFFFF){
                    if(arr[i*3] == 0xFFFFFFFF){
                        return 0;
                    }
                    else if(arr[i*3] == new->uid.val){
                        return 0;
                    }
                }
                else if(arr[i*3 + 1] == new->euid.val){
                    if(arr[i*3] == 0xFFFFFFFF){
                        return 0;
                    }
                    else if(arr[i*3] == new->uid.val){
                        return 0;
                    }
                }
            }
            else if(arr[i*3 + 2] == new->suid.val){
                if(arr[i*3 + 1] == 0xFFFFFFFF){
                    if(arr[i*3] == 0xFFFFFFFF){
                        return 0;
                    }
                    else if(arr[i*3] == new->uid.val){
                        return 0;
                    }
                }
                else if(arr[i*3 + 1] == new->euid.val){
                    if(arr[i*3] == 0xFFFFFFFF){
                        return 0;
                    }
                    else if(arr[i*3] == new->uid.val){
                        return 0;
                    }
                }
            }
        }
    }
    

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("lsm: detected PID: %d, comm: %s - blocked PID", pid, comm);
    // Create event, we are going to send this over to userspace.
    
    struct event *new_event = NULL;
    new_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (new_event == NULL) {
        return 0;
    }
    new_event->pid = pid;
    for (u8 i = 0 ; i < 16 ; i++) new_event->comm[i] = comm[i];
    bpf_ringbuf_submit(new_event, 0);

    return -EPERM;
}

SEC("lsm/socket_accept")
int BPF_PROG(socket_accept, struct socket *sock, struct socket *newsock, int ret){
    if (ret != 0)
        return ret;

    u8 comm[16] = {0};
    bpf_get_current_comm(comm, 16);
    struct task_struct *task = (struct task_struct*)bpf_get_current_task();
    if(!task)
        return 0;
    struct pid_mount_ns ns;
    u32 pidns = getPidInum(task);
    u32 mntns = getMntInum(task);
    ns.pidns = pidns;
    ns.mountns = mntns;
    u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
    if(!is_container_process)
        return 0;
    u32 syscall = lookup_syscall(ns, SOCKET_ACCEPT);
    
    u32 init_failed = set_syscall_map(pidns, mntns, SOCKET_ACCEPT, 0);
    if(init_failed)
        return 0;
    // u32 policy = lookup_policy(pidns, mntns, syscall);
    // if(!policy)
    //     return 0;
    u32 ip_dest = sock->sk->__sk_common.skc_daddr;
    u32 port_dest = (u32)(sock->sk->__sk_common.skc_dport);
    u32 proto_dest = (u32)(sock->sk->sk_protocol);
    bpf_printk("socket_accept LSM Hook triggered! ip_dest = %u, port_dest = %u", ip_dest, port_dest);
    u32 policy = lookup_policy(pidns, mntns, syscall);
    if(!policy)
        return 0;
    struct pid_syscall_args psa;
    psa.syscall = syscall;
    psa.namespace = ns;

    u32 *arr = bpf_map_lookup_elem(&policy_params_socket_accept, &psa);
    if(arr){
        u16 flag = 0;
        u32 policy_ip, policy_port, policy_proto;
        for(int i = 0 ; i < 8; i++){
            if(!arr[i * 3]&& !arr[i * 3 + 1] && !arr[i*3 + 2]){
                break;
            }
            policy_ip = arr[i*3];
            policy_port = arr[i*3 + 1] & 0x0000FFFF;
            policy_proto = arr[i*3 + 2];
            flag = arr[i*3 + 1] >> 16;
            
            if(flag == 0x00){
                if(policy_ip == ip_dest && policy_port == port_dest && policy_proto == proto_dest){
                    return 0;
                }
            }
            else if(flag == 0xfe){
                if(!ip_dest && !port_dest && !proto_dest){
                    return 0;
                }
            }
            else if(flag == 0xfd){
                if(policy_port == port_dest && policy_proto == proto_dest){
                    return 0;
                }
            }
            else if(flag == 0xfb){
                if(policy_ip == ip_dest && policy_proto == proto_dest){
                    return 0;
                }
            }
            else if(flag == 0xf7){
                if(policy_ip == ip_dest && policy_port == port_dest){
                    return 0;
                }
            }
            else if(flag == 0xef){
                if(policy_proto == proto_dest){
                    return 0;
                }
            }
            else if(flag == 0xdf){
                if(policy_port == port_dest){
                    return 0;
                }
            }
            else if(flag == 0xbf){
                if(policy_ip == ip_dest){
                    return 0;
                }
            }
            else if(flag == 0x7f){
                return 0;
            }
        } 
    }
    ///
    
    
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("lsm: detected PID: %d, comm: %s - blocked PID", pid, comm);
    // Create event, we are going to send this over to userspace.
    
    struct event *new_event = NULL;
    new_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (new_event == NULL) {
        return 0;
    }
    new_event->pid = pid;
    for (u8 i = 0 ; i < 16 ; i++) new_event->comm[i] = comm[i];
    bpf_ringbuf_submit(new_event, 0);

    return -EPERM;
} 

SEC("lsm/socket_bind")
int BPF_PROG(socket_bind, struct socket *sock, struct sockaddr *address, int addrlen, int ret){
    if (ret != 0)
        return ret;

    u8 comm[16] = {0};
    bpf_get_current_comm(comm, 16);
    struct task_struct *task = (struct task_struct*)bpf_get_current_task();
    if(!task)
        return 0;
    bpf_printk("bind triggered!");
    struct pid_mount_ns ns;
    u32 pidns = getPidInum(task);
    u32 mntns = getMntInum(task);
    ns.pidns = pidns;
    ns.mountns = mntns;
    u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
    bpf_printk("Check if container process");
    if(!is_container_process)
        return 0;
    bpf_printk("bind triggered2!");
    u32 syscall = lookup_syscall(ns, SOCKET_BIND);
    u32 init_failed = set_syscall_map(pidns, mntns, SOCKET_BIND, 0);
    if(init_failed)
        return 0;
    bpf_printk("bind triggered!3");
    struct sockaddr_in *addr = (struct sockaddr_in *)address;
    if(!addr)
        return 0;
    u32 ip_dest = addr->sin_addr.s_addr;
    u32 port_dest = (u32)(addr->sin_port);
    u32 proto_dest = (u32)(sock->sk->sk_protocol);
    bpf_printk("socket_bind LSM Hook triggered! ip_dest = %u, port_dest = %u", ip_dest, port_dest);
    if (address->sa_family != AF_INET)
    {
        return 0;
    }
    u32 policy = lookup_policy(pidns, mntns, syscall);
    if(!policy)
        return 0;
    struct pid_syscall_args psa;
    psa.syscall = syscall;
    psa.namespace = ns;

    u32 *arr = bpf_map_lookup_elem(&policy_params_socket_bind, &psa);
    if(arr){
        u16 flag = 0;
        u32 policy_ip, policy_port, policy_proto;
        for(int i = 0 ; i < 8; i++){
            if(!arr[i * 3]&& !arr[i * 3 + 1] && !arr[i*3 + 2]){
                break;
            }
            policy_ip = arr[i*3];
            policy_port = arr[i*3 + 1] & 0x0000FFFF;
            policy_proto = arr[i*3 + 2];
            flag = arr[i*3 + 1] >> 16;
            
            if(flag == 0x00){
                if(policy_ip == ip_dest && policy_port == port_dest && policy_proto == proto_dest){
                    return 0;
                }
            }
            else if(flag == 0xfe){
                if(!ip_dest && !port_dest && !proto_dest){
                    return 0;
                }
            }
            else if(flag == 0xfd){
                if(policy_port == port_dest && policy_proto == proto_dest){
                    return 0;
                }
            }
            else if(flag == 0xfb){
                if(policy_ip == ip_dest && policy_proto == proto_dest){
                    return 0;
                }
            }
            else if(flag == 0xf7){
                if(policy_ip == ip_dest && policy_port == port_dest){
                    return 0;
                }
            }
            else if(flag == 0xef){
                if(policy_proto == proto_dest){
                    return 0;
                }
            }
            else if(flag == 0xdf){
                if(policy_port == port_dest){
                    return 0;
                }
            }
            else if(flag == 0xbf){
                if(policy_ip == ip_dest){
                    return 0;
                }
            }
            else if(flag == 0x7f){
                return 0;
            }
        }
    }
    ///
    
    
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("lsm: detected PID: %d, comm: %s - blocked PID", pid, comm);
    // Create event, we are going to send this over to userspace.
    
    struct event *new_event = NULL;
    new_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (new_event == NULL) {
        return 0;
    }
    new_event->pid = pid;
    for (u8 i = 0 ; i < 16 ; i++) new_event->comm[i] = comm[i];
    bpf_ringbuf_submit(new_event, 0);

    return -EPERM;
}

SEC("lsm/socket_connect")
int BPF_PROG(socket_connect, struct socket *sock, struct sockaddr *address, int addrlen, int ret){
    if (ret != 0)
        return ret;

    u8 comm[16] = {0};
    bpf_get_current_comm(comm, 16);
    struct task_struct *task = (struct task_struct*)bpf_get_current_task();
    if(!task)
        return 0;
    struct pid_mount_ns ns;
    u32 pidns = getPidInum(task);
    u32 mntns = getMntInum(task);
    ns.pidns = pidns;
    ns.mountns = mntns;
    u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
    if(!is_container_process)
        return 0;
    u32 syscall = lookup_syscall(ns, SOCKET_CONNECT);
    u32 init_failed = set_syscall_map(pidns, mntns, SOCKET_CONNECT, 0);
    bpf_printk("socket_connect triggered! syscall : %d, ret : %d", syscall, ret);
    if(init_failed)
        return 0;
    if (address->sa_family != AF_INET)
    {
        return 0;
    }
    struct sockaddr_in *addr = (struct sockaddr_in *)address;
    if(!addr)
        return 0;
    u32 ip_dest = addr->sin_addr.s_addr;
    u32 port_dest = (u32)(addr->sin_port);
    u32 proto_dest = (u32)(sock->sk->sk_protocol);
    bpf_printk("socket_connect LSM Hook triggered! ip_dest = %d, port_dest = %d", ip_dest, port_dest);
    u32 policy = lookup_policy(pidns, mntns, syscall);
    if(!policy)
        return 0;
    struct pid_syscall_args psa;
    psa.syscall = syscall;
    psa.namespace = ns;

    u32 *arr = bpf_map_lookup_elem(&policy_params_socket_connect, &psa);
    if(!arr){
        u16 flag = 0;
        u32 policy_ip, policy_port, policy_proto;
        for(int i = 0 ; i < 8; i++){
            if(!arr[i * 3]&& !arr[i * 3 + 1] && !arr[i*3 + 2]){
                break;
            }
            policy_ip = arr[i*3];
            policy_port = arr[i*3 + 1] & 0x0000FFFF;
            policy_proto = arr[i*3 + 2];
            flag = arr[i*3 + 1] >> 16;
            
            if(flag == 0x00){
                if(policy_ip == ip_dest && policy_port == port_dest && policy_proto == proto_dest){
                    return 0;
                }
            }
            else if(flag == 0xfe){
                if(!ip_dest && !port_dest && !proto_dest){
                    return 0;
                }
            }
            else if(flag == 0xfd){
                if(policy_port == port_dest && policy_proto == proto_dest){
                    return 0;
                }
            }
            else if(flag == 0xfb){
                if(policy_ip == ip_dest && policy_proto == proto_dest){
                    return 0;
                }
            }
            else if(flag == 0xf7){
                if(policy_ip == ip_dest && policy_port == port_dest){
                    return 0;
                }
            }
            else if(flag == 0xef){
                if(policy_proto == proto_dest){
                    return 0;
                }
            }
            else if(flag == 0xdf){
                if(policy_port == port_dest){
                    return 0;
                }
            }
            else if(flag == 0xbf){
                if(policy_ip == ip_dest){
                    return 0;
                }
            }
            else if(flag == 0x7f){
                return 0;
            }
        }   
        
    }
    ///
    
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("lsm: detected PID: %d, comm: %s - blocked PID", pid, comm);
    // Create event, we are going to send this over to userspace.
    
    struct event *new_event = NULL;
    new_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (new_event == NULL) {
        return 0;
    }
    new_event->pid = pid;
    for (u8 i = 0 ; i < 16 ; i++) new_event->comm[i] = comm[i];
    bpf_ringbuf_submit(new_event, 0);

    return -EPERM;
}

SEC("lsm/socket_listen")
int BPF_PROG(socket_listen, struct socket *sock, int backlog, int ret){
    if (ret != 0)
        return ret;

    u8 comm[16] = {0};
    bpf_get_current_comm(comm, 16);
    struct task_struct *task = (struct task_struct*)bpf_get_current_task();
    if(!task)
        return 0;
    struct pid_mount_ns ns;
    u32 pidns = getPidInum(task);
    u32 mntns = getMntInum(task);
    ns.pidns = pidns;
    ns.mountns = mntns;
    u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
    if(!is_container_process)
        return 0;
    u32 syscall = lookup_syscall(ns, SOCKET_LISTEN);
    
    u32 init_failed = set_syscall_map(pidns, mntns, SOCKET_LISTEN, 0);
    if(init_failed)
        return 0;
    // u32 policy = lookup_policy(pidns, mntns, syscall);
    // if(!policy)
    //     return 0;
    u32 ip_dest = sock->sk->__sk_common.skc_daddr;
    u32 port_dest = (u32)(sock->sk->__sk_common.skc_dport);
    u32 proto_dest = (u32)(sock->sk->sk_protocol);
    bpf_printk("socket_listen LSM Hook triggered! ip_dest = %u, port_dest = %u", ip_dest, port_dest);
    u32 policy = lookup_policy(pidns, mntns, syscall);
    if(!policy)
        return 0;
    struct pid_syscall_args psa;
    psa.syscall = syscall;
    psa.namespace = ns;

    u32 *arr = bpf_map_lookup_elem(&policy_params_socket_listen, &psa);
    if(arr){
        u16 flag = 0;
        u32 policy_ip, policy_port, policy_proto;
        for(int i = 0 ; i < 8; i++){
            if(!arr[i * 3]&& !arr[i * 3 + 1] && !arr[i*3 + 2]){
                break;
            }
            policy_ip = arr[i*3];
            policy_port = arr[i*3 + 1] & 0x0000FFFF;
            policy_proto = arr[i*3 + 2];
            flag = arr[i*3 + 1] >> 16;
            
            if(flag == 0x00){
                if(policy_ip == ip_dest && policy_port == port_dest && policy_proto == proto_dest){
                    return 0;
                }
            }
            else if(flag == 0xfe){
                if(!ip_dest && !port_dest && !proto_dest){
                    return 0;
                }
            }
            else if(flag == 0xfd){
                if(policy_port == port_dest && policy_proto == proto_dest){
                    return 0;
                }
            }
            else if(flag == 0xfb){
                if(policy_ip == ip_dest && policy_proto == proto_dest){
                    return 0;
                }
            }
            else if(flag == 0xf7){
                if(policy_ip == ip_dest && policy_port == port_dest){
                    return 0;
                }
            }
            else if(flag == 0xef){
                if(policy_proto == proto_dest){
                    return 0;
                }
            }
            else if(flag == 0xdf){
                if(policy_port == port_dest){
                    return 0;
                }
            }
            else if(flag == 0xbf){
                if(policy_ip == ip_dest){
                    return 0;
                }
            }
            else if(flag == 0x7f){
                return 0;
            }
        }   
    }
    ///
    

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("lsm: detected PID: %d, comm: %s - blocked PID", pid, comm);
    // Create event, we are going to send this over to userspace.
    
    struct event *new_event = NULL;
    new_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (new_event == NULL) {
        return 0;
    }
    new_event->pid = pid;
    for (u8 i = 0 ; i < 16 ; i++) new_event->comm[i] = comm[i];
    bpf_ringbuf_submit(new_event, 0);

    return -EPERM;
}

SEC("lsm/socket_recvmsg")
int BPF_PROG(socket_recvmsg, struct socket *sock, struct msghdr *msg, int size, int flags, int ret){
    if (ret != 0)
        return ret;

    u8 comm[16] = {0};
    bpf_get_current_comm(comm, 16);
    struct task_struct *task = (struct task_struct*)bpf_get_current_task();
    if(!task)
        return 0;
    struct pid_mount_ns ns;
    u32 pidns = getPidInum(task);
    u32 mntns = getMntInum(task);
    ns.pidns = pidns;
    ns.mountns = mntns;
    u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
    if(!is_container_process)
        return 0;
    u32 syscall = lookup_syscall(ns, SOCKET_RECVMSG);
    
    u32 init_failed = set_syscall_map(pidns, mntns, SOCKET_RECVMSG, 0);
    if(init_failed)
        return 0;
    // u32 policy = lookup_policy(pidns, mntns, syscall);
    // if(!policy)
    //     return 0;
    u32 ip_dest = sock->sk->__sk_common.skc_daddr;
    u32 port_dest = (u32)(sock->sk->__sk_common.skc_dport);
    u32 proto_dest = (u32)(sock->sk->sk_protocol);
    bpf_printk("socket_recvmsg LSM Hook triggered! ip_dest = %u, port_dest = %u", ip_dest, port_dest);
    u32 policy = lookup_policy(pidns, mntns, syscall);
    if(!policy)
        return 0;
    struct pid_syscall_args psa;
    psa.syscall = syscall;
    psa.namespace = ns;

    u32 *arr = bpf_map_lookup_elem(&policy_params_socket_recvmsg, &psa);
    if(arr){
        u16 flag = 0;
        u32 policy_ip, policy_port, policy_proto;
        for(int i = 0 ; i < 8; i++){
            if(!arr[i * 3]&& !arr[i * 3 + 1] && !arr[i*3 + 2]){
                break;
            }
            policy_ip = arr[i*3];
            policy_port = arr[i*3 + 1] & 0x0000FFFF;
            policy_proto = arr[i*3 + 2];
            flag = arr[i*3 + 1] >> 16;
            
            if(flag == 0x00){
                if(policy_ip == ip_dest && policy_port == port_dest && policy_proto == proto_dest){
                    return 0;
                }
            }
            else if(flag == 0xfe){
                if(!ip_dest && !port_dest && !proto_dest){
                    return 0;
                }
            }
            else if(flag == 0xfd){
                if(policy_port == port_dest && policy_proto == proto_dest){
                    return 0;
                }
            }
            else if(flag == 0xfb){
                if(policy_ip == ip_dest && policy_proto == proto_dest){
                    return 0;
                }
            }
            else if(flag == 0xf7){
                if(policy_ip == ip_dest && policy_port == port_dest){
                    return 0;
                }
            }
            else if(flag == 0xef){
                if(policy_proto == proto_dest){
                    return 0;
                }
            }
            else if(flag == 0xdf){
                if(policy_port == port_dest){
                    return 0;
                }
            }
            else if(flag == 0xbf){
                if(policy_ip == ip_dest){
                    return 0;
                }
            }
            else if(flag == 0x7f){
                return 0;
            }
        }
    }
    ///
       

    
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("lsm: detected PID: %d, comm: %s - blocked PID", pid, comm);
    // Create event, we are going to send this over to userspace.
    
    struct event *new_event = NULL;
    new_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (new_event == NULL) {
        return 0;
    }
    new_event->pid = pid;
    for (u8 i = 0 ; i < 16 ; i++) new_event->comm[i] = comm[i];
    bpf_ringbuf_submit(new_event, 0);

    return -EPERM;
}

SEC("lsm/socket_create")
int BPF_PROG(socket_create, int family, int type, int protocol, int kern, int ret){
    if (ret != 0)
        return ret;
    u8 comm[16] = {0};
    bpf_get_current_comm(comm, 16);
    struct task_struct *task = (struct task_struct*)bpf_get_current_task();
    if(!task)
        return 0;
    struct pid_mount_ns ns;
    u32 pidns = getPidInum(task);
    u32 mntns = getMntInum(task);
    ns.pidns = pidns;
    ns.mountns = mntns;
    u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
    if(!is_container_process)
        return 0;
    u32 syscall = lookup_syscall(ns, SOCKET_CREATE);

    u32 init_failed = set_syscall_map(pidns, mntns, SOCKET_CREATE, 0);
    if(init_failed)
        return 0;
    bpf_printk("socket_create LSM Hook triggered! protocol = %u, type = %u", protocol, type);
    u32 policy = lookup_policy(pidns, mntns, syscall);
    if(!policy)
        return 0;
    struct pid_syscall_args psa;
    psa.syscall = syscall;
    psa.namespace = ns;

    u32 *arr = bpf_map_lookup_elem(&policy_params_socket_create, &psa);
    if(arr){
        for(int i = 0; i < 8; i++){
        if(!arr[i*2] && !arr[i*2 + 1])
            break;
        else if(arr[i*2] == 7){
            if(arr[i*2 + 1] == protocol){
                return 0;
            }
            else if(arr[i*2 + 1] == 7){
                return 0;
            }
        }
        else if(arr[i*2 + 1] == 7){
            if(arr[i * 2] == type){
                return 0;
            }
        }
            else if(arr[i*2] == type && arr[i*2 + 1] == protocol){
                return 0;
            }
        }
    }

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("lsm: detected PID: %d, comm: %s - blocked PID", pid, comm);
    // Create event, we are going to send this over to userspace.
    
    struct event *new_event = NULL;
    new_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (new_event == NULL) {
        return 0;
    }
    new_event->pid = pid;
    for (u8 i = 0 ; i < 16 ; i++) new_event->comm[i] = comm[i];
    bpf_ringbuf_submit(new_event, 0);

    return -EPERM;
}

SEC("lsm/socket_getpeername")
int BPF_PROG(socket_getpeername, struct socket *sock){
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u8 comm[16] = {0};
    bpf_get_current_comm(comm, 16);
    struct task_struct *task = (struct task_struct*)bpf_get_current_task();
    if(!task)
        return 0;
    struct pid_mount_ns ns;
    u32 pidns = getPidInum(task);
    u32 mntns = getMntInum(task);
    ns.pidns = pidns;
    ns.mountns = mntns;
    u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
    if(!is_container_process)
        return 0;
    u32 syscall = lookup_syscall(ns, SOCKET_GETPEERNAME);
    
    u32 init_failed = set_syscall_map(pidns, mntns, SOCKET_GETPEERNAME, 0);
    if(init_failed)
        return 0;
        
    u32 policy = lookup_policy(pidns, mntns, syscall);
    if(!policy){
        return 0;
    }

    struct event *new_event = NULL;
    new_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (new_event == NULL) {
        return 0;
    }
    new_event->pid = pid;
    for (u8 i = 0 ; i < 16 ; i++) new_event->comm[i] = comm[i];
    bpf_ringbuf_submit(new_event, 0);
    return 0;
}

SEC("lsm/socket_sendmsg")
int BPF_PROG(socket_sendmsg, struct socket *sock, struct msghdr *msg, int size){
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u8 comm[16] = {0};
    bpf_get_current_comm(comm, 16);
    struct task_struct *task = (struct task_struct*)bpf_get_current_task();
    if(!task)
        return 0;
    struct pid_mount_ns ns;
    u32 pidns = getPidInum(task);
    u32 mntns = getMntInum(task);
    ns.pidns = pidns;
    ns.mountns = mntns;
    u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
    if(!is_container_process)
        return 0;
    u32 syscall = lookup_syscall(ns, SOCKET_SENDMSG);
    
    u32 init_failed = set_syscall_map(pidns, mntns, SOCKET_SENDMSG, 0);
    if(init_failed)
        return 0;
        
    u32 policy = lookup_policy(pidns, mntns, syscall);
    if(!policy){
        return 0;
    }

    struct event *new_event = NULL;
    new_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (new_event == NULL) {
        return 0;
    }
    new_event->pid = pid;
    for (u8 i = 0 ; i < 16 ; i++) new_event->comm[i] = comm[i];
    bpf_ringbuf_submit(new_event, 0);
    return 0;
}

SEC("lsm/socket_setsockopt")
int BPF_PROG(socket_setsockopt, struct socket *sock, int level, int optname){
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u8 comm[16] = {0};
    bpf_get_current_comm(comm, 16);
    struct task_struct *task = (struct task_struct*)bpf_get_current_task();
    if(!task)
        return 0;
    struct pid_mount_ns ns;
    u32 pidns = getPidInum(task);
    u32 mntns = getMntInum(task);
    ns.pidns = pidns;
    ns.mountns = mntns;
    u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
    if(!is_container_process)
        return 0;
    u32 syscall = lookup_syscall(ns, SOCKET_SETSOCKOPT);
    
    u32 init_failed = set_syscall_map(pidns, mntns, SOCKET_SETSOCKOPT, 0);
    if(init_failed)
        return 0;
        
    u32 policy = lookup_policy(pidns, mntns, syscall);
    if(!policy){
        return 0;
    }

    struct event *new_event = NULL;
    new_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (new_event == NULL) {
        return 0;
    }
    new_event->pid = pid;
    for (u8 i = 0 ; i < 16 ; i++) new_event->comm[i] = comm[i];
    bpf_ringbuf_submit(new_event, 0);
    return 0;
}

SEC("lsm/socket_shutdown")
int BPF_PROG(socket_shutdown, struct socket *sock, int how){
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u8 comm[16] = {0};
    bpf_get_current_comm(comm, 16);
    struct task_struct *task = (struct task_struct*)bpf_get_current_task();
    if(!task)
        return 0;
    struct pid_mount_ns ns;
    u32 pidns = getPidInum(task);
    u32 mntns = getMntInum(task);
    ns.pidns = pidns;
    ns.mountns = mntns;
    u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
    if(!is_container_process)
        return 0;
    u32 syscall = lookup_syscall(ns, SOCKET_SHUTDOWN);
    
    u32 init_failed = set_syscall_map(pidns, mntns, SOCKET_SHUTDOWN, 0);
    if(init_failed)
        return 0;
        
    u32 policy = lookup_policy(pidns, mntns, syscall);
    if(!policy){
        return 0;
    }

    struct event *new_event = NULL;
    new_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (new_event == NULL) {
        return 0;
    }
    new_event->pid = pid;
    for (u8 i = 0 ; i < 16 ; i++) new_event->comm[i] = comm[i];
    bpf_ringbuf_submit(new_event, 0);
    return 0;
}

SEC("lsm/capable")
int BPF_PROG(capable, const struct cred *cred, struct user_namespace *ns, int cap, unsigned int opts){
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u8 comm[16] = {0};
    bpf_get_current_comm(comm, 16);
    struct task_struct *task = (struct task_struct*)bpf_get_current_task();
    if(!task)
        return 0;
    struct pid_mount_ns nss;
    u32 pidns = getPidInum(task);
    u32 mntns = getMntInum(task);
    nss.pidns = pidns;
    nss.mountns = mntns;
    u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &nss);
    if(!is_container_process)
        return 0;
    u32 syscall = lookup_syscall(nss, CAPABLE);
    
    u32 init_failed = set_syscall_map(pidns, mntns, CAPABLE, 0);
    if(init_failed)
        return 0;
        
    u32 policy = lookup_policy(pidns, mntns, syscall);
    if(!policy){
        return 0;
    }

    struct event *new_event = NULL;
    new_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (new_event == NULL) {
        return 0;
    }
    new_event->pid = pid;
    for (u8 i = 0 ; i < 16 ; i++) new_event->comm[i] = comm[i];
    bpf_ringbuf_submit(new_event, 0);
    return 0;
}

SEC("lsm/capget")
int BPF_PROG(capget, struct task_struct *target, kernel_cap_t *effective, kernel_cap_t *inheritable, kernel_cap_t *permitted){
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u8 comm[16] = {0};
    bpf_get_current_comm(comm, 16);
    struct task_struct *task = (struct task_struct*)bpf_get_current_task();
    if(!task)
        return 0;
    struct pid_mount_ns ns;
    u32 pidns = getPidInum(task);
    u32 mntns = getMntInum(task);
    ns.pidns = pidns;
    ns.mountns = mntns;
    u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
    if(!is_container_process)
        return 0;
    u32 syscall = lookup_syscall(ns, CAPGET);
    
    u32 init_failed = set_syscall_map(pidns, mntns, CAPGET, 0);
    if(init_failed)
        return 0;
        
    u32 policy = lookup_policy(pidns, mntns, syscall);
    if(!policy){
        return 0;
    }

    struct event *new_event = NULL;
    new_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (new_event == NULL) {
        return 0;
    }
    new_event->pid = pid;
    for (u8 i = 0 ; i < 16 ; i++) new_event->comm[i] = comm[i];
    bpf_ringbuf_submit(new_event, 0);
    return 0;
}

SEC("lsm/capset")
int BPF_PROG(capset, struct cred *new, const struct cred *old, const kernel_cap_t *effective, const kernel_cap_t *inheritable, const kernel_cap_t *permitted){
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u8 comm[16] = {0};
    bpf_get_current_comm(comm, 16);
    struct task_struct *task = (struct task_struct*)bpf_get_current_task();
    if(!task)
        return 0;
    struct pid_mount_ns ns;
    u32 pidns = getPidInum(task);
    u32 mntns = getMntInum(task);
    ns.pidns = pidns;
    ns.mountns = mntns;
    u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
    if(!is_container_process)
        return 0;
    u32 syscall = lookup_syscall(ns, CAPSET);
    
    u32 init_failed = set_syscall_map(pidns, mntns, CAPSET, 0);
    if(init_failed)
        return 0;
        
    u32 policy = lookup_policy(pidns, mntns, syscall);
    if(!policy){
        return 0;
    }

    struct event *new_event = NULL;
    new_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (new_event == NULL) {
        return 0;
    }
    new_event->pid = pid;
    for (u8 i = 0 ; i < 16 ; i++) new_event->comm[i] = comm[i];
    bpf_ringbuf_submit(new_event, 0);
    return 0;
}

SEC("lsm/quotactl")
int BPF_PROG(quotactl, int cmds, int type, int id, struct super_block *sb){
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u8 comm[16] = {0};
    bpf_get_current_comm(comm, 16);
    struct task_struct *task = (struct task_struct*)bpf_get_current_task();
    if(!task)
        return 0;
    struct pid_mount_ns ns;
    u32 pidns = getPidInum(task);
    u32 mntns = getMntInum(task);
    ns.pidns = pidns;
    ns.mountns = mntns;
    u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
    if(!is_container_process)
        return 0;
    u32 syscall = lookup_syscall(ns, QUOTACTL);
    
    u32 init_failed = set_syscall_map(pidns, mntns, QUOTACTL, 0);
    if(init_failed)
        return 0;
        
    u32 policy = lookup_policy(pidns, mntns, syscall);
    if(!policy){
        return 0;
    }

    struct event *new_event = NULL;
    new_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (new_event == NULL) {
        return 0;
    }
    new_event->pid = pid;
    for (u8 i = 0 ; i < 16 ; i++) new_event->comm[i] = comm[i];
    bpf_ringbuf_submit(new_event, 0);
    return 0;
}

SEC("lsm/syslog")
int BPF_PROG(syslog, int type){
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u8 comm[16] = {0};
    bpf_get_current_comm(comm, 16);
    struct task_struct *task = (struct task_struct*)bpf_get_current_task();
    if(!task)
        return 0;
    struct pid_mount_ns ns;
    u32 pidns = getPidInum(task);
    u32 mntns = getMntInum(task);
    ns.pidns = pidns;
    ns.mountns = mntns;
    u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
    if(!is_container_process)
        return 0;
    u32 syscall = lookup_syscall(ns, SYSLOG);
    
    u32 init_failed = set_syscall_map(pidns, mntns, SYSLOG, 0);
    if(init_failed)
        return 0;
        
    u32 policy = lookup_policy(pidns, mntns, syscall);
    if(!policy){
        return 0;
    }

    struct event *new_event = NULL;
    new_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (new_event == NULL) {
        return 0;
    }
    new_event->pid = pid;
    for (u8 i = 0 ; i < 16 ; i++) new_event->comm[i] = comm[i];
    bpf_ringbuf_submit(new_event, 0);
    return 0;
}

SEC("lsm/settime")
int BPF_PROG(settime, const struct timespec64 *ts, const struct timezone *tz){
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u8 comm[16] = {0};
    bpf_get_current_comm(comm, 16);
    struct task_struct *task = (struct task_struct*)bpf_get_current_task();
    if(!task)
        return 0;
    struct pid_mount_ns ns;
    u32 pidns = getPidInum(task);
    u32 mntns = getMntInum(task);
    ns.pidns = pidns;
    ns.mountns = mntns;
    u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
    if(!is_container_process)
        return 0;
    u32 syscall = lookup_syscall(ns, SETTIME);
    
    u32 init_failed = set_syscall_map(pidns, mntns, SETTIME, 0);
    if(init_failed)
        return 0;
        
    u32 policy = lookup_policy(pidns, mntns, syscall);
    if(!policy){
        return 0;
    }

    struct event *new_event = NULL;
    new_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (new_event == NULL) {
        return 0;
    }
    new_event->pid = pid;
    for (u8 i = 0 ; i < 16 ; i++) new_event->comm[i] = comm[i];
    bpf_ringbuf_submit(new_event, 0);
    return 0;
}



SEC("lsm/sb_free_mnt_opts")
int BPF_PROG(sb_free_mnt_opts, void **mnt_opts){
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u8 comm[16] = {0};
    bpf_get_current_comm(comm, 16);
    struct task_struct *task = (struct task_struct*)bpf_get_current_task();
    if(!task)
        return 0;
    struct pid_mount_ns ns;
    u32 pidns = getPidInum(task);
    u32 mntns = getMntInum(task);
    ns.pidns = pidns;
    ns.mountns = mntns;
    u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
    if(!is_container_process)
        return 0;
    u32 syscall = lookup_syscall(ns, SB_FREE_MNT_OPTS);
    
    u32 init_failed = set_syscall_map(pidns, mntns, SB_FREE_MNT_OPTS, 0);
    if(init_failed)
        return 0;
        
    u32 policy = lookup_policy(pidns, mntns, syscall);
    if(!policy){
        return 0;
    }

    struct event *new_event = NULL;
    new_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (new_event == NULL) {
        return 0;
    }
    new_event->pid = pid;
    for (u8 i = 0 ; i < 16 ; i++) new_event->comm[i] = comm[i];
    bpf_ringbuf_submit(new_event, 0);
    return 0;
}


SEC("lsm/sb_statfs")
int BPF_PROG(sb_statfs, struct dentry *dentry){
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u8 comm[16] = {0};
    bpf_get_current_comm(comm, 16);
    struct task_struct *task = (struct task_struct*)bpf_get_current_task();
    if(!task)
        return 0;
    struct pid_mount_ns ns;
    u32 pidns = getPidInum(task);
    u32 mntns = getMntInum(task);
    ns.pidns = pidns;
    ns.mountns = mntns;
    u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
    if(!is_container_process)
        return 0;
    u32 syscall = lookup_syscall(ns, SB_STATFS);
    
    u32 init_failed = set_syscall_map(pidns, mntns, SB_STATFS, 0);
    if(init_failed)
        return 0;
        
    u32 policy = lookup_policy(pidns, mntns, syscall);
    if(!policy){
        return 0;
    }

    struct event *new_event = NULL;
    new_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (new_event == NULL) {
        return 0;
    }
    new_event->pid = pid;
    for (u8 i = 0 ; i < 16 ; i++) new_event->comm[i] = comm[i];
    bpf_ringbuf_submit(new_event, 0);
    return 0;
}


SEC("lsm/sb_pivotroot")
int BPF_PROG(sb_pivotroot, const struct path *old_path, const struct path *new_path){
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u8 comm[16] = {0};
    bpf_get_current_comm(comm, 16);
    struct task_struct *task = (struct task_struct*)bpf_get_current_task();
    if(!task)
        return 0;
    struct pid_mount_ns ns;
    u32 pidns = getPidInum(task);
    u32 mntns = getMntInum(task);
    ns.pidns = pidns;
    ns.mountns = mntns;
    u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
    if(!is_container_process)
        return 0;
    u32 syscall = lookup_syscall(ns, SB_PIVOTROOT);
    
    u32 init_failed = set_syscall_map(pidns, mntns, SB_PIVOTROOT, 0);
    if(init_failed)
        return 0;
        
    u32 policy = lookup_policy(pidns, mntns, syscall);
    if(!policy){
        return 0;
    }

    struct event *new_event = NULL;
    new_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (new_event == NULL) {
        return 0;
    }
    new_event->pid = pid;
    for (u8 i = 0 ; i < 16 ; i++) new_event->comm[i] = comm[i];
    bpf_ringbuf_submit(new_event, 0);
    return 0;
}


SEC("lsm/move_mount")
int BPF_PROG(move_mount, const struct path *from_path, const struct path *to_path){
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u8 comm[16] = {0};
    bpf_get_current_comm(comm, 16);
    struct task_struct *task = (struct task_struct*)bpf_get_current_task();
    if(!task)
        return 0;
    struct pid_mount_ns ns;
    u32 pidns = getPidInum(task);
    u32 mntns = getMntInum(task);
    ns.pidns = pidns;
    ns.mountns = mntns;
    u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
    if(!is_container_process)
        return 0;
    u32 syscall = lookup_syscall(ns, MOVE_MOUNT);
    
    u32 init_failed = set_syscall_map(pidns, mntns, MOVE_MOUNT, 0);
    if(init_failed)
        return 0;
        
    u32 policy = lookup_policy(pidns, mntns, syscall);
    if(!policy){
        return 0;
    }

    struct event *new_event = NULL;
    new_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (new_event == NULL) {
        return 0;
    }
    new_event->pid = pid;
    for (u8 i = 0 ; i < 16 ; i++) new_event->comm[i] = comm[i];
    bpf_ringbuf_submit(new_event, 0);
    return 0;
}


SEC("lsm/path_notify")
int BPF_PROG(path_notify, const struct path *path, u64 mask, unsigned int obj_type){
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u8 comm[16] = {0};
    bpf_get_current_comm(comm, 16);
    struct task_struct *task = (struct task_struct*)bpf_get_current_task();
    if(!task)
        return 0;
    struct pid_mount_ns ns;
    u32 pidns = getPidInum(task);
    u32 mntns = getMntInum(task);
    ns.pidns = pidns;
    ns.mountns = mntns;
    u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
    if(!is_container_process)
        return 0;
    u32 syscall = lookup_syscall(ns, PATH_NOTIFY);
    
    u32 init_failed = set_syscall_map(pidns, mntns, PATH_NOTIFY, 0);
    if(init_failed)
        return 0;
        
    u32 policy = lookup_policy(pidns, mntns, syscall);
    if(!policy){
        return 0;
    }

    struct event *new_event = NULL;
    new_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (new_event == NULL) {
        return 0;
    }
    new_event->pid = pid;
    for (u8 i = 0 ; i < 16 ; i++) new_event->comm[i] = comm[i];
    bpf_ringbuf_submit(new_event, 0);
    return 0;
}


SEC("lsm/path_mkdir")
int BPF_PROG(path_mkdir, const struct path *dir, struct dentry *dentry, umode_t mode){
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u8 comm[16] = {0};
    bpf_get_current_comm(comm, 16);
    struct task_struct *task = (struct task_struct*)bpf_get_current_task();
    if(!task)
        return 0;
    struct pid_mount_ns ns;
    u32 pidns = getPidInum(task);
    u32 mntns = getMntInum(task);
    ns.pidns = pidns;
    ns.mountns = mntns;
    u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
    if(!is_container_process)
        return 0;
    u32 syscall = lookup_syscall(ns, PATH_MKDIR);
    
    u32 init_failed = set_syscall_map(pidns, mntns, PATH_MKDIR, 0);
    if(init_failed)
        return 0;
        
    u32 policy = lookup_policy(pidns, mntns, syscall);
    if(!policy){
        return 0;
    }

    struct event *new_event = NULL;
    new_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (new_event == NULL) {
        return 0;
    }
    new_event->pid = pid;
    for (u8 i = 0 ; i < 16 ; i++) new_event->comm[i] = comm[i];
    bpf_ringbuf_submit(new_event, 0);
    return 0;
}


SEC("lsm/path_rmdir")
int BPF_PROG(path_rmdir, const struct path *dir, struct dentry *dentry){
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u8 comm[16] = {0};
    bpf_get_current_comm(comm, 16);
    struct task_struct *task = (struct task_struct*)bpf_get_current_task();
    if(!task)
        return 0;
    struct pid_mount_ns ns;
    u32 pidns = getPidInum(task);
    u32 mntns = getMntInum(task);
    ns.pidns = pidns;
    ns.mountns = mntns;
    u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
    if(!is_container_process)
        return 0;
    u32 syscall = lookup_syscall(ns, PATH_RMDIR);
    
    u32 init_failed = set_syscall_map(pidns, mntns, PATH_RMDIR, 0);
    if(init_failed)
        return 0;
        
    u32 policy = lookup_policy(pidns, mntns, syscall);
    if(!policy){
        return 0;
    }

    struct event *new_event = NULL;
    new_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (new_event == NULL) {
        return 0;
    }
    new_event->pid = pid;
    for (u8 i = 0 ; i < 16 ; i++) new_event->comm[i] = comm[i];
    bpf_ringbuf_submit(new_event, 0);
    return 0;
}


SEC("lsm/path_unlink")
int BPF_PROG(path_unlink, const struct path *dir, struct dentry *dentry){
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u8 comm[16] = {0};
    bpf_get_current_comm(comm, 16);
    struct task_struct *task = (struct task_struct*)bpf_get_current_task();
    if(!task)
        return 0;
    struct pid_mount_ns ns;
    u32 pidns = getPidInum(task);
    u32 mntns = getMntInum(task);
    ns.pidns = pidns;
    ns.mountns = mntns;
    u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
    if(!is_container_process)
        return 0;
    u32 syscall = lookup_syscall(ns, PATH_UNLINK);
    
    u32 init_failed = set_syscall_map(pidns, mntns, PATH_UNLINK, 0);
    if(init_failed)
        return 0;
        
    u32 policy = lookup_policy(pidns, mntns, syscall);
    if(!policy){
        return 0;
    }

    struct event *new_event = NULL;
    new_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (new_event == NULL) {
        return 0;
    }
    new_event->pid = pid;
    for (u8 i = 0 ; i < 16 ; i++) new_event->comm[i] = comm[i];
    bpf_ringbuf_submit(new_event, 0);
    return 0;
}


SEC("lsm/path_symlink")
int BPF_PROG(path_symlink, const struct path *dir, struct dentry *dentry, const char *old_name){
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u8 comm[16] = {0};
    bpf_get_current_comm(comm, 16);
    struct task_struct *task = (struct task_struct*)bpf_get_current_task();
    if(!task)
        return 0;
    struct pid_mount_ns ns;
    u32 pidns = getPidInum(task);
    u32 mntns = getMntInum(task);
    ns.pidns = pidns;
    ns.mountns = mntns;
    u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
    if(!is_container_process)
        return 0;
    u32 syscall = lookup_syscall(ns, PATH_SYMLINK);
    
    u32 init_failed = set_syscall_map(pidns, mntns, PATH_SYMLINK, 0);
    if(init_failed)
        return 0;
        
    u32 policy = lookup_policy(pidns, mntns, syscall);
    if(!policy){
        return 0;
    }

    struct event *new_event = NULL;
    new_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (new_event == NULL) {
        return 0;
    }
    new_event->pid = pid;
    for (u8 i = 0 ; i < 16 ; i++) new_event->comm[i] = comm[i];
    bpf_ringbuf_submit(new_event, 0);
    return 0;
}


SEC("lsm/path_link")
int BPF_PROG(path_link, struct dentry *old_dentry, const struct path *new_dir, struct dentry *new_dentry){
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u8 comm[16] = {0};
    bpf_get_current_comm(comm, 16);
    struct task_struct *task = (struct task_struct*)bpf_get_current_task();
    if(!task)
        return 0;
    struct pid_mount_ns ns;
    u32 pidns = getPidInum(task);
    u32 mntns = getMntInum(task);
    ns.pidns = pidns;
    ns.mountns = mntns;
    u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
    if(!is_container_process)
        return 0;
    u32 syscall = lookup_syscall(ns, PATH_LINK);
    
    u32 init_failed = set_syscall_map(pidns, mntns, PATH_LINK, 0);
    if(init_failed)
        return 0;
        
    u32 policy = lookup_policy(pidns, mntns, syscall);
    if(!policy){
        return 0;
    }

    struct event *new_event = NULL;
    new_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (new_event == NULL) {
        return 0;
    }
    new_event->pid = pid;
    for (u8 i = 0 ; i < 16 ; i++) new_event->comm[i] = comm[i];
    bpf_ringbuf_submit(new_event, 0);
    return 0;
}


SEC("lsm/path_rename")
int BPF_PROG(path_rename, const struct path *old_dir, struct dentry *old_dentry, const struct path *new_dir, struct dentry *new_dentry, unsigned int flags){
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u8 comm[16] = {0};
    bpf_get_current_comm(comm, 16);
    struct task_struct *task = (struct task_struct*)bpf_get_current_task();
    if(!task)
        return 0;
    struct pid_mount_ns ns;
    u32 pidns = getPidInum(task);
    u32 mntns = getMntInum(task);
    ns.pidns = pidns;
    ns.mountns = mntns;
    u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
    if(!is_container_process)
        return 0;
    u32 syscall = lookup_syscall(ns, PATH_RENAME);
    
    u32 init_failed = set_syscall_map(pidns, mntns, PATH_RENAME, 0);
    if(init_failed)
        return 0;
        
    u32 policy = lookup_policy(pidns, mntns, syscall);
    if(!policy){
        return 0;
    }

    struct event *new_event = NULL;
    new_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (new_event == NULL) {
        return 0;
    }
    new_event->pid = pid;
    for (u8 i = 0 ; i < 16 ; i++) new_event->comm[i] = comm[i];
    bpf_ringbuf_submit(new_event, 0);
    return 0;
}


SEC("lsm/path_truncate")
int BPF_PROG(path_truncate, const struct path *path){
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u8 comm[16] = {0};
    bpf_get_current_comm(comm, 16);
    struct task_struct *task = (struct task_struct*)bpf_get_current_task();
    if(!task)
        return 0;
    struct pid_mount_ns ns;
    u32 pidns = getPidInum(task);
    u32 mntns = getMntInum(task);
    ns.pidns = pidns;
    ns.mountns = mntns;
    u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
    if(!is_container_process)
        return 0;
    u32 syscall = lookup_syscall(ns, PATH_TRUNCATE);
    
    u32 init_failed = set_syscall_map(pidns, mntns, PATH_TRUNCATE, 0);
    if(init_failed)
        return 0;
        
    u32 policy = lookup_policy(pidns, mntns, syscall);
    if(!policy){
        return 0;
    }

    struct event *new_event = NULL;
    new_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (new_event == NULL) {
        return 0;
    }
    new_event->pid = pid;
    for (u8 i = 0 ; i < 16 ; i++) new_event->comm[i] = comm[i];
    bpf_ringbuf_submit(new_event, 0);
    return 0;
}


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


SEC("lsm/path_chroot")
int BPF_PROG(path_chroot, const struct path *path){
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u8 comm[16] = {0};
    bpf_get_current_comm(comm, 16);
    struct task_struct *task = (struct task_struct*)bpf_get_current_task();
    if(!task)
        return 0;
    struct pid_mount_ns ns;
    u32 pidns = getPidInum(task);
    u32 mntns = getMntInum(task);
    ns.pidns = pidns;
    ns.mountns = mntns;
    u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
    if(!is_container_process)
        return 0;
    u32 syscall = lookup_syscall(ns, PATH_CHROOT);
    
    u32 init_failed = set_syscall_map(pidns, mntns, PATH_CHROOT, 0);
    if(init_failed)
        return 0;
        
    u32 policy = lookup_policy(pidns, mntns, syscall);
    if(!policy){
        return 0;
    }

    struct event *new_event = NULL;
    new_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (new_event == NULL) {
        return 0;
    }
    new_event->pid = pid;
    for (u8 i = 0 ; i < 16 ; i++) new_event->comm[i] = comm[i];
    bpf_ringbuf_submit(new_event, 0);
    return 0;
}


SEC("lsm/mmap_file")
int BPF_PROG(mmap_file, struct file *file, unsigned long prot, unsigned long flags){
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u8 comm[16] = {0};
    bpf_get_current_comm(comm, 16);
    struct task_struct *task = (struct task_struct*)bpf_get_current_task();
    if(!task)
        return 0;
    struct pid_mount_ns ns;
    u32 pidns = getPidInum(task);
    u32 mntns = getMntInum(task);
    ns.pidns = pidns;
    ns.mountns = mntns;
    u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
    if(!is_container_process)
        return 0;
    u32 syscall = lookup_syscall(ns, MMAP_FILE);
    
    u32 init_failed = set_syscall_map(pidns, mntns, MMAP_FILE, 0);
    if(init_failed)
        return 0;
        
    u32 policy = lookup_policy(pidns, mntns, syscall);
    if(!policy){
        return 0;
    }

    struct event *new_event = NULL;
    new_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (new_event == NULL) {
        return 0;
    }
    new_event->pid = pid;
    for (u8 i = 0 ; i < 16 ; i++) new_event->comm[i] = comm[i];
    bpf_ringbuf_submit(new_event, 0);
    return 0;
}


SEC("lsm/mmap_addr")
int BPF_PROG(mmap_addr, unsigned long addr){
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u8 comm[16] = {0};
    bpf_get_current_comm(comm, 16);
    struct task_struct *task = (struct task_struct*)bpf_get_current_task();
    if(!task)
        return 0;
    struct pid_mount_ns ns;
    u32 pidns = getPidInum(task);
    u32 mntns = getMntInum(task);
    ns.pidns = pidns;
    ns.mountns = mntns;
    u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
    if(!is_container_process)
        return 0;
    u32 syscall = lookup_syscall(ns, MMAP_ADDR);
    
    u32 init_failed = set_syscall_map(pidns, mntns, MMAP_ADDR, 0);
    if(init_failed)
        return 0;
        
    u32 policy = lookup_policy(pidns, mntns, syscall);
    if(!policy){
        return 0;
    }

    struct event *new_event = NULL;
    new_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (new_event == NULL) {
        return 0;
    }
    new_event->pid = pid;
    for (u8 i = 0 ; i < 16 ; i++) new_event->comm[i] = comm[i];
    bpf_ringbuf_submit(new_event, 0);
    return 0;
}


SEC("lsm/file_fcntl")
int BPF_PROG(file_fcntl, struct file *file, unsigned int cmd, unsigned long arg){
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u8 comm[16] = {0};
    bpf_get_current_comm(comm, 16);
    struct task_struct *task = (struct task_struct*)bpf_get_current_task();
    if(!task)
        return 0;
    struct pid_mount_ns ns;
    u32 pidns = getPidInum(task);
    u32 mntns = getMntInum(task);
    ns.pidns = pidns;
    ns.mountns = mntns;
    u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
    if(!is_container_process)
        return 0;
    u32 syscall = lookup_syscall(ns, FILE_FCNTL);
    
    u32 init_failed = set_syscall_map(pidns, mntns, FILE_FCNTL, 0);
    if(init_failed)
        return 0;
        
    u32 policy = lookup_policy(pidns, mntns, syscall);
    if(!policy){
        return 0;
    }

    struct event *new_event = NULL;
    new_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (new_event == NULL) {
        return 0;
    }
    new_event->pid = pid;
    for (u8 i = 0 ; i < 16 ; i++) new_event->comm[i] = comm[i];
    bpf_ringbuf_submit(new_event, 0);
    return 0;
}


SEC("lsm/task_setpgid")
int BPF_PROG(task_setpgid, struct task_struct *p, pid_t pgid){
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u8 comm[16] = {0};
    bpf_get_current_comm(comm, 16);
    struct task_struct *task = (struct task_struct*)bpf_get_current_task();
    if(!task)
        return 0;
    struct pid_mount_ns ns;
    u32 pidns = getPidInum(task);
    u32 mntns = getMntInum(task);
    ns.pidns = pidns;
    ns.mountns = mntns;
    u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
    if(!is_container_process)
        return 0;
    u32 syscall = lookup_syscall(ns, TASK_SETPGID);
    
    u32 init_failed = set_syscall_map(pidns, mntns, TASK_SETPGID, 0);
    if(init_failed)
        return 0;
        
    u32 policy = lookup_policy(pidns, mntns, syscall);
    if(!policy){
        return 0;
    }

    struct event *new_event = NULL;
    new_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (new_event == NULL) {
        return 0;
    }
    new_event->pid = pid;
    for (u8 i = 0 ; i < 16 ; i++) new_event->comm[i] = comm[i];
    bpf_ringbuf_submit(new_event, 0);
    return 0;
}


SEC("lsm/task_getpgid")
int BPF_PROG(task_getpgid, struct task_struct *p){
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u8 comm[16] = {0};
    bpf_get_current_comm(comm, 16);
    struct task_struct *task = (struct task_struct*)bpf_get_current_task();
    if(!task)
        return 0;
    struct pid_mount_ns ns;
    u32 pidns = getPidInum(task);
    u32 mntns = getMntInum(task);
    ns.pidns = pidns;
    ns.mountns = mntns;
    u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
    if(!is_container_process)
        return 0;
    u32 syscall = lookup_syscall(ns, TASK_GETPGID);
    
    u32 init_failed = set_syscall_map(pidns, mntns, TASK_GETPGID, 0);
    if(init_failed)
        return 0;
        
    u32 policy = lookup_policy(pidns, mntns, syscall);
    if(!policy){
        return 0;
    }

    struct event *new_event = NULL;
    new_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (new_event == NULL) {
        return 0;
    }
    new_event->pid = pid;
    for (u8 i = 0 ; i < 16 ; i++) new_event->comm[i] = comm[i];
    bpf_ringbuf_submit(new_event, 0);
    return 0;
}


SEC("lsm/task_getsid")
int BPF_PROG(task_getsid, struct task_struct *p){
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u8 comm[16] = {0};
    bpf_get_current_comm(comm, 16);
    struct task_struct *task = (struct task_struct*)bpf_get_current_task();
    if(!task)
        return 0;
    struct pid_mount_ns ns;
    u32 pidns = getPidInum(task);
    u32 mntns = getMntInum(task);
    ns.pidns = pidns;
    ns.mountns = mntns;
    u32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);
    if(!is_container_process)
        return 0;
    u32 syscall = lookup_syscall(ns, TASK_GETSID);
    
    u32 init_failed = set_syscall_map(pidns, mntns, TASK_GETSID, 0);
    if(init_failed)
        return 0;
        
    u32 policy = lookup_policy(pidns, mntns, syscall);
    if(!policy){
        return 0;
    }

    struct event *new_event = NULL;
    new_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (new_event == NULL) {
        return 0;
    }
    new_event->pid = pid;
    for (u8 i = 0 ; i < 16 ; i++) new_event->comm[i] = comm[i];
    bpf_ringbuf_submit(new_event, 0);
    return 0;
}