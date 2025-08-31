//go:build amd64

package main

import "C"
import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"os"
	"os/signal"
	"path"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

const (
	binPath   = "./test/heap_test"
	symbol    = "wrap_free"
	bpfFSPath = "/sys/fs/bpf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64 -type event -tags linux bpf monitoring.c

func main() {
	// buffered channel 생성
	stopper := make(chan os.Signal, 1)
	// 지정한 시그널(os.Interrupt)을 받을 수 있는 채널을 받아 등록
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	fn := "daemon_map"
	pinpath := path.Join(bpfFSPath, fn)
	if err := os.MkdirAll(pinpath, os.ModePerm); err != nil {
		log.Fatalf("failed to create bpf fs subpath: %+v", err)
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: pinpath,
		},
	}); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
	defer objs.Close()

	rtp_sys_enter, err := link.AttachRawTracepoint(link.RawTracepointOptions{Name: "sys_enter", Program: objs.RtpSysEnter})
	if err != nil {
		log.Fatalf("opening rtp_sys_enter: %s", err)
	}
	defer rtp_sys_enter.Close()
	log.Println("rtp_sys_enter Attached!")

	// rtp_sys_enter_tail, err := link.AttachRawTracepoint(link.RawTracepointOptions{Name:"sys_enter_tail",Program: objs.RtpSysEnterTail})
	// if err != nil {
	// 	log.Fatalf("opening rtp_sys_enter_tail: %s", err)
	// }
	// defer rtp_sys_enter_tail.Close()
	// log.Println("rtp_sys_enter_tail Attached!")

	sys_accept_hook, _ := link.Tracepoint("syscalls", "sys_enter_accept", objs.SysAcceptCallback, nil)
	defer sys_accept_hook.Close()
	log.Println("sys_accept kprobe attached!")

	sys_accept4_hook, _ := link.Tracepoint("syscalls", "sys_enter_accept4", objs.SysAccept4Callback, nil)
	defer sys_accept4_hook.Close()
	log.Println("sys_accept4 kprobe attached!")

	sys_access_hook, _ := link.Tracepoint("syscalls", "sys_enter_access", objs.SysAccessCallback, nil)
	defer sys_access_hook.Close()
	log.Println("sys_access kprobe attached!")

	sys_acct_hook, _ := link.Tracepoint("syscalls", "sys_enter_acct", objs.SysAcctCallback, nil)
	defer sys_acct_hook.Close()
	log.Println("sys_acct kprobe attached!")

	sys_add_key_hook, _ := link.Tracepoint("syscalls", "sys_enter_add_key", objs.SysAddKeyCallback, nil)
	defer sys_add_key_hook.Close()
	log.Println("sys_add_key kprobe attached!")

	sys_adjtimex_hook, _ := link.Tracepoint("syscalls", "sys_enter_adjtimex", objs.SysAdjtimexCallback, nil)
	defer sys_adjtimex_hook.Close()
	log.Println("sys_adjtimex kprobe attached!")

	sys_alarm_hook, _ := link.Tracepoint("syscalls", "sys_enter_alarm", objs.SysAlarmCallback, nil)
	defer sys_alarm_hook.Close()
	log.Println("sys_alarm kprobe attached!")

	sys_arch_prctl_hook, _ := link.Tracepoint("syscalls", "sys_enter_arch_prctl", objs.SysArchPrctlCallback, nil)
	defer sys_arch_prctl_hook.Close()
	log.Println("sys_arch_prctl kprobe attached!")

	sys_bind_hook, _ := link.Tracepoint("syscalls", "sys_enter_bind", objs.SysBindCallback, nil)
	defer sys_bind_hook.Close()
	log.Println("sys_bind kprobe attached!")

	sys_bpf_hook, _ := link.Tracepoint("syscalls", "sys_enter_bpf", objs.SysBpfCallback, nil)
	defer sys_bpf_hook.Close()
	log.Println("sys_bpf kprobe attached!")

	sys_brk_hook, _ := link.Tracepoint("syscalls", "sys_enter_brk", objs.SysBrkCallback, nil)
	defer sys_brk_hook.Close()
	log.Println("sys_brk kprobe attached!")

	sys_capget_hook, _ := link.Tracepoint("syscalls", "sys_enter_capget", objs.SysCapgetCallback, nil)
	defer sys_capget_hook.Close()
	log.Println("sys_capget kprobe attached!")

	sys_capset_hook, _ := link.Tracepoint("syscalls", "sys_enter_capset", objs.SysCapsetCallback, nil)
	defer sys_capset_hook.Close()
	log.Println("sys_capset kprobe attached!")

	sys_chdir_hook, _ := link.Tracepoint("syscalls", "sys_enter_chdir", objs.SysChdirCallback, nil)
	defer sys_chdir_hook.Close()
	log.Println("sys_chdir kprobe attached!")

	sys_chmod_hook, _ := link.Tracepoint("syscalls", "sys_enter_chmod", objs.SysChmodCallback, nil)
	defer sys_chmod_hook.Close()
	log.Println("sys_chmod kprobe attached!")

	sys_chown_hook, _ := link.Tracepoint("syscalls", "sys_enter_chown", objs.SysChownCallback, nil)
	defer sys_chown_hook.Close()
	log.Println("sys_chown kprobe attached!")

	sys_chroot_hook, _ := link.Tracepoint("syscalls", "sys_enter_chroot", objs.SysChrootCallback, nil)
	defer sys_chroot_hook.Close()
	log.Println("sys_chroot kprobe attached!")

	sys_clock_adjtime_hook, _ := link.Tracepoint("syscalls", "sys_enter_clock_adjtime", objs.SysClockAdjtimeCallback, nil)
	defer sys_clock_adjtime_hook.Close()
	log.Println("sys_clock_adjtime kprobe attached!")

	sys_clock_getres_hook, _ := link.Tracepoint("syscalls", "sys_enter_clock_getres", objs.SysClockGetresCallback, nil)
	defer sys_clock_getres_hook.Close()
	log.Println("sys_clock_getres kprobe attached!")

	sys_clock_gettime_hook, _ := link.Tracepoint("syscalls", "sys_enter_clock_gettime", objs.SysClockGettimeCallback, nil)
	defer sys_clock_gettime_hook.Close()
	log.Println("sys_clock_gettime kprobe attached!")

	sys_clock_nanosleep_hook, _ := link.Tracepoint("syscalls", "sys_enter_clock_nanosleep", objs.SysClockNanosleepCallback, nil)
	defer sys_clock_nanosleep_hook.Close()
	log.Println("sys_clock_nanosleep kprobe attached!")

	sys_clock_settime_hook, _ := link.Tracepoint("syscalls", "sys_enter_clock_settime", objs.SysClockSettimeCallback, nil)
	defer sys_clock_settime_hook.Close()
	log.Println("sys_clock_settime kprobe attached!")

	sys_clone_hook, _ := link.Tracepoint("syscalls", "sys_enter_clone", objs.SysCloneCallback, nil)
	defer sys_clone_hook.Close()
	log.Println("sys_clone kprobe attached!")

	sys_clone3_hook, _ := link.Tracepoint("syscalls", "sys_enter_clone3", objs.SysClone3Callback, nil)
	defer sys_clone3_hook.Close()
	log.Println("sys_clone3 kprobe attached!")

	sys_close_hook, _ := link.Tracepoint("syscalls", "sys_enter_close", objs.SysCloseCallback, nil)
	defer sys_close_hook.Close()
	log.Println("sys_close kprobe attached!")

	sys_close_range_hook, _ := link.Tracepoint("syscalls", "sys_enter_close_range", objs.SysCloseRangeCallback, nil)
	defer sys_close_range_hook.Close()
	log.Println("sys_close_range kprobe attached!")

	sys_connect_hook, _ := link.Tracepoint("syscalls", "sys_enter_connect", objs.SysConnectCallback, nil)
	defer sys_connect_hook.Close()
	log.Println("sys_connect kprobe attached!")

	sys_copy_file_range_hook, _ := link.Tracepoint("syscalls", "sys_enter_copy_file_range", objs.SysCopyFileRangeCallback, nil)
	defer sys_copy_file_range_hook.Close()
	log.Println("sys_copy_file_range kprobe attached!")

	sys_creat_hook, _ := link.Tracepoint("syscalls", "sys_enter_creat", objs.SysCreatCallback, nil)
	defer sys_creat_hook.Close()
	log.Println("sys_creat kprobe attached!")

	sys_delete_module_hook, _ := link.Tracepoint("syscalls", "sys_enter_delete_module", objs.SysDeleteModuleCallback, nil)
	defer sys_delete_module_hook.Close()
	log.Println("sys_delete_module kprobe attached!")

	sys_dup_hook, _ := link.Tracepoint("syscalls", "sys_enter_dup", objs.SysDupCallback, nil)
	defer sys_dup_hook.Close()
	log.Println("sys_dup kprobe attached!")

	sys_dup2_hook, _ := link.Tracepoint("syscalls", "sys_enter_dup2", objs.SysDup2Callback, nil)
	defer sys_dup2_hook.Close()
	log.Println("sys_dup2 kprobe attached!")

	sys_dup3_hook, _ := link.Tracepoint("syscalls", "sys_enter_dup3", objs.SysDup3Callback, nil)
	defer sys_dup3_hook.Close()
	log.Println("sys_dup3 kprobe attached!")

	sys_epoll_create_hook, _ := link.Tracepoint("syscalls", "sys_enter_epoll_create", objs.SysEpollCreateCallback, nil)
	defer sys_epoll_create_hook.Close()
	log.Println("sys_epoll_create kprobe attached!")

	sys_epoll_create1_hook, _ := link.Tracepoint("syscalls", "sys_enter_epoll_create1", objs.SysEpollCreate1Callback, nil)
	defer sys_epoll_create1_hook.Close()
	log.Println("sys_epoll_create1 kprobe attached!")

	sys_epoll_ctl_hook, _ := link.Tracepoint("syscalls", "sys_enter_epoll_ctl", objs.SysEpollCtlCallback, nil)
	defer sys_epoll_ctl_hook.Close()
	log.Println("sys_epoll_ctl kprobe attached!")

	sys_epoll_pwait_hook, _ := link.Tracepoint("syscalls", "sys_enter_epoll_pwait", objs.SysEpollPwaitCallback, nil)
	defer sys_epoll_pwait_hook.Close()
	log.Println("sys_epoll_pwait kprobe attached!")

	sys_epoll_pwait2_hook, _ := link.Tracepoint("syscalls", "sys_enter_epoll_pwait2", objs.SysEpollPwait2Callback, nil)
	defer sys_epoll_pwait2_hook.Close()
	log.Println("sys_epoll_pwait2 kprobe attached!")

	sys_epoll_wait_hook, _ := link.Tracepoint("syscalls", "sys_enter_epoll_wait", objs.SysEpollWaitCallback, nil)
	defer sys_epoll_wait_hook.Close()
	log.Println("sys_epoll_wait kprobe attached!")

	sys_eventfd_hook, _ := link.Tracepoint("syscalls", "sys_enter_eventfd", objs.SysEventfdCallback, nil)
	defer sys_eventfd_hook.Close()
	log.Println("sys_eventfd kprobe attached!")

	sys_eventfd2_hook, _ := link.Tracepoint("syscalls", "sys_enter_eventfd2", objs.SysEventfd2Callback, nil)
	defer sys_eventfd2_hook.Close()
	log.Println("sys_eventfd2 kprobe attached!")

	sys_execve_hook, _ := link.Tracepoint("syscalls", "sys_enter_execve", objs.SysExecveCallback, nil)
	defer sys_execve_hook.Close()
	log.Println("sys_execve kprobe attached!")

	sys_execveat_hook, _ := link.Tracepoint("syscalls", "sys_enter_execveat", objs.SysExecveatCallback, nil)
	defer sys_execveat_hook.Close()
	log.Println("sys_execveat kprobe attached!")

	sys_exit_hook, _ := link.Tracepoint("syscalls", "sys_enter_exit", objs.SysExitCallback, nil)
	defer sys_exit_hook.Close()
	log.Println("sys_exit kprobe attached!")

	sys_exit_group_hook, _ := link.Tracepoint("syscalls", "sys_enter_exit_group", objs.SysExitGroupCallback, nil)
	defer sys_exit_group_hook.Close()
	log.Println("sys_exit_group kprobe attached!")

	sys_faccessat_hook, _ := link.Tracepoint("syscalls", "sys_enter_faccessat", objs.SysFaccessatCallback, nil)
	defer sys_faccessat_hook.Close()
	log.Println("sys_faccessat kprobe attached!")

	sys_faccessat2_hook, _ := link.Tracepoint("syscalls", "sys_enter_faccessat2", objs.SysFaccessat2Callback, nil)
	defer sys_faccessat2_hook.Close()
	log.Println("sys_faccessat2 kprobe attached!")

	sys_fadvise64_hook, _ := link.Tracepoint("syscalls", "sys_enter_fadvise64", objs.SysFadvise64Callback, nil)
	defer sys_fadvise64_hook.Close()
	log.Println("sys_fadvise64 kprobe attached!")

	sys_fallocate_hook, _ := link.Tracepoint("syscalls", "sys_enter_fallocate", objs.SysFallocateCallback, nil)
	defer sys_fallocate_hook.Close()
	log.Println("sys_fallocate kprobe attached!")

	sys_fanotify_init_hook, _ := link.Tracepoint("syscalls", "sys_enter_fanotify_init", objs.SysFanotifyInitCallback, nil)
	defer sys_fanotify_init_hook.Close()
	log.Println("sys_fanotify_init kprobe attached!")

	sys_fanotify_mark_hook, _ := link.Tracepoint("syscalls", "sys_enter_fanotify_mark", objs.SysFanotifyMarkCallback, nil)
	defer sys_fanotify_mark_hook.Close()
	log.Println("sys_fanotify_mark kprobe attached!")

	sys_fchdir_hook, _ := link.Tracepoint("syscalls", "sys_enter_fchdir", objs.SysFchdirCallback, nil)
	defer sys_fchdir_hook.Close()
	log.Println("sys_fchdir kprobe attached!")

	sys_fchmod_hook, _ := link.Tracepoint("syscalls", "sys_enter_fchmod", objs.SysFchmodCallback, nil)
	defer sys_fchmod_hook.Close()
	log.Println("sys_fchmod kprobe attached!")

	sys_fchmodat_hook, _ := link.Tracepoint("syscalls", "sys_enter_fchmodat", objs.SysFchmodatCallback, nil)
	defer sys_fchmodat_hook.Close()
	log.Println("sys_fchmodat kprobe attached!")

	sys_fchown_hook, _ := link.Tracepoint("syscalls", "sys_enter_fchown", objs.SysFchownCallback, nil)
	defer sys_fchown_hook.Close()
	log.Println("sys_fchown kprobe attached!")

	sys_fchownat_hook, _ := link.Tracepoint("syscalls", "sys_enter_fchownat", objs.SysFchownatCallback, nil)
	defer sys_fchownat_hook.Close()
	log.Println("sys_fchownat kprobe attached!")

	sys_fcntl_hook, _ := link.Tracepoint("syscalls", "sys_enter_fcntl", objs.SysFcntlCallback, nil)
	defer sys_fcntl_hook.Close()
	log.Println("sys_fcntl kprobe attached!")

	sys_fdatasync_hook, _ := link.Tracepoint("syscalls", "sys_enter_fdatasync", objs.SysFdatasyncCallback, nil)
	defer sys_fdatasync_hook.Close()
	log.Println("sys_fdatasync kprobe attached!")

	sys_fgetxattr_hook, _ := link.Tracepoint("syscalls", "sys_enter_fgetxattr", objs.SysFgetxattrCallback, nil)
	defer sys_fgetxattr_hook.Close()
	log.Println("sys_fgetxattr kprobe attached!")

	sys_finit_module_hook, _ := link.Tracepoint("syscalls", "sys_enter_finit_module", objs.SysFinitModuleCallback, nil)
	defer sys_finit_module_hook.Close()
	log.Println("sys_finit_module kprobe attached!")

	sys_flistxattr_hook, _ := link.Tracepoint("syscalls", "sys_enter_flistxattr", objs.SysFlistxattrCallback, nil)
	defer sys_flistxattr_hook.Close()
	log.Println("sys_flistxattr kprobe attached!")

	sys_flock_hook, _ := link.Tracepoint("syscalls", "sys_enter_flock", objs.SysFlockCallback, nil)
	defer sys_flock_hook.Close()
	log.Println("sys_flock kprobe attached!")

	sys_fork_hook, _ := link.Tracepoint("syscalls", "sys_enter_fork", objs.SysForkCallback, nil)
	defer sys_fork_hook.Close()
	log.Println("sys_fork kprobe attached!")

	sys_fremovexattr_hook, _ := link.Tracepoint("syscalls", "sys_enter_fremovexattr", objs.SysFremovexattrCallback, nil)
	defer sys_fremovexattr_hook.Close()
	log.Println("sys_fremovexattr kprobe attached!")

	sys_fsconfig_hook, _ := link.Tracepoint("syscalls", "sys_enter_fsconfig", objs.SysFsconfigCallback, nil)
	defer sys_fsconfig_hook.Close()
	log.Println("sys_fsconfig kprobe attached!")

	sys_fsetxattr_hook, _ := link.Tracepoint("syscalls", "sys_enter_fsetxattr", objs.SysFsetxattrCallback, nil)
	defer sys_fsetxattr_hook.Close()
	log.Println("sys_fsetxattr kprobe attached!")

	sys_fsmount_hook, _ := link.Tracepoint("syscalls", "sys_enter_fsmount", objs.SysFsmountCallback, nil)
	defer sys_fsmount_hook.Close()
	log.Println("sys_fsmount kprobe attached!")

	sys_fsopen_hook, _ := link.Tracepoint("syscalls", "sys_enter_fsopen", objs.SysFsopenCallback, nil)
	defer sys_fsopen_hook.Close()
	log.Println("sys_fsopen kprobe attached!")

	sys_fspick_hook, _ := link.Tracepoint("syscalls", "sys_enter_fspick", objs.SysFspickCallback, nil)
	defer sys_fspick_hook.Close()
	log.Println("sys_fspick kprobe attached!")

	sys_fstatfs_hook, _ := link.Tracepoint("syscalls", "sys_enter_fstatfs", objs.SysFstatfsCallback, nil)
	defer sys_fstatfs_hook.Close()
	log.Println("sys_fstatfs kprobe attached!")

	sys_fsync_hook, _ := link.Tracepoint("syscalls", "sys_enter_fsync", objs.SysFsyncCallback, nil)
	defer sys_fsync_hook.Close()
	log.Println("sys_fsync kprobe attached!")

	sys_ftruncate_hook, _ := link.Tracepoint("syscalls", "sys_enter_ftruncate", objs.SysFtruncateCallback, nil)
	defer sys_ftruncate_hook.Close()
	log.Println("sys_ftruncate kprobe attached!")

	sys_futex_hook, _ := link.Tracepoint("syscalls", "sys_enter_futex", objs.SysFutexCallback, nil)
	defer sys_futex_hook.Close()
	log.Println("sys_futex kprobe attached!")

	sys_futex_waitv_hook, _ := link.Tracepoint("syscalls", "sys_enter_futex_waitv", objs.SysFutexWaitvCallback, nil)
	defer sys_futex_waitv_hook.Close()
	log.Println("sys_futex_waitv kprobe attached!")

	sys_futimesat_hook, _ := link.Tracepoint("syscalls", "sys_enter_futimesat", objs.SysFutimesatCallback, nil)
	defer sys_futimesat_hook.Close()
	log.Println("sys_futimesat kprobe attached!")

	sys_getcpu_hook, _ := link.Tracepoint("syscalls", "sys_enter_getcpu", objs.SysGetcpuCallback, nil)
	defer sys_getcpu_hook.Close()
	log.Println("sys_getcpu kprobe attached!")

	sys_getcwd_hook, _ := link.Tracepoint("syscalls", "sys_enter_getcwd", objs.SysGetcwdCallback, nil)
	defer sys_getcwd_hook.Close()
	log.Println("sys_getcwd kprobe attached!")

	sys_getdents_hook, _ := link.Tracepoint("syscalls", "sys_enter_getdents", objs.SysGetdentsCallback, nil)
	defer sys_getdents_hook.Close()
	log.Println("sys_getdents kprobe attached!")

	sys_getdents64_hook, _ := link.Tracepoint("syscalls", "sys_enter_getdents64", objs.SysGetdents64Callback, nil)
	defer sys_getdents64_hook.Close()
	log.Println("sys_getdents64 kprobe attached!")

	sys_getegid_hook, _ := link.Tracepoint("syscalls", "sys_enter_getegid", objs.SysGetegidCallback, nil)
	defer sys_getegid_hook.Close()
	log.Println("sys_getegid kprobe attached!")

	sys_geteuid_hook, _ := link.Tracepoint("syscalls", "sys_enter_geteuid", objs.SysGeteuidCallback, nil)
	defer sys_geteuid_hook.Close()
	log.Println("sys_geteuid kprobe attached!")

	sys_getgid_hook, _ := link.Tracepoint("syscalls", "sys_enter_getgid", objs.SysGetgidCallback, nil)
	defer sys_getgid_hook.Close()
	log.Println("sys_getgid kprobe attached!")

	sys_getgroups_hook, _ := link.Tracepoint("syscalls", "sys_enter_getgroups", objs.SysGetgroupsCallback, nil)
	defer sys_getgroups_hook.Close()
	log.Println("sys_getgroups kprobe attached!")

	sys_getitimer_hook, _ := link.Tracepoint("syscalls", "sys_enter_getitimer", objs.SysGetitimerCallback, nil)
	defer sys_getitimer_hook.Close()
	log.Println("sys_getitimer kprobe attached!")

	sys_get_mempolicy_hook, _ := link.Tracepoint("syscalls", "sys_enter_get_mempolicy", objs.SysGetMempolicyCallback, nil)
	defer sys_get_mempolicy_hook.Close()
	log.Println("sys_get_mempolicy kprobe attached!")

	sys_getpeername_hook, _ := link.Tracepoint("syscalls", "sys_enter_getpeername", objs.SysGetpeernameCallback, nil)
	defer sys_getpeername_hook.Close()
	log.Println("sys_getpeername kprobe attached!")

	sys_getpgid_hook, _ := link.Tracepoint("syscalls", "sys_enter_getpgid", objs.SysGetpgidCallback, nil)
	defer sys_getpgid_hook.Close()
	log.Println("sys_getpgid kprobe attached!")

	sys_getpgrp_hook, _ := link.Tracepoint("syscalls", "sys_enter_getpgrp", objs.SysGetpgrpCallback, nil)
	defer sys_getpgrp_hook.Close()
	log.Println("sys_getpgrp kprobe attached!")

	sys_getpid_hook, _ := link.Tracepoint("syscalls", "sys_enter_getpid", objs.SysGetpidCallback, nil)
	defer sys_getpid_hook.Close()
	log.Println("sys_getpid kprobe attached!")

	sys_getppid_hook, _ := link.Tracepoint("syscalls", "sys_enter_getppid", objs.SysGetppidCallback, nil)
	defer sys_getppid_hook.Close()
	log.Println("sys_getppid kprobe attached!")

	sys_getpriority_hook, _ := link.Tracepoint("syscalls", "sys_enter_getpriority", objs.SysGetpriorityCallback, nil)
	defer sys_getpriority_hook.Close()
	log.Println("sys_getpriority kprobe attached!")

	sys_getrandom_hook, _ := link.Tracepoint("syscalls", "sys_enter_getrandom", objs.SysGetrandomCallback, nil)
	defer sys_getrandom_hook.Close()
	log.Println("sys_getrandom kprobe attached!")

	sys_getresgid_hook, _ := link.Tracepoint("syscalls", "sys_enter_getresgid", objs.SysGetresgidCallback, nil)
	defer sys_getresgid_hook.Close()
	log.Println("sys_getresgid kprobe attached!")

	sys_getresuid_hook, _ := link.Tracepoint("syscalls", "sys_enter_getresuid", objs.SysGetresuidCallback, nil)
	defer sys_getresuid_hook.Close()
	log.Println("sys_getresuid kprobe attached!")

	sys_getrlimit_hook, _ := link.Tracepoint("syscalls", "sys_enter_getrlimit", objs.SysGetrlimitCallback, nil)
	defer sys_getrlimit_hook.Close()
	log.Println("sys_getrlimit kprobe attached!")

	sys_get_robust_list_hook, _ := link.Tracepoint("syscalls", "sys_enter_get_robust_list", objs.SysGetRobustListCallback, nil)
	defer sys_get_robust_list_hook.Close()
	log.Println("sys_get_robust_list kprobe attached!")

	sys_getrusage_hook, _ := link.Tracepoint("syscalls", "sys_enter_getrusage", objs.SysGetrusageCallback, nil)
	defer sys_getrusage_hook.Close()
	log.Println("sys_getrusage kprobe attached!")

	sys_getsid_hook, _ := link.Tracepoint("syscalls", "sys_enter_getsid", objs.SysGetsidCallback, nil)
	defer sys_getsid_hook.Close()
	log.Println("sys_getsid kprobe attached!")

	sys_getsockname_hook, _ := link.Tracepoint("syscalls", "sys_enter_getsockname", objs.SysGetsocknameCallback, nil)
	defer sys_getsockname_hook.Close()
	log.Println("sys_getsockname kprobe attached!")

	sys_getsockopt_hook, _ := link.Tracepoint("syscalls", "sys_enter_getsockopt", objs.SysGetsockoptCallback, nil)
	defer sys_getsockopt_hook.Close()
	log.Println("sys_getsockopt kprobe attached!")

	sys_gettid_hook, _ := link.Tracepoint("syscalls", "sys_enter_gettid", objs.SysGettidCallback, nil)
	defer sys_gettid_hook.Close()
	log.Println("sys_gettid kprobe attached!")

	sys_gettimeofday_hook, _ := link.Tracepoint("syscalls", "sys_enter_gettimeofday", objs.SysGettimeofdayCallback, nil)
	defer sys_gettimeofday_hook.Close()
	log.Println("sys_gettimeofday kprobe attached!")

	sys_getuid_hook, _ := link.Tracepoint("syscalls", "sys_enter_getuid", objs.SysGetuidCallback, nil)
	defer sys_getuid_hook.Close()
	log.Println("sys_getuid kprobe attached!")

	sys_getxattr_hook, _ := link.Tracepoint("syscalls", "sys_enter_getxattr", objs.SysGetxattrCallback, nil)
	defer sys_getxattr_hook.Close()
	log.Println("sys_getxattr kprobe attached!")

	sys_init_module_hook, _ := link.Tracepoint("syscalls", "sys_enter_init_module", objs.SysInitModuleCallback, nil)
	defer sys_init_module_hook.Close()
	log.Println("sys_init_module kprobe attached!")

	sys_inotify_add_watch_hook, _ := link.Tracepoint("syscalls", "sys_enter_inotify_add_watch", objs.SysInotifyAddWatchCallback, nil)
	defer sys_inotify_add_watch_hook.Close()
	log.Println("sys_inotify_add_watch kprobe attached!")

	sys_inotify_init_hook, _ := link.Tracepoint("syscalls", "sys_enter_inotify_init", objs.SysInotifyInitCallback, nil)
	defer sys_inotify_init_hook.Close()
	log.Println("sys_inotify_init kprobe attached!")

	sys_inotify_init1_hook, _ := link.Tracepoint("syscalls", "sys_enter_inotify_init1", objs.SysInotifyInit1Callback, nil)
	defer sys_inotify_init1_hook.Close()
	log.Println("sys_inotify_init1 kprobe attached!")

	sys_inotify_rm_watch_hook, _ := link.Tracepoint("syscalls", "sys_enter_inotify_rm_watch", objs.SysInotifyRmWatchCallback, nil)
	defer sys_inotify_rm_watch_hook.Close()
	log.Println("sys_inotify_rm_watch kprobe attached!")

	sys_io_cancel_hook, _ := link.Tracepoint("syscalls", "sys_enter_io_cancel", objs.SysIoCancelCallback, nil)
	defer sys_io_cancel_hook.Close()
	log.Println("sys_io_cancel kprobe attached!")

	sys_ioctl_hook, _ := link.Tracepoint("syscalls", "sys_enter_ioctl", objs.SysIoctlCallback, nil)
	defer sys_ioctl_hook.Close()
	log.Println("sys_ioctl kprobe attached!")

	sys_io_destroy_hook, _ := link.Tracepoint("syscalls", "sys_enter_io_destroy", objs.SysIoDestroyCallback, nil)
	defer sys_io_destroy_hook.Close()
	log.Println("sys_io_destroy kprobe attached!")

	sys_io_getevents_hook, _ := link.Tracepoint("syscalls", "sys_enter_io_getevents", objs.SysIoGeteventsCallback, nil)
	defer sys_io_getevents_hook.Close()
	log.Println("sys_io_getevents kprobe attached!")

	sys_ioperm_hook, _ := link.Tracepoint("syscalls", "sys_enter_ioperm", objs.SysIopermCallback, nil)
	defer sys_ioperm_hook.Close()
	log.Println("sys_ioperm kprobe attached!")

	sys_io_pgetevents_hook, _ := link.Tracepoint("syscalls", "sys_enter_io_pgetevents", objs.SysIoPgeteventsCallback, nil)
	defer sys_io_pgetevents_hook.Close()
	log.Println("sys_io_pgetevents kprobe attached!")

	sys_iopl_hook, _ := link.Tracepoint("syscalls", "sys_enter_iopl", objs.SysIoplCallback, nil)
	defer sys_iopl_hook.Close()
	log.Println("sys_iopl kprobe attached!")

	sys_ioprio_get_hook, _ := link.Tracepoint("syscalls", "sys_enter_ioprio_get", objs.SysIoprioGetCallback, nil)
	defer sys_ioprio_get_hook.Close()
	log.Println("sys_ioprio_get kprobe attached!")

	sys_ioprio_set_hook, _ := link.Tracepoint("syscalls", "sys_enter_ioprio_set", objs.SysIoprioSetCallback, nil)
	defer sys_ioprio_set_hook.Close()
	log.Println("sys_ioprio_set kprobe attached!")

	sys_io_setup_hook, _ := link.Tracepoint("syscalls", "sys_enter_io_setup", objs.SysIoSetupCallback, nil)
	defer sys_io_setup_hook.Close()
	log.Println("sys_io_setup kprobe attached!")

	sys_io_submit_hook, _ := link.Tracepoint("syscalls", "sys_enter_io_submit", objs.SysIoSubmitCallback, nil)
	defer sys_io_submit_hook.Close()
	log.Println("sys_io_submit kprobe attached!")

	sys_io_uring_enter_hook, _ := link.Tracepoint("syscalls", "sys_enter_io_uring_enter", objs.SysIoUringEnterCallback, nil)
	defer sys_io_uring_enter_hook.Close()
	log.Println("sys_io_uring_enter kprobe attached!")

	sys_io_uring_register_hook, _ := link.Tracepoint("syscalls", "sys_enter_io_uring_register", objs.SysIoUringRegisterCallback, nil)
	defer sys_io_uring_register_hook.Close()
	log.Println("sys_io_uring_register kprobe attached!")

	sys_io_uring_setup_hook, _ := link.Tracepoint("syscalls", "sys_enter_io_uring_setup", objs.SysIoUringSetupCallback, nil)
	defer sys_io_uring_setup_hook.Close()
	log.Println("sys_io_uring_setup kprobe attached!")

	sys_kcmp_hook, _ := link.Tracepoint("syscalls", "sys_enter_kcmp", objs.SysKcmpCallback, nil)
	defer sys_kcmp_hook.Close()
	log.Println("sys_kcmp kprobe attached!")

	sys_kexec_file_load_hook, _ := link.Tracepoint("syscalls", "sys_enter_kexec_file_load", objs.SysKexecFileLoadCallback, nil)
	defer sys_kexec_file_load_hook.Close()
	log.Println("sys_kexec_file_load kprobe attached!")

	sys_kexec_load_hook, _ := link.Tracepoint("syscalls", "sys_enter_kexec_load", objs.SysKexecLoadCallback, nil)
	defer sys_kexec_load_hook.Close()
	log.Println("sys_kexec_load kprobe attached!")

	sys_keyctl_hook, _ := link.Tracepoint("syscalls", "sys_enter_keyctl", objs.SysKeyctlCallback, nil)
	defer sys_keyctl_hook.Close()
	log.Println("sys_keyctl kprobe attached!")

	sys_kill_hook, _ := link.Tracepoint("syscalls", "sys_enter_kill", objs.SysKillCallback, nil)
	defer sys_kill_hook.Close()
	log.Println("sys_kill kprobe attached!")

	sys_landlock_add_rule_hook, _ := link.Tracepoint("syscalls", "sys_enter_landlock_add_rule", objs.SysLandlockAddRuleCallback, nil)
	defer sys_landlock_add_rule_hook.Close()
	log.Println("sys_landlock_add_rule kprobe attached!")

	sys_landlock_create_ruleset_hook, _ := link.Tracepoint("syscalls", "sys_enter_landlock_create_ruleset", objs.SysLandlockCreateRulesetCallback, nil)
	defer sys_landlock_create_ruleset_hook.Close()
	log.Println("sys_landlock_create_ruleset kprobe attached!")

	sys_landlock_restrict_self_hook, _ := link.Tracepoint("syscalls", "sys_enter_landlock_restrict_self", objs.SysLandlockRestrictSelfCallback, nil)
	defer sys_landlock_restrict_self_hook.Close()
	log.Println("sys_landlock_restrict_self kprobe attached!")

	sys_lchown_hook, _ := link.Tracepoint("syscalls", "sys_enter_lchown", objs.SysLchownCallback, nil)
	defer sys_lchown_hook.Close()
	log.Println("sys_lchown kprobe attached!")

	sys_lgetxattr_hook, _ := link.Tracepoint("syscalls", "sys_enter_lgetxattr", objs.SysLgetxattrCallback, nil)
	defer sys_lgetxattr_hook.Close()
	log.Println("sys_lgetxattr kprobe attached!")

	sys_link_hook, _ := link.Tracepoint("syscalls", "sys_enter_link", objs.SysLinkCallback, nil)
	defer sys_link_hook.Close()
	log.Println("sys_link kprobe attached!")

	sys_linkat_hook, _ := link.Tracepoint("syscalls", "sys_enter_linkat", objs.SysLinkatCallback, nil)
	defer sys_linkat_hook.Close()
	log.Println("sys_linkat kprobe attached!")

	sys_listen_hook, _ := link.Tracepoint("syscalls", "sys_enter_listen", objs.SysListenCallback, nil)
	defer sys_listen_hook.Close()
	log.Println("sys_listen kprobe attached!")

	sys_listxattr_hook, _ := link.Tracepoint("syscalls", "sys_enter_listxattr", objs.SysListxattrCallback, nil)
	defer sys_listxattr_hook.Close()
	log.Println("sys_listxattr kprobe attached!")

	sys_llistxattr_hook, _ := link.Tracepoint("syscalls", "sys_enter_llistxattr", objs.SysLlistxattrCallback, nil)
	defer sys_llistxattr_hook.Close()
	log.Println("sys_llistxattr kprobe attached!")

	sys_lremovexattr_hook, _ := link.Tracepoint("syscalls", "sys_enter_lremovexattr", objs.SysLremovexattrCallback, nil)
	defer sys_lremovexattr_hook.Close()
	log.Println("sys_lremovexattr kprobe attached!")

	sys_lseek_hook, _ := link.Tracepoint("syscalls", "sys_enter_lseek", objs.SysLseekCallback, nil)
	defer sys_lseek_hook.Close()
	log.Println("sys_lseek kprobe attached!")

	sys_lsetxattr_hook, _ := link.Tracepoint("syscalls", "sys_enter_lsetxattr", objs.SysLsetxattrCallback, nil)
	defer sys_lsetxattr_hook.Close()
	log.Println("sys_lsetxattr kprobe attached!")

	sys_madvise_hook, _ := link.Tracepoint("syscalls", "sys_enter_madvise", objs.SysMadviseCallback, nil)
	defer sys_madvise_hook.Close()
	log.Println("sys_madvise kprobe attached!")

	sys_mbind_hook, _ := link.Tracepoint("syscalls", "sys_enter_mbind", objs.SysMbindCallback, nil)
	defer sys_mbind_hook.Close()
	log.Println("sys_mbind kprobe attached!")

	sys_membarrier_hook, _ := link.Tracepoint("syscalls", "sys_enter_membarrier", objs.SysMembarrierCallback, nil)
	defer sys_membarrier_hook.Close()
	log.Println("sys_membarrier kprobe attached!")

	sys_memfd_create_hook, _ := link.Tracepoint("syscalls", "sys_enter_memfd_create", objs.SysMemfdCreateCallback, nil)
	defer sys_memfd_create_hook.Close()
	log.Println("sys_memfd_create kprobe attached!")

	sys_memfd_secret_hook, _ := link.Tracepoint("syscalls", "sys_enter_memfd_secret", objs.SysMemfdSecretCallback, nil)
	defer sys_memfd_secret_hook.Close()
	log.Println("sys_memfd_secret kprobe attached!")

	sys_migrate_pages_hook, _ := link.Tracepoint("syscalls", "sys_enter_migrate_pages", objs.SysMigratePagesCallback, nil)
	defer sys_migrate_pages_hook.Close()
	log.Println("sys_migrate_pages kprobe attached!")

	sys_mincore_hook, _ := link.Tracepoint("syscalls", "sys_enter_mincore", objs.SysMincoreCallback, nil)
	defer sys_mincore_hook.Close()
	log.Println("sys_mincore kprobe attached!")

	sys_mkdir_hook, _ := link.Tracepoint("syscalls", "sys_enter_mkdir", objs.SysMkdirCallback, nil)
	defer sys_mkdir_hook.Close()
	log.Println("sys_mkdir kprobe attached!")

	sys_mkdirat_hook, _ := link.Tracepoint("syscalls", "sys_enter_mkdirat", objs.SysMkdiratCallback, nil)
	defer sys_mkdirat_hook.Close()
	log.Println("sys_mkdirat kprobe attached!")

	sys_mknod_hook, _ := link.Tracepoint("syscalls", "sys_enter_mknod", objs.SysMknodCallback, nil)
	defer sys_mknod_hook.Close()
	log.Println("sys_mknod kprobe attached!")

	sys_mknodat_hook, _ := link.Tracepoint("syscalls", "sys_enter_mknodat", objs.SysMknodatCallback, nil)
	defer sys_mknodat_hook.Close()
	log.Println("sys_mknodat kprobe attached!")

	sys_mlock_hook, _ := link.Tracepoint("syscalls", "sys_enter_mlock", objs.SysMlockCallback, nil)
	defer sys_mlock_hook.Close()
	log.Println("sys_mlock kprobe attached!")

	sys_mlock2_hook, _ := link.Tracepoint("syscalls", "sys_enter_mlock2", objs.SysMlock2Callback, nil)
	defer sys_mlock2_hook.Close()
	log.Println("sys_mlock2 kprobe attached!")

	sys_mlockall_hook, _ := link.Tracepoint("syscalls", "sys_enter_mlockall", objs.SysMlockallCallback, nil)
	defer sys_mlockall_hook.Close()
	log.Println("sys_mlockall kprobe attached!")

	sys_mmap_hook, _ := link.Tracepoint("syscalls", "sys_enter_mmap", objs.SysMmapCallback, nil)
	defer sys_mmap_hook.Close()
	log.Println("sys_mmap kprobe attached!")

	sys_modify_ldt_hook, _ := link.Tracepoint("syscalls", "sys_enter_modify_ldt", objs.SysModifyLdtCallback, nil)
	defer sys_modify_ldt_hook.Close()
	log.Println("sys_modify_ldt kprobe attached!")

	sys_mount_hook, _ := link.Tracepoint("syscalls", "sys_enter_mount", objs.SysMountCallback, nil)
	defer sys_mount_hook.Close()
	log.Println("sys_mount kprobe attached!")

	sys_mount_setattr_hook, _ := link.Tracepoint("syscalls", "sys_enter_mount_setattr", objs.SysMountSetattrCallback, nil)
	defer sys_mount_setattr_hook.Close()
	log.Println("sys_mount_setattr kprobe attached!")

	sys_move_mount_hook, _ := link.Tracepoint("syscalls", "sys_enter_move_mount", objs.SysMoveMountCallback, nil)
	defer sys_move_mount_hook.Close()
	log.Println("sys_move_mount kprobe attached!")

	sys_move_pages_hook, _ := link.Tracepoint("syscalls", "sys_enter_move_pages", objs.SysMovePagesCallback, nil)
	defer sys_move_pages_hook.Close()
	log.Println("sys_move_pages kprobe attached!")

	sys_mprotect_hook, _ := link.Tracepoint("syscalls", "sys_enter_mprotect", objs.SysMprotectCallback, nil)
	defer sys_mprotect_hook.Close()
	log.Println("sys_mprotect kprobe attached!")

	sys_mq_getsetattr_hook, _ := link.Tracepoint("syscalls", "sys_enter_mq_getsetattr", objs.SysMqGetsetattrCallback, nil)
	defer sys_mq_getsetattr_hook.Close()
	log.Println("sys_mq_getsetattr kprobe attached!")

	sys_mq_notify_hook, _ := link.Tracepoint("syscalls", "sys_enter_mq_notify", objs.SysMqNotifyCallback, nil)
	defer sys_mq_notify_hook.Close()
	log.Println("sys_mq_notify kprobe attached!")

	sys_mq_open_hook, _ := link.Tracepoint("syscalls", "sys_enter_mq_open", objs.SysMqOpenCallback, nil)
	defer sys_mq_open_hook.Close()
	log.Println("sys_mq_open kprobe attached!")

	sys_mq_timedreceive_hook, _ := link.Tracepoint("syscalls", "sys_enter_mq_timedreceive", objs.SysMqTimedreceiveCallback, nil)
	defer sys_mq_timedreceive_hook.Close()
	log.Println("sys_mq_timedreceive kprobe attached!")

	sys_mq_timedsend_hook, _ := link.Tracepoint("syscalls", "sys_enter_mq_timedsend", objs.SysMqTimedsendCallback, nil)
	defer sys_mq_timedsend_hook.Close()
	log.Println("sys_mq_timedsend kprobe attached!")

	sys_mq_unlink_hook, _ := link.Tracepoint("syscalls", "sys_enter_mq_unlink", objs.SysMqUnlinkCallback, nil)
	defer sys_mq_unlink_hook.Close()
	log.Println("sys_mq_unlink kprobe attached!")

	sys_mremap_hook, _ := link.Tracepoint("syscalls", "sys_enter_mremap", objs.SysMremapCallback, nil)
	defer sys_mremap_hook.Close()
	log.Println("sys_mremap kprobe attached!")

	sys_msgctl_hook, _ := link.Tracepoint("syscalls", "sys_enter_msgctl", objs.SysMsgctlCallback, nil)
	defer sys_msgctl_hook.Close()
	log.Println("sys_msgctl kprobe attached!")

	sys_msgget_hook, _ := link.Tracepoint("syscalls", "sys_enter_msgget", objs.SysMsggetCallback, nil)
	defer sys_msgget_hook.Close()
	log.Println("sys_msgget kprobe attached!")

	sys_msgrcv_hook, _ := link.Tracepoint("syscalls", "sys_enter_msgrcv", objs.SysMsgrcvCallback, nil)
	defer sys_msgrcv_hook.Close()
	log.Println("sys_msgrcv kprobe attached!")

	sys_msgsnd_hook, _ := link.Tracepoint("syscalls", "sys_enter_msgsnd", objs.SysMsgsndCallback, nil)
	defer sys_msgsnd_hook.Close()
	log.Println("sys_msgsnd kprobe attached!")

	sys_msync_hook, _ := link.Tracepoint("syscalls", "sys_enter_msync", objs.SysMsyncCallback, nil)
	defer sys_msync_hook.Close()
	log.Println("sys_msync kprobe attached!")

	sys_munlock_hook, _ := link.Tracepoint("syscalls", "sys_enter_munlock", objs.SysMunlockCallback, nil)
	defer sys_munlock_hook.Close()
	log.Println("sys_munlock kprobe attached!")

	sys_munlockall_hook, _ := link.Tracepoint("syscalls", "sys_enter_munlockall", objs.SysMunlockallCallback, nil)
	defer sys_munlockall_hook.Close()
	log.Println("sys_munlockall kprobe attached!")

	sys_munmap_hook, _ := link.Tracepoint("syscalls", "sys_enter_munmap", objs.SysMunmapCallback, nil)
	defer sys_munmap_hook.Close()
	log.Println("sys_munmap kprobe attached!")

	sys_name_to_handle_at_hook, _ := link.Tracepoint("syscalls", "sys_enter_name_to_handle_at", objs.SysNameToHandleAtCallback, nil)
	defer sys_name_to_handle_at_hook.Close()
	log.Println("sys_name_to_handle_at kprobe attached!")

	sys_nanosleep_hook, _ := link.Tracepoint("syscalls", "sys_enter_nanosleep", objs.SysNanosleepCallback, nil)
	defer sys_nanosleep_hook.Close()
	log.Println("sys_nanosleep kprobe attached!")

	sys_newfstat_hook, _ := link.Tracepoint("syscalls", "sys_enter_newfstat", objs.SysNewfstatCallback, nil)
	defer sys_newfstat_hook.Close()
	log.Println("sys_newfstat kprobe attached!")

	sys_newfstatat_hook, _ := link.Tracepoint("syscalls", "sys_enter_newfstatat", objs.SysNewfstatatCallback, nil)
	defer sys_newfstatat_hook.Close()
	log.Println("sys_newfstatat kprobe attached!")

	sys_newlstat_hook, _ := link.Tracepoint("syscalls", "sys_enter_newlstat", objs.SysNewlstatCallback, nil)
	defer sys_newlstat_hook.Close()
	log.Println("sys_newlstat kprobe attached!")

	sys_newstat_hook, _ := link.Tracepoint("syscalls", "sys_enter_newstat", objs.SysNewstatCallback, nil)
	defer sys_newstat_hook.Close()
	log.Println("sys_newstat kprobe attached!")

	sys_newuname_hook, _ := link.Tracepoint("syscalls", "sys_enter_newuname", objs.SysNewunameCallback, nil)
	defer sys_newuname_hook.Close()
	log.Println("sys_newuname kprobe attached!")

	sys_open_hook, _ := link.Tracepoint("syscalls", "sys_enter_open", objs.SysOpenCallback, nil)
	defer sys_open_hook.Close()
	log.Println("sys_open kprobe attached!")

	sys_openat_hook, _ := link.Tracepoint("syscalls", "sys_enter_openat", objs.SysOpenatCallback, nil)
	defer sys_openat_hook.Close()
	log.Println("sys_openat kprobe attached!")

	sys_openat2_hook, _ := link.Tracepoint("syscalls", "sys_enter_openat2", objs.SysOpenat2Callback, nil)
	defer sys_openat2_hook.Close()
	log.Println("sys_openat2 kprobe attached!")

	sys_open_by_handle_at_hook, _ := link.Tracepoint("syscalls", "sys_enter_open_by_handle_at", objs.SysOpenByHandleAtCallback, nil)
	defer sys_open_by_handle_at_hook.Close()
	log.Println("sys_open_by_handle_at kprobe attached!")

	sys_open_tree_hook, _ := link.Tracepoint("syscalls", "sys_enter_open_tree", objs.SysOpenTreeCallback, nil)
	defer sys_open_tree_hook.Close()
	log.Println("sys_open_tree kprobe attached!")

	sys_pause_hook, _ := link.Tracepoint("syscalls", "sys_enter_pause", objs.SysPauseCallback, nil)
	defer sys_pause_hook.Close()
	log.Println("sys_pause kprobe attached!")

	sys_perf_event_open_hook, _ := link.Tracepoint("syscalls", "sys_enter_perf_event_open", objs.SysPerfEventOpenCallback, nil)
	defer sys_perf_event_open_hook.Close()
	log.Println("sys_perf_event_open kprobe attached!")

	sys_personality_hook, _ := link.Tracepoint("syscalls", "sys_enter_personality", objs.SysPersonalityCallback, nil)
	defer sys_personality_hook.Close()
	log.Println("sys_personality kprobe attached!")

	sys_pidfd_getfd_hook, _ := link.Tracepoint("syscalls", "sys_enter_pidfd_getfd", objs.SysPidfdGetfdCallback, nil)
	defer sys_pidfd_getfd_hook.Close()
	log.Println("sys_pidfd_getfd kprobe attached!")

	sys_pidfd_open_hook, _ := link.Tracepoint("syscalls", "sys_enter_pidfd_open", objs.SysPidfdOpenCallback, nil)
	defer sys_pidfd_open_hook.Close()
	log.Println("sys_pidfd_open kprobe attached!")

	sys_pidfd_send_signal_hook, _ := link.Tracepoint("syscalls", "sys_enter_pidfd_send_signal", objs.SysPidfdSendSignalCallback, nil)
	defer sys_pidfd_send_signal_hook.Close()
	log.Println("sys_pidfd_send_signal kprobe attached!")

	sys_pipe_hook, _ := link.Tracepoint("syscalls", "sys_enter_pipe", objs.SysPipeCallback, nil)
	defer sys_pipe_hook.Close()
	log.Println("sys_pipe kprobe attached!")

	sys_pipe2_hook, _ := link.Tracepoint("syscalls", "sys_enter_pipe2", objs.SysPipe2Callback, nil)
	defer sys_pipe2_hook.Close()
	log.Println("sys_pipe2 kprobe attached!")

	sys_pivot_root_hook, _ := link.Tracepoint("syscalls", "sys_enter_pivot_root", objs.SysPivotRootCallback, nil)
	defer sys_pivot_root_hook.Close()
	log.Println("sys_pivot_root kprobe attached!")

	sys_pkey_alloc_hook, _ := link.Tracepoint("syscalls", "sys_enter_pkey_alloc", objs.SysPkeyAllocCallback, nil)
	defer sys_pkey_alloc_hook.Close()
	log.Println("sys_pkey_alloc kprobe attached!")

	sys_pkey_free_hook, _ := link.Tracepoint("syscalls", "sys_enter_pkey_free", objs.SysPkeyFreeCallback, nil)
	defer sys_pkey_free_hook.Close()
	log.Println("sys_pkey_free kprobe attached!")

	sys_pkey_mprotect_hook, _ := link.Tracepoint("syscalls", "sys_enter_pkey_mprotect", objs.SysPkeyMprotectCallback, nil)
	defer sys_pkey_mprotect_hook.Close()
	log.Println("sys_pkey_mprotect kprobe attached!")

	sys_poll_hook, _ := link.Tracepoint("syscalls", "sys_enter_poll", objs.SysPollCallback, nil)
	defer sys_poll_hook.Close()
	log.Println("sys_poll kprobe attached!")

	sys_ppoll_hook, _ := link.Tracepoint("syscalls", "sys_enter_ppoll", objs.SysPpollCallback, nil)
	defer sys_ppoll_hook.Close()
	log.Println("sys_ppoll kprobe attached!")

	sys_prctl_hook, _ := link.Tracepoint("syscalls", "sys_enter_prctl", objs.SysPrctlCallback, nil)
	defer sys_prctl_hook.Close()
	log.Println("sys_prctl kprobe attached!")

	sys_pread64_hook, _ := link.Tracepoint("syscalls", "sys_enter_pread64", objs.SysPread64Callback, nil)
	defer sys_pread64_hook.Close()
	log.Println("sys_pread64 kprobe attached!")

	sys_preadv_hook, _ := link.Tracepoint("syscalls", "sys_enter_preadv", objs.SysPreadvCallback, nil)
	defer sys_preadv_hook.Close()
	log.Println("sys_preadv kprobe attached!")

	sys_preadv2_hook, _ := link.Tracepoint("syscalls", "sys_enter_preadv2", objs.SysPreadv2Callback, nil)
	defer sys_preadv2_hook.Close()
	log.Println("sys_preadv2 kprobe attached!")

	sys_prlimit64_hook, _ := link.Tracepoint("syscalls", "sys_enter_prlimit64", objs.SysPrlimit64Callback, nil)
	defer sys_prlimit64_hook.Close()
	log.Println("sys_prlimit64 kprobe attached!")

	sys_process_madvise_hook, _ := link.Tracepoint("syscalls", "sys_enter_process_madvise", objs.SysProcessMadviseCallback, nil)
	defer sys_process_madvise_hook.Close()
	log.Println("sys_process_madvise kprobe attached!")

	sys_process_mrelease_hook, _ := link.Tracepoint("syscalls", "sys_enter_process_mrelease", objs.SysProcessMreleaseCallback, nil)
	defer sys_process_mrelease_hook.Close()
	log.Println("sys_process_mrelease kprobe attached!")

	sys_process_vm_readv_hook, _ := link.Tracepoint("syscalls", "sys_enter_process_vm_readv", objs.SysProcessVmReadvCallback, nil)
	defer sys_process_vm_readv_hook.Close()
	log.Println("sys_process_vm_readv kprobe attached!")

	sys_process_vm_writev_hook, _ := link.Tracepoint("syscalls", "sys_enter_process_vm_writev", objs.SysProcessVmWritevCallback, nil)
	defer sys_process_vm_writev_hook.Close()
	log.Println("sys_process_vm_writev kprobe attached!")

	sys_pselect6_hook, _ := link.Tracepoint("syscalls", "sys_enter_pselect6", objs.SysPselect6Callback, nil)
	defer sys_pselect6_hook.Close()
	log.Println("sys_pselect6 kprobe attached!")

	sys_ptrace_hook, _ := link.Tracepoint("syscalls", "sys_enter_ptrace", objs.SysPtraceCallback, nil)
	defer sys_ptrace_hook.Close()
	log.Println("sys_ptrace kprobe attached!")

	sys_pwrite64_hook, _ := link.Tracepoint("syscalls", "sys_enter_pwrite64", objs.SysPwrite64Callback, nil)
	defer sys_pwrite64_hook.Close()
	log.Println("sys_pwrite64 kprobe attached!")

	sys_pwritev_hook, _ := link.Tracepoint("syscalls", "sys_enter_pwritev", objs.SysPwritevCallback, nil)
	defer sys_pwritev_hook.Close()
	log.Println("sys_pwritev kprobe attached!")

	sys_pwritev2_hook, _ := link.Tracepoint("syscalls", "sys_enter_pwritev2", objs.SysPwritev2Callback, nil)
	defer sys_pwritev2_hook.Close()
	log.Println("sys_pwritev2 kprobe attached!")

	sys_quotactl_hook, _ := link.Tracepoint("syscalls", "sys_enter_quotactl", objs.SysQuotactlCallback, nil)
	defer sys_quotactl_hook.Close()
	log.Println("sys_quotactl kprobe attached!")

	sys_quotactl_fd_hook, _ := link.Tracepoint("syscalls", "sys_enter_quotactl_fd", objs.SysQuotactlFdCallback, nil)
	defer sys_quotactl_fd_hook.Close()
	log.Println("sys_quotactl_fd kprobe attached!")

	sys_read_hook, _ := link.Tracepoint("syscalls", "sys_enter_read", objs.SysReadCallback, nil)
	defer sys_read_hook.Close()
	log.Println("sys_read kprobe attached!")

	sys_readahead_hook, _ := link.Tracepoint("syscalls", "sys_enter_readahead", objs.SysReadaheadCallback, nil)
	defer sys_readahead_hook.Close()
	log.Println("sys_readahead kprobe attached!")

	sys_readlink_hook, _ := link.Tracepoint("syscalls", "sys_enter_readlink", objs.SysReadlinkCallback, nil)
	defer sys_readlink_hook.Close()
	log.Println("sys_readlink kprobe attached!")

	sys_readlinkat_hook, _ := link.Tracepoint("syscalls", "sys_enter_readlinkat", objs.SysReadlinkatCallback, nil)
	defer sys_readlinkat_hook.Close()
	log.Println("sys_readlinkat kprobe attached!")

	sys_readv_hook, _ := link.Tracepoint("syscalls", "sys_enter_readv", objs.SysReadvCallback, nil)
	defer sys_readv_hook.Close()
	log.Println("sys_readv kprobe attached!")

	sys_reboot_hook, _ := link.Tracepoint("syscalls", "sys_enter_reboot", objs.SysRebootCallback, nil)
	defer sys_reboot_hook.Close()
	log.Println("sys_reboot kprobe attached!")

	sys_recvfrom_hook, _ := link.Tracepoint("syscalls", "sys_enter_recvfrom", objs.SysRecvfromCallback, nil)
	defer sys_recvfrom_hook.Close()
	log.Println("sys_recvfrom kprobe attached!")

	sys_recvmmsg_hook, _ := link.Tracepoint("syscalls", "sys_enter_recvmmsg", objs.SysRecvmmsgCallback, nil)
	defer sys_recvmmsg_hook.Close()
	log.Println("sys_recvmmsg kprobe attached!")

	sys_recvmsg_hook, _ := link.Tracepoint("syscalls", "sys_enter_recvmsg", objs.SysRecvmsgCallback, nil)
	defer sys_recvmsg_hook.Close()
	log.Println("sys_recvmsg kprobe attached!")

	sys_remap_file_pages_hook, _ := link.Tracepoint("syscalls", "sys_enter_remap_file_pages", objs.SysRemapFilePagesCallback, nil)
	defer sys_remap_file_pages_hook.Close()
	log.Println("sys_remap_file_pages kprobe attached!")

	sys_removexattr_hook, _ := link.Tracepoint("syscalls", "sys_enter_removexattr", objs.SysRemovexattrCallback, nil)
	defer sys_removexattr_hook.Close()
	log.Println("sys_removexattr kprobe attached!")

	sys_rename_hook, _ := link.Tracepoint("syscalls", "sys_enter_rename", objs.SysRenameCallback, nil)
	defer sys_rename_hook.Close()
	log.Println("sys_rename kprobe attached!")

	sys_renameat_hook, _ := link.Tracepoint("syscalls", "sys_enter_renameat", objs.SysRenameatCallback, nil)
	defer sys_renameat_hook.Close()
	log.Println("sys_renameat kprobe attached!")

	sys_renameat2_hook, _ := link.Tracepoint("syscalls", "sys_enter_renameat2", objs.SysRenameat2Callback, nil)
	defer sys_renameat2_hook.Close()
	log.Println("sys_renameat2 kprobe attached!")

	sys_request_key_hook, _ := link.Tracepoint("syscalls", "sys_enter_request_key", objs.SysRequestKeyCallback, nil)
	defer sys_request_key_hook.Close()
	log.Println("sys_request_key kprobe attached!")

	sys_restart_syscall_hook, _ := link.Tracepoint("syscalls", "sys_enter_restart_syscall", objs.SysRestartSyscallCallback, nil)
	defer sys_restart_syscall_hook.Close()
	log.Println("sys_restart_syscall kprobe attached!")

	sys_rmdir_hook, _ := link.Tracepoint("syscalls", "sys_enter_rmdir", objs.SysRmdirCallback, nil)
	defer sys_rmdir_hook.Close()
	log.Println("sys_rmdir kprobe attached!")

	sys_rseq_hook, _ := link.Tracepoint("syscalls", "sys_enter_rseq", objs.SysRseqCallback, nil)
	defer sys_rseq_hook.Close()
	log.Println("sys_rseq kprobe attached!")

	sys_rt_sigaction_hook, _ := link.Tracepoint("syscalls", "sys_enter_rt_sigaction", objs.SysRtSigactionCallback, nil)
	defer sys_rt_sigaction_hook.Close()
	log.Println("sys_rt_sigaction kprobe attached!")

	sys_rt_sigpending_hook, _ := link.Tracepoint("syscalls", "sys_enter_rt_sigpending", objs.SysRtSigpendingCallback, nil)
	defer sys_rt_sigpending_hook.Close()
	log.Println("sys_rt_sigpending kprobe attached!")

	sys_rt_sigprocmask_hook, _ := link.Tracepoint("syscalls", "sys_enter_rt_sigprocmask", objs.SysRtSigprocmaskCallback, nil)
	defer sys_rt_sigprocmask_hook.Close()
	log.Println("sys_rt_sigprocmask kprobe attached!")

	sys_rt_sigqueueinfo_hook, _ := link.Tracepoint("syscalls", "sys_enter_rt_sigqueueinfo", objs.SysRtSigqueueinfoCallback, nil)
	defer sys_rt_sigqueueinfo_hook.Close()
	log.Println("sys_rt_sigqueueinfo kprobe attached!")

	sys_rt_sigreturn_hook, _ := link.Tracepoint("syscalls", "sys_enter_rt_sigreturn", objs.SysRtSigreturnCallback, nil)
	defer sys_rt_sigreturn_hook.Close()
	log.Println("sys_rt_sigreturn kprobe attached!")

	sys_rt_sigsuspend_hook, _ := link.Tracepoint("syscalls", "sys_enter_rt_sigsuspend", objs.SysRtSigsuspendCallback, nil)
	defer sys_rt_sigsuspend_hook.Close()
	log.Println("sys_rt_sigsuspend kprobe attached!")

	sys_rt_sigtimedwait_hook, _ := link.Tracepoint("syscalls", "sys_enter_rt_sigtimedwait", objs.SysRtSigtimedwaitCallback, nil)
	defer sys_rt_sigtimedwait_hook.Close()
	log.Println("sys_rt_sigtimedwait kprobe attached!")

	sys_rt_tgsigqueueinfo_hook, _ := link.Tracepoint("syscalls", "sys_enter_rt_tgsigqueueinfo", objs.SysRtTgsigqueueinfoCallback, nil)
	defer sys_rt_tgsigqueueinfo_hook.Close()
	log.Println("sys_rt_tgsigqueueinfo kprobe attached!")

	sys_sched_getaffinity_hook, _ := link.Tracepoint("syscalls", "sys_enter_sched_getaffinity", objs.SysSchedGetaffinityCallback, nil)
	defer sys_sched_getaffinity_hook.Close()
	log.Println("sys_sched_getaffinity kprobe attached!")

	sys_sched_getattr_hook, _ := link.Tracepoint("syscalls", "sys_enter_sched_getattr", objs.SysSchedGetattrCallback, nil)
	defer sys_sched_getattr_hook.Close()
	log.Println("sys_sched_getattr kprobe attached!")

	sys_sched_getparam_hook, _ := link.Tracepoint("syscalls", "sys_enter_sched_getparam", objs.SysSchedGetparamCallback, nil)
	defer sys_sched_getparam_hook.Close()
	log.Println("sys_sched_getparam kprobe attached!")

	sys_sched_get_priority_max_hook, _ := link.Tracepoint("syscalls", "sys_enter_sched_get_priority_max", objs.SysSchedGetPriorityMaxCallback, nil)
	defer sys_sched_get_priority_max_hook.Close()
	log.Println("sys_sched_get_priority_max kprobe attached!")

	sys_sched_get_priority_min_hook, _ := link.Tracepoint("syscalls", "sys_enter_sched_get_priority_min", objs.SysSchedGetPriorityMinCallback, nil)
	defer sys_sched_get_priority_min_hook.Close()
	log.Println("sys_sched_get_priority_min kprobe attached!")

	sys_sched_getscheduler_hook, _ := link.Tracepoint("syscalls", "sys_enter_sched_getscheduler", objs.SysSchedGetschedulerCallback, nil)
	defer sys_sched_getscheduler_hook.Close()
	log.Println("sys_sched_getscheduler kprobe attached!")

	sys_sched_rr_get_interval_hook, _ := link.Tracepoint("syscalls", "sys_enter_sched_rr_get_interval", objs.SysSchedRrGetIntervalCallback, nil)
	defer sys_sched_rr_get_interval_hook.Close()
	log.Println("sys_sched_rr_get_interval kprobe attached!")

	sys_sched_setaffinity_hook, _ := link.Tracepoint("syscalls", "sys_enter_sched_setaffinity", objs.SysSchedSetaffinityCallback, nil)
	defer sys_sched_setaffinity_hook.Close()
	log.Println("sys_sched_setaffinity kprobe attached!")

	sys_sched_setattr_hook, _ := link.Tracepoint("syscalls", "sys_enter_sched_setattr", objs.SysSchedSetattrCallback, nil)
	defer sys_sched_setattr_hook.Close()
	log.Println("sys_sched_setattr kprobe attached!")

	sys_sched_setparam_hook, _ := link.Tracepoint("syscalls", "sys_enter_sched_setparam", objs.SysSchedSetparamCallback, nil)
	defer sys_sched_setparam_hook.Close()
	log.Println("sys_sched_setparam kprobe attached!")

	sys_sched_setscheduler_hook, _ := link.Tracepoint("syscalls", "sys_enter_sched_setscheduler", objs.SysSchedSetschedulerCallback, nil)
	defer sys_sched_setscheduler_hook.Close()
	log.Println("sys_sched_setscheduler kprobe attached!")

	sys_sched_yield_hook, _ := link.Tracepoint("syscalls", "sys_enter_sched_yield", objs.SysSchedYieldCallback, nil)
	defer sys_sched_yield_hook.Close()
	log.Println("sys_sched_yield kprobe attached!")

	sys_seccomp_hook, _ := link.Tracepoint("syscalls", "sys_enter_seccomp", objs.SysSeccompCallback, nil)
	defer sys_seccomp_hook.Close()
	log.Println("sys_seccomp kprobe attached!")

	sys_select_hook, _ := link.Tracepoint("syscalls", "sys_enter_select", objs.SysSelectCallback, nil)
	defer sys_select_hook.Close()
	log.Println("sys_select kprobe attached!")

	sys_semctl_hook, _ := link.Tracepoint("syscalls", "sys_enter_semctl", objs.SysSemctlCallback, nil)
	defer sys_semctl_hook.Close()
	log.Println("sys_semctl kprobe attached!")

	sys_semget_hook, _ := link.Tracepoint("syscalls", "sys_enter_semget", objs.SysSemgetCallback, nil)
	defer sys_semget_hook.Close()
	log.Println("sys_semget kprobe attached!")

	sys_semop_hook, _ := link.Tracepoint("syscalls", "sys_enter_semop", objs.SysSemopCallback, nil)
	defer sys_semop_hook.Close()
	log.Println("sys_semop kprobe attached!")

	sys_semtimedop_hook, _ := link.Tracepoint("syscalls", "sys_enter_semtimedop", objs.SysSemtimedopCallback, nil)
	defer sys_semtimedop_hook.Close()
	log.Println("sys_semtimedop kprobe attached!")

	sys_sendfile64_hook, _ := link.Tracepoint("syscalls", "sys_enter_sendfile64", objs.SysSendfile64Callback, nil)
	defer sys_sendfile64_hook.Close()
	log.Println("sys_sendfile64 kprobe attached!")

	sys_sendmmsg_hook, _ := link.Tracepoint("syscalls", "sys_enter_sendmmsg", objs.SysSendmmsgCallback, nil)
	defer sys_sendmmsg_hook.Close()
	log.Println("sys_sendmmsg kprobe attached!")

	sys_sendmsg_hook, _ := link.Tracepoint("syscalls", "sys_enter_sendmsg", objs.SysSendmsgCallback, nil)
	defer sys_sendmsg_hook.Close()
	log.Println("sys_sendmsg kprobe attached!")

	sys_sendto_hook, _ := link.Tracepoint("syscalls", "sys_enter_sendto", objs.SysSendtoCallback, nil)
	defer sys_sendto_hook.Close()
	log.Println("sys_sendto kprobe attached!")

	sys_setdomainname_hook, _ := link.Tracepoint("syscalls", "sys_enter_setdomainname", objs.SysSetdomainnameCallback, nil)
	defer sys_setdomainname_hook.Close()
	log.Println("sys_setdomainname kprobe attached!")

	sys_setfsgid_hook, _ := link.Tracepoint("syscalls", "sys_enter_setfsgid", objs.SysSetfsgidCallback, nil)
	defer sys_setfsgid_hook.Close()
	log.Println("sys_setfsgid kprobe attached!")

	sys_setfsuid_hook, _ := link.Tracepoint("syscalls", "sys_enter_setfsuid", objs.SysSetfsuidCallback, nil)
	defer sys_setfsuid_hook.Close()
	log.Println("sys_setfsuid kprobe attached!")

	sys_setgid_hook, _ := link.Tracepoint("syscalls", "sys_enter_setgid", objs.SysSetgidCallback, nil)
	defer sys_setgid_hook.Close()
	log.Println("sys_setgid kprobe attached!")

	sys_setgroups_hook, _ := link.Tracepoint("syscalls", "sys_enter_setgroups", objs.SysSetgroupsCallback, nil)
	defer sys_setgroups_hook.Close()
	log.Println("sys_setgroups kprobe attached!")

	sys_sethostname_hook, _ := link.Tracepoint("syscalls", "sys_enter_sethostname", objs.SysSethostnameCallback, nil)
	defer sys_sethostname_hook.Close()
	log.Println("sys_sethostname kprobe attached!")

	sys_setitimer_hook, _ := link.Tracepoint("syscalls", "sys_enter_setitimer", objs.SysSetitimerCallback, nil)
	defer sys_setitimer_hook.Close()
	log.Println("sys_setitimer kprobe attached!")

	sys_set_mempolicy_hook, _ := link.Tracepoint("syscalls", "sys_enter_set_mempolicy", objs.SysSetMempolicyCallback, nil)
	defer sys_set_mempolicy_hook.Close()
	log.Println("sys_set_mempolicy kprobe attached!")

	sys_set_mempolicy_home_node_hook, _ := link.Tracepoint("syscalls", "sys_enter_set_mempolicy_home_node", objs.SysSetMempolicyHomeNodeCallback, nil)
	defer sys_set_mempolicy_home_node_hook.Close()
	log.Println("sys_set_mempolicy_home_node kprobe attached!")

	sys_setns_hook, _ := link.Tracepoint("syscalls", "sys_enter_setns", objs.SysSetnsCallback, nil)
	defer sys_setns_hook.Close()
	log.Println("sys_setns kprobe attached!")

	sys_setpgid_hook, _ := link.Tracepoint("syscalls", "sys_enter_setpgid", objs.SysSetpgidCallback, nil)
	defer sys_setpgid_hook.Close()
	log.Println("sys_setpgid kprobe attached!")

	sys_setpriority_hook, _ := link.Tracepoint("syscalls", "sys_enter_setpriority", objs.SysSetpriorityCallback, nil)
	defer sys_setpriority_hook.Close()
	log.Println("sys_setpriority kprobe attached!")

	sys_setregid_hook, _ := link.Tracepoint("syscalls", "sys_enter_setregid", objs.SysSetregidCallback, nil)
	defer sys_setregid_hook.Close()
	log.Println("sys_setregid kprobe attached!")

	sys_setresgid_hook, _ := link.Tracepoint("syscalls", "sys_enter_setresgid", objs.SysSetresgidCallback, nil)
	defer sys_setresgid_hook.Close()
	log.Println("sys_setresgid kprobe attached!")

	sys_setresuid_hook, _ := link.Tracepoint("syscalls", "sys_enter_setresuid", objs.SysSetresuidCallback, nil)
	defer sys_setresuid_hook.Close()
	log.Println("sys_setresuid kprobe attached!")

	sys_setreuid_hook, _ := link.Tracepoint("syscalls", "sys_enter_setreuid", objs.SysSetreuidCallback, nil)
	defer sys_setreuid_hook.Close()
	log.Println("sys_setreuid kprobe attached!")

	sys_setrlimit_hook, _ := link.Tracepoint("syscalls", "sys_enter_setrlimit", objs.SysSetrlimitCallback, nil)
	defer sys_setrlimit_hook.Close()
	log.Println("sys_setrlimit kprobe attached!")

	sys_set_robust_list_hook, _ := link.Tracepoint("syscalls", "sys_enter_set_robust_list", objs.SysSetRobustListCallback, nil)
	defer sys_set_robust_list_hook.Close()
	log.Println("sys_set_robust_list kprobe attached!")

	sys_setsid_hook, _ := link.Tracepoint("syscalls", "sys_enter_setsid", objs.SysSetsidCallback, nil)
	defer sys_setsid_hook.Close()
	log.Println("sys_setsid kprobe attached!")

	sys_setsockopt_hook, _ := link.Tracepoint("syscalls", "sys_enter_setsockopt", objs.SysSetsockoptCallback, nil)
	defer sys_setsockopt_hook.Close()
	log.Println("sys_setsockopt kprobe attached!")

	sys_set_tid_address_hook, _ := link.Tracepoint("syscalls", "sys_enter_set_tid_address", objs.SysSetTidAddressCallback, nil)
	defer sys_set_tid_address_hook.Close()
	log.Println("sys_set_tid_address kprobe attached!")

	sys_settimeofday_hook, _ := link.Tracepoint("syscalls", "sys_enter_settimeofday", objs.SysSettimeofdayCallback, nil)
	defer sys_settimeofday_hook.Close()
	log.Println("sys_settimeofday kprobe attached!")

	sys_setuid_hook, _ := link.Tracepoint("syscalls", "sys_enter_setuid", objs.SysSetuidCallback, nil)
	defer sys_setuid_hook.Close()
	log.Println("sys_setuid kprobe attached!")

	sys_setxattr_hook, _ := link.Tracepoint("syscalls", "sys_enter_setxattr", objs.SysSetxattrCallback, nil)
	defer sys_setxattr_hook.Close()
	log.Println("sys_setxattr kprobe attached!")

	sys_shmat_hook, _ := link.Tracepoint("syscalls", "sys_enter_shmat", objs.SysShmatCallback, nil)
	defer sys_shmat_hook.Close()
	log.Println("sys_shmat kprobe attached!")

	sys_shmctl_hook, _ := link.Tracepoint("syscalls", "sys_enter_shmctl", objs.SysShmctlCallback, nil)
	defer sys_shmctl_hook.Close()
	log.Println("sys_shmctl kprobe attached!")

	sys_shmdt_hook, _ := link.Tracepoint("syscalls", "sys_enter_shmdt", objs.SysShmdtCallback, nil)
	defer sys_shmdt_hook.Close()
	log.Println("sys_shmdt kprobe attached!")

	sys_shmget_hook, _ := link.Tracepoint("syscalls", "sys_enter_shmget", objs.SysShmgetCallback, nil)
	defer sys_shmget_hook.Close()
	log.Println("sys_shmget kprobe attached!")

	sys_shutdown_hook, _ := link.Tracepoint("syscalls", "sys_enter_shutdown", objs.SysShutdownCallback, nil)
	defer sys_shutdown_hook.Close()
	log.Println("sys_shutdown kprobe attached!")

	sys_sigaltstack_hook, _ := link.Tracepoint("syscalls", "sys_enter_sigaltstack", objs.SysSigaltstackCallback, nil)
	defer sys_sigaltstack_hook.Close()
	log.Println("sys_sigaltstack kprobe attached!")

	sys_signalfd_hook, _ := link.Tracepoint("syscalls", "sys_enter_signalfd", objs.SysSignalfdCallback, nil)
	defer sys_signalfd_hook.Close()
	log.Println("sys_signalfd kprobe attached!")

	sys_signalfd4_hook, _ := link.Tracepoint("syscalls", "sys_enter_signalfd4", objs.SysSignalfd4Callback, nil)
	defer sys_signalfd4_hook.Close()
	log.Println("sys_signalfd4 kprobe attached!")

	sys_socket_hook, _ := link.Tracepoint("syscalls", "sys_enter_socket", objs.SysSocketCallback, nil)
	defer sys_socket_hook.Close()
	log.Println("sys_socket kprobe attached!")

	sys_socketpair_hook, _ := link.Tracepoint("syscalls", "sys_enter_socketpair", objs.SysSocketpairCallback, nil)
	defer sys_socketpair_hook.Close()
	log.Println("sys_socketpair kprobe attached!")

	sys_splice_hook, _ := link.Tracepoint("syscalls", "sys_enter_splice", objs.SysSpliceCallback, nil)
	defer sys_splice_hook.Close()
	log.Println("sys_splice kprobe attached!")

	sys_statfs_hook, _ := link.Tracepoint("syscalls", "sys_enter_statfs", objs.SysStatfsCallback, nil)
	defer sys_statfs_hook.Close()
	log.Println("sys_statfs kprobe attached!")

	sys_statx_hook, _ := link.Tracepoint("syscalls", "sys_enter_statx", objs.SysStatxCallback, nil)
	defer sys_statx_hook.Close()
	log.Println("sys_statx kprobe attached!")

	sys_swapoff_hook, _ := link.Tracepoint("syscalls", "sys_enter_swapoff", objs.SysSwapoffCallback, nil)
	defer sys_swapoff_hook.Close()
	log.Println("sys_swapoff kprobe attached!")

	sys_swapon_hook, _ := link.Tracepoint("syscalls", "sys_enter_swapon", objs.SysSwaponCallback, nil)
	defer sys_swapon_hook.Close()
	log.Println("sys_swapon kprobe attached!")

	sys_symlink_hook, _ := link.Tracepoint("syscalls", "sys_enter_symlink", objs.SysSymlinkCallback, nil)
	defer sys_symlink_hook.Close()
	log.Println("sys_symlink kprobe attached!")

	sys_symlinkat_hook, _ := link.Tracepoint("syscalls", "sys_enter_symlinkat", objs.SysSymlinkatCallback, nil)
	defer sys_symlinkat_hook.Close()
	log.Println("sys_symlinkat kprobe attached!")

	sys_sync_hook, _ := link.Tracepoint("syscalls", "sys_enter_sync", objs.SysSyncCallback, nil)
	defer sys_sync_hook.Close()
	log.Println("sys_sync kprobe attached!")

	sys_sync_file_range_hook, _ := link.Tracepoint("syscalls", "sys_enter_sync_file_range", objs.SysSyncFileRangeCallback, nil)
	defer sys_sync_file_range_hook.Close()
	log.Println("sys_sync_file_range kprobe attached!")

	sys_syncfs_hook, _ := link.Tracepoint("syscalls", "sys_enter_syncfs", objs.SysSyncfsCallback, nil)
	defer sys_syncfs_hook.Close()
	log.Println("sys_syncfs kprobe attached!")

	sys_sysfs_hook, _ := link.Tracepoint("syscalls", "sys_enter_sysfs", objs.SysSysfsCallback, nil)
	defer sys_sysfs_hook.Close()
	log.Println("sys_sysfs kprobe attached!")

	sys_sysinfo_hook, _ := link.Tracepoint("syscalls", "sys_enter_sysinfo", objs.SysSysinfoCallback, nil)
	defer sys_sysinfo_hook.Close()
	log.Println("sys_sysinfo kprobe attached!")

	sys_syslog_hook, _ := link.Tracepoint("syscalls", "sys_enter_syslog", objs.SysSyslogCallback, nil)
	defer sys_syslog_hook.Close()
	log.Println("sys_syslog kprobe attached!")

	sys_tee_hook, _ := link.Tracepoint("syscalls", "sys_enter_tee", objs.SysTeeCallback, nil)
	defer sys_tee_hook.Close()
	log.Println("sys_tee kprobe attached!")

	sys_tgkill_hook, _ := link.Tracepoint("syscalls", "sys_enter_tgkill", objs.SysTgkillCallback, nil)
	defer sys_tgkill_hook.Close()
	log.Println("sys_tgkill kprobe attached!")

	sys_time_hook, _ := link.Tracepoint("syscalls", "sys_enter_time", objs.SysTimeCallback, nil)
	defer sys_time_hook.Close()
	log.Println("sys_time kprobe attached!")

	sys_timer_create_hook, _ := link.Tracepoint("syscalls", "sys_enter_timer_create", objs.SysTimerCreateCallback, nil)
	defer sys_timer_create_hook.Close()
	log.Println("sys_timer_create kprobe attached!")

	sys_timer_delete_hook, _ := link.Tracepoint("syscalls", "sys_enter_timer_delete", objs.SysTimerDeleteCallback, nil)
	defer sys_timer_delete_hook.Close()
	log.Println("sys_timer_delete kprobe attached!")

	sys_timerfd_create_hook, _ := link.Tracepoint("syscalls", "sys_enter_timerfd_create", objs.SysTimerfdCreateCallback, nil)
	defer sys_timerfd_create_hook.Close()
	log.Println("sys_timerfd_create kprobe attached!")

	sys_timerfd_gettime_hook, _ := link.Tracepoint("syscalls", "sys_enter_timerfd_gettime", objs.SysTimerfdGettimeCallback, nil)
	defer sys_timerfd_gettime_hook.Close()
	log.Println("sys_timerfd_gettime kprobe attached!")

	sys_timerfd_settime_hook, _ := link.Tracepoint("syscalls", "sys_enter_timerfd_settime", objs.SysTimerfdSettimeCallback, nil)
	defer sys_timerfd_settime_hook.Close()
	log.Println("sys_timerfd_settime kprobe attached!")

	sys_timer_getoverrun_hook, _ := link.Tracepoint("syscalls", "sys_enter_timer_getoverrun", objs.SysTimerGetoverrunCallback, nil)
	defer sys_timer_getoverrun_hook.Close()
	log.Println("sys_timer_getoverrun kprobe attached!")

	sys_timer_gettime_hook, _ := link.Tracepoint("syscalls", "sys_enter_timer_gettime", objs.SysTimerGettimeCallback, nil)
	defer sys_timer_gettime_hook.Close()
	log.Println("sys_timer_gettime kprobe attached!")

	sys_timer_settime_hook, _ := link.Tracepoint("syscalls", "sys_enter_timer_settime", objs.SysTimerSettimeCallback, nil)
	defer sys_timer_settime_hook.Close()
	log.Println("sys_timer_settime kprobe attached!")

	sys_times_hook, _ := link.Tracepoint("syscalls", "sys_enter_times", objs.SysTimesCallback, nil)
	defer sys_times_hook.Close()
	log.Println("sys_times kprobe attached!")

	sys_tkill_hook, _ := link.Tracepoint("syscalls", "sys_enter_tkill", objs.SysTkillCallback, nil)
	defer sys_tkill_hook.Close()
	log.Println("sys_tkill kprobe attached!")

	sys_truncate_hook, _ := link.Tracepoint("syscalls", "sys_enter_truncate", objs.SysTruncateCallback, nil)
	defer sys_truncate_hook.Close()
	log.Println("sys_truncate kprobe attached!")

	sys_umask_hook, _ := link.Tracepoint("syscalls", "sys_enter_umask", objs.SysUmaskCallback, nil)
	defer sys_umask_hook.Close()
	log.Println("sys_umask kprobe attached!")

	sys_umount_hook, _ := link.Tracepoint("syscalls", "sys_enter_umount", objs.SysUmountCallback, nil)
	defer sys_umount_hook.Close()
	log.Println("sys_umount kprobe attached!")

	sys_unlink_hook, _ := link.Tracepoint("syscalls", "sys_enter_unlink", objs.SysUnlinkCallback, nil)
	defer sys_unlink_hook.Close()
	log.Println("sys_unlink kprobe attached!")

	sys_unlinkat_hook, _ := link.Tracepoint("syscalls", "sys_enter_unlinkat", objs.SysUnlinkatCallback, nil)
	defer sys_unlinkat_hook.Close()
	log.Println("sys_unlinkat kprobe attached!")

	sys_unshare_hook, _ := link.Tracepoint("syscalls", "sys_enter_unshare", objs.SysUnshareCallback, nil)
	defer sys_unshare_hook.Close()
	log.Println("sys_unshare kprobe attached!")

	sys_userfaultfd_hook, _ := link.Tracepoint("syscalls", "sys_enter_userfaultfd", objs.SysUserfaultfdCallback, nil)
	defer sys_userfaultfd_hook.Close()
	log.Println("sys_userfaultfd kprobe attached!")

	sys_ustat_hook, _ := link.Tracepoint("syscalls", "sys_enter_ustat", objs.SysUstatCallback, nil)
	defer sys_ustat_hook.Close()
	log.Println("sys_ustat kprobe attached!")

	sys_utime_hook, _ := link.Tracepoint("syscalls", "sys_enter_utime", objs.SysUtimeCallback, nil)
	defer sys_utime_hook.Close()
	log.Println("sys_utime kprobe attached!")

	sys_utimensat_hook, _ := link.Tracepoint("syscalls", "sys_enter_utimensat", objs.SysUtimensatCallback, nil)
	defer sys_utimensat_hook.Close()
	log.Println("sys_utimensat kprobe attached!")

	sys_utimes_hook, _ := link.Tracepoint("syscalls", "sys_enter_utimes", objs.SysUtimesCallback, nil)
	defer sys_utimes_hook.Close()
	log.Println("sys_utimes kprobe attached!")

	sys_vfork_hook, _ := link.Tracepoint("syscalls", "sys_enter_vfork", objs.SysVforkCallback, nil)
	defer sys_vfork_hook.Close()
	log.Println("sys_vfork kprobe attached!")

	sys_vhangup_hook, _ := link.Tracepoint("syscalls", "sys_enter_vhangup", objs.SysVhangupCallback, nil)
	defer sys_vhangup_hook.Close()
	log.Println("sys_vhangup kprobe attached!")

	sys_vmsplice_hook, _ := link.Tracepoint("syscalls", "sys_enter_vmsplice", objs.SysVmspliceCallback, nil)
	defer sys_vmsplice_hook.Close()
	log.Println("sys_vmsplice kprobe attached!")

	sys_wait4_hook, _ := link.Tracepoint("syscalls", "sys_enter_wait4", objs.SysWait4Callback, nil)
	defer sys_wait4_hook.Close()
	log.Println("sys_wait4 kprobe attached!")

	sys_waitid_hook, _ := link.Tracepoint("syscalls", "sys_enter_waitid", objs.SysWaitidCallback, nil)
	defer sys_waitid_hook.Close()
	log.Println("sys_waitid kprobe attached!")

	sys_write_hook, _ := link.Tracepoint("syscalls", "sys_enter_write", objs.SysWriteCallback, nil)
	defer sys_write_hook.Close()
	log.Println("sys_write kprobe attached!")

	sys_writev_hook, _ := link.Tracepoint("syscalls", "sys_enter_writev", objs.SysWritevCallback, nil)
	defer sys_writev_hook.Close()
	log.Println("sys_writev kprobe attached!")

	// lsm_task_alloc, _ := link.AttachLSM(link.LSMOptions{Program: objs.TaskAlloc})
	// defer lsm_task_alloc.Close()
	// log.Println("lsm_task_alloc Attached!")

	// lsm_bprm_check, _ := link.AttachLSM(link.LSMOptions{Program: objs.BprmCheck})
	// defer lsm_bprm_check.Close()
	// log.Println("lsm_bprm_check Attached!")

	// lsm_ptrace_check, _ := link.AttachLSM(link.LSMOptions{Program: objs.PtraceCheck})
	// defer lsm_ptrace_check.Close()
	// log.Println("lsm_ptrace_check Attached!")

	// lsm_path_chmod, _ := link.AttachLSM(link.LSMOptions{Program: objs.PathChmod})
	// defer lsm_path_chmod.Close()
	// log.Println("lsm_path_chmod Attached!")

	// lsm_file_mprotect, _ := link.AttachLSM(link.LSMOptions{Program: objs.FileMprotect})
	// defer lsm_file_mprotect.Close()
	// log.Println("lsm_file_mprotect Attached!")

	// lsm_fix_setgid, _ := link.AttachLSM(link.LSMOptions{Program: objs.FixSetgid})
	// defer lsm_fix_setgid.Close()
	// log.Println("lsm_fix_setgid Attached!")

	// lsm_fix_setuid, _ := link.AttachLSM(link.LSMOptions{Program: objs.FixSetuid})
	// defer lsm_fix_setuid.Close()
	// log.Println("lsm_fix_setuid Attached!")

	// lsm_socket_accept, _ := link.AttachLSM(link.LSMOptions{Program: objs.SocketAccept})
	// defer lsm_socket_accept.Close()
	// log.Println("lsm_socket_accept Attached!")

	// lsm_socket_bind, _ := link.AttachLSM(link.LSMOptions{Program: objs.SocketBind})
	// defer lsm_socket_bind.Close()
	// log.Println("lsm_socket_bind Attached!")

	// lsm_socket_connect, _ := link.AttachLSM(link.LSMOptions{Program: objs.SocketConnect})
	// defer lsm_socket_connect.Close()
	// log.Println("lsm_socket_connect Attached!")

	// lsm_socket_listen, _ := link.AttachLSM(link.LSMOptions{Program: objs.SocketListen})
	// defer lsm_socket_listen.Close()
	// log.Println("lsm_socket_listen Attached!")

	// lsm_socket_recvmsg, _ := link.AttachLSM(link.LSMOptions{Program: objs.SocketRecvmsg})
	// defer lsm_socket_recvmsg.Close()
	// log.Println("lsm_socket_recvmsg Attached!")

	// lsm_socket_create, _ := link.AttachLSM(link.LSMOptions{Program: objs.SocketCreate})
	// defer lsm_socket_create.Close()
	// log.Println("lsm_socket_create Attached!")

	// lsm_file_permission, _ := link.AttachLSM(link.LSMOptions{Program: objs.FilePermission})
	// defer lsm_file_permission.Close()
	// log.Println("lsm_file_permission Attached!")

	// lsm_socket_getpeername, _ := link.AttachLSM(link.LSMOptions{Program: objs.SocketGetpeername})
	// defer lsm_socket_getpeername.Close()
	// log.Println("lsm_socket_getpeername Attached!")

	// lsm_socket_getsockname, _ := link.AttachLSM(link.LSMOptions{Program: objs.SocketGetsockname})
	// defer lsm_socket_getsockname.Close()
	// log.Println("lsm_socket_getsockname Attached!")

	// lsm_socket_getsockopt, _ := link.AttachLSM(link.LSMOptions{Program: objs.SocketGetsockopt})
	// defer lsm_socket_getsockopt.Close()
	// log.Println("lsm_socket_getsockopt Attached!")

	// lsm_socket_sendmsg, _ := link.AttachLSM(link.LSMOptions{Program: objs.SocketSendmsg})
	// defer lsm_socket_sendmsg.Close()
	// log.Println("lsm_socket_sendmsg Attached!")

	// lsm_socket_setsockopt, _ := link.AttachLSM(link.LSMOptions{Program: objs.SocketSetsockopt})
	// defer lsm_socket_setsockopt.Close()
	// log.Println("lsm_socket_setsockopt Attached!")

	// lsm_socket_shutdown, _ := link.AttachLSM(link.LSMOptions{Program: objs.SocketShutdown})
	// defer lsm_socket_shutdown.Close()
	// log.Println("lsm_socket_shutdown Attached!")

	// lsm_capable, _ := link.AttachLSM(link.LSMOptions{Program: objs.Capable})
	// defer lsm_capable.Close()
	// log.Println("lsm_capable Attached!")

	// lsm_capget, _ := link.AttachLSM(link.LSMOptions{Program: objs.Capget})
	// defer lsm_capget.Close()
	// log.Println("lsm_capget Attached!")

	// lsm_capset, _ := link.AttachLSM(link.LSMOptions{Program: objs.Capset})
	// defer lsm_capset.Close()
	// log.Println("lsm_capset Attached!")

	// lsm_quotactl, _ := link.AttachLSM(link.LSMOptions{Program: objs.Quotactl})
	// defer lsm_quotactl.Close()
	// log.Println("lsm_quotactl Attached!")

	// lsm_syslog, _ := link.AttachLSM(link.LSMOptions{Program: objs.Syslog})
	// defer lsm_syslog.Close()
	// log.Println("lsm_syslog Attached!")

	// lsm_settime, _ := link.AttachLSM(link.LSMOptions{Program: objs.Settime})
	// defer lsm_settime.Close()
	// log.Println("lsm_settime Attached!")

	// lsm_sb_free_mnt_opts, _ := link.AttachLSM(link.LSMOptions{Program: objs.SbFreeMntOpts})
	// defer lsm_sb_free_mnt_opts.Close()
	// log.Println("lsm_sb_free_mnt_opts Attached!")

	// lsm_sb_statfs, _ := link.AttachLSM(link.LSMOptions{Program: objs.SbStatfs})
	// defer lsm_sb_statfs.Close()
	// log.Println("lsm_sb_statfs Attached!")

	// lsm_sb_pivotroot, _ := link.AttachLSM(link.LSMOptions{Program: objs.SbPivotroot})
	// defer lsm_sb_pivotroot.Close()
	// log.Println("lsm_sb_pivotroot Attached!")

	// lsm_move_mount, _ := link.AttachLSM(link.LSMOptions{Program: objs.MoveMount})
	// defer lsm_move_mount.Close()
	// log.Println("lsm_move_mount Attached!")

	// lsm_path_notify, _ := link.AttachLSM(link.LSMOptions{Program: objs.PathNotify})
	// defer lsm_path_notify.Close()
	// log.Println("lsm_path_notify Attached!")

	// lsm_path_mkdir, _ := link.AttachLSM(link.LSMOptions{Program: objs.PathMkdir})
	// defer lsm_path_mkdir.Close()
	// log.Println("lsm_path_mkdir Attached!")

	// lsm_path_rmdir, _ := link.AttachLSM(link.LSMOptions{Program: objs.PathRmdir})
	// defer lsm_path_rmdir.Close()
	// log.Println("lsm_path_rmdir Attached!")

	// lsm_path_unlink, _ := link.AttachLSM(link.LSMOptions{Program: objs.PathUnlink})
	// defer lsm_path_unlink.Close()
	// log.Println("lsm_path_unlink Attached!")

	// lsm_path_symlink, _ := link.AttachLSM(link.LSMOptions{Program: objs.PathSymlink})
	// defer lsm_path_symlink.Close()
	// log.Println("lsm_path_symlink Attached!")

	// lsm_path_link, _ := link.AttachLSM(link.LSMOptions{Program: objs.PathLink})
	// defer lsm_path_link.Close()
	// log.Println("lsm_path_link Attached!")

	// lsm_path_rename, _ := link.AttachLSM(link.LSMOptions{Program: objs.PathRename})
	// defer lsm_path_rename.Close()
	// log.Println("lsm_path_rename Attached!")

	// lsm_path_truncate, _ := link.AttachLSM(link.LSMOptions{Program: objs.PathTruncate})
	// defer lsm_path_truncate.Close()
	// log.Println("lsm_path_truncate Attached!")

	// lsm_path_chown, _ := link.AttachLSM(link.LSMOptions{Program: objs.PathChown})
	// defer lsm_path_chown.Close()
	// log.Println("lsm_path_chown Attached!")

	// lsm_path_chroot, _ := link.AttachLSM(link.LSMOptions{Program: objs.PathChroot})
	// defer lsm_path_chroot.Close()
	// log.Println("lsm_path_chroot Attached!")

	// lsm_mmap_file, _ := link.AttachLSM(link.LSMOptions{Program: objs.MmapFile})
	// defer lsm_mmap_file.Close()
	// log.Println("lsm_mmap_file Attached!")

	// lsm_mmap_addr, _ := link.AttachLSM(link.LSMOptions{Program: objs.MmapAddr})
	// defer lsm_mmap_addr.Close()
	// log.Println("lsm_mmap_addr Attached!")

	// lsm_file_fcntl, _ := link.AttachLSM(link.LSMOptions{Program: objs.FileFcntl})
	// defer lsm_file_fcntl.Close()
	// log.Println("lsm_file_fcntl Attached!")

	// lsm_task_setpgid, _ := link.AttachLSM(link.LSMOptions{Program: objs.TaskSetpgid})
	// defer lsm_task_setpgid.Close()
	// log.Println("lsm_task_setpgid Attached!")

	// lsm_task_getpgid, _ := link.AttachLSM(link.LSMOptions{Program: objs.TaskGetpgid})
	// defer lsm_task_getpgid.Close()
	// log.Println("lsm_task_getpgid Attached!")

	// lsm_task_getsid, _ := link.AttachLSM(link.LSMOptions{Program: objs.TaskGetsid})
	// defer lsm_task_getsid.Close()
	// log.Println("lsm_task_getsid Attached!")

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
	}
	defer rd.Close()
	go consoleCommands()
	Daemon()
	// containerdDaemon()

	go func() {
		<-stopper
		if err := rd.Close(); err != nil {
			log.Fatalf("closing ringbuf reader: %s", err)
		}

		policy_map, err := ebpf.LoadPinnedMap("/sys/fs/bpf/daemon_map/policy_map", nil)
		if err != nil || policy_map == nil {
			log.Fatalf("Error loading policy_map: %v", err)
		}
		defer policy_map.Close()

		lsm_to_syscall, err := ebpf.LoadPinnedMap("/sys/fs/bpf/daemon_map/lsm_to_syscall", nil)
		if err != nil || lsm_to_syscall == nil {
			log.Fatalf("Error loading pid_lsm_syscall_map: %v", err)
		}
		defer lsm_to_syscall.Close()

		policy_params_bprm_check, err := ebpf.LoadPinnedMap("/sys/fs/bpf/daemon_map/policy_params_bprm_check", nil)
		if err != nil || policy_params_bprm_check == nil {
			log.Fatalf("Error loading socket_bind_allow_policy: %v", err)
		}
		defer policy_params_bprm_check.Close()

		policy_params_task_alloc, err := ebpf.LoadPinnedMap("/sys/fs/bpf/daemon_map/policy_params_task_alloc", nil)
		if err != nil || policy_params_task_alloc == nil {
			log.Fatalf("Error loading policy_params_task_alloc: %v", err)
		}
		defer policy_params_task_alloc.Close()

		policy_params_ptrace_access, err := ebpf.LoadPinnedMap("/sys/fs/bpf/daemon_map/policy_params_ptrace_access", nil)
		if err != nil || policy_params_ptrace_access == nil {
			log.Fatalf("Error loading policy_params_ptrace_access: %v", err)
		}
		defer policy_params_ptrace_access.Close()

		policy_params_file_mprotect, err := ebpf.LoadPinnedMap("/sys/fs/bpf/daemon_map/policy_params_file_mprotect", nil)
		if err != nil || policy_params_file_mprotect == nil {
			log.Fatalf("Error loading policy_params_file_mprotect: %v", err)
		}
		defer policy_params_file_mprotect.Close()

		policy_params_fix_setgid, err := ebpf.LoadPinnedMap("/sys/fs/bpf/daemon_map/policy_params_fix_setgid", nil)
		if err != nil || policy_params_fix_setgid == nil {
			log.Fatalf("Error loading policy_params_fix_setgid: %v", err)
		}
		defer policy_params_fix_setgid.Close()

		policy_params_fix_setuid, err := ebpf.LoadPinnedMap("/sys/fs/bpf/daemon_map/policy_params_fix_setuid", nil)
		if err != nil || policy_params_fix_setuid == nil {
			log.Fatalf("Error loading policy_params_fix_setuid: %v", err)
		}
		defer policy_params_fix_setuid.Close()

		policy_params_socket_accept, err := ebpf.LoadPinnedMap("/sys/fs/bpf/daemon_map/policy_params_socket_accept", nil)
		if err != nil || policy_params_socket_accept == nil {
			log.Fatalf("Error loading policy_params_socket_accept: %v", err)
		}
		defer policy_params_socket_accept.Close()

		policy_params_socket_listen, err := ebpf.LoadPinnedMap("/sys/fs/bpf/daemon_map/policy_params_socket_listen", nil)
		if err != nil || policy_params_socket_listen == nil {
			log.Fatalf("Error loading policy_params_socket_listen: %v", err)
		}
		defer policy_params_socket_listen.Close()

		policy_params_socket_recvmsg, err := ebpf.LoadPinnedMap("/sys/fs/bpf/daemon_map/policy_params_socket_recvmsg", nil)
		if err != nil || policy_params_socket_recvmsg == nil {
			log.Fatalf("Error loading policy_params_socket_recvmsg: %v", err)
		}
		defer policy_params_socket_recvmsg.Close()

		policy_params_socket_create, err := ebpf.LoadPinnedMap("/sys/fs/bpf/daemon_map/policy_params_socket_create", nil)
		if err != nil || policy_params_socket_create == nil {
			log.Fatalf("Error loading policy_params_socket_create: %v", err)
		}
		defer policy_params_socket_create.Close()

		policy_params_path_chmod, err := ebpf.LoadPinnedMap("/sys/fs/bpf/daemon_map/policy_params_path_chmod", nil)
		if err != nil || policy_params_path_chmod == nil {
			log.Fatalf("Error loading policy_params_path_chmod: %v", err)
		}
		defer policy_params_path_chmod.Close()

		policy_params_socket_bind, err := ebpf.LoadPinnedMap("/sys/fs/bpf/daemon_map/policy_params_socket_bind", nil)
		if err != nil || policy_params_socket_bind == nil {
			log.Fatalf("Error loading policy_params_socket_bind: %v", err)
		}
		defer policy_params_socket_bind.Close()

		policy_params_socket_connect, err := ebpf.LoadPinnedMap("/sys/fs/bpf/daemon_map/policy_params_socket_connect", nil)
		if err != nil || policy_params_socket_connect == nil {
			log.Fatalf("Error loading policy_params_socket_connect: %v", err)
		}
		defer policy_params_socket_connect.Close()

		monitoring_map, err := ebpf.LoadPinnedMap("/sys/fs/bpf/daemon_map/monitoring_map", nil)
		if err != nil || monitoring_map == nil {
			log.Fatalf("Error loading monitoring_map: %v", err)
		}
		defer monitoring_map.Close()

		containerID_PID_map, err := ebpf.LoadPinnedMap("/sys/fs/bpf/daemon_map/containerID_PID_map", nil)
		if err != nil || containerID_PID_map == nil {
			log.Fatalf("Error loading containerID_PID_map: %v", err)
		}
		defer containerID_PID_map.Close()

		err = policy_map.Unpin()
		if err != nil {
			log.Fatalf("could not delete element : %s", err)
		}

		err = lsm_to_syscall.Unpin()
		if err != nil {
			log.Fatalf("could not delete element : %s", err)
		}

		err = policy_params_bprm_check.Unpin()
		if err != nil {
			log.Fatalf("could not delete element : %s", err)
		}

		err = policy_params_task_alloc.Unpin()
		if err != nil {
			log.Fatalf("could not delete element : %s", err)
		}

		err = policy_params_ptrace_access.Unpin()
		if err != nil {
			log.Fatalf("could not delete element : %s", err)
		}

		err = policy_params_file_mprotect.Unpin()
		if err != nil {
			log.Fatalf("could not delete element : %s", err)
		}

		err = policy_params_fix_setgid.Unpin()
		if err != nil {
			log.Fatalf("could not delete element : %s", err)
		}

		err = policy_params_fix_setuid.Unpin()
		if err != nil {
			log.Fatalf("could not delete element : %s", err)
		}

		err = policy_params_socket_accept.Unpin()
		if err != nil {
			log.Fatalf("could not delete element : %s", err)
		}

		err = policy_params_socket_listen.Unpin()
		if err != nil {
			log.Fatalf("could not delete element : %s", err)
		}

		err = policy_params_socket_recvmsg.Unpin()
		if err != nil {
			log.Fatalf("could not delete element : %s", err)
		}

		err = policy_params_socket_create.Unpin()
		if err != nil {
			log.Fatalf("could not delete element : %s", err)
		}

		err = policy_params_path_chmod.Unpin()
		if err != nil {
			log.Fatalf("could not delete element : %s", err)
		}

		err = policy_params_socket_bind.Unpin()
		if err != nil {
			log.Fatalf("could not delete element : %s", err)
		}

		err = policy_params_socket_connect.Unpin()
		if err != nil {
			log.Fatalf("could not delete element : %s", err)
		}

		err = monitoring_map.Unpin()
		if err != nil {
			log.Fatalf("could not delete element : %s", err)
		}

		err = containerID_PID_map.Unpin()
		if err != nil {
			log.Fatalf("could not delete element : %s", err)
		}

		os.Exit(0)
	}()

	var event bpfEvent
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("Received signal, exiting..")
				return
			}
			log.Printf("reading from reader: %s", err)
			continue
		}

		// Check buffer input, print out event
		// binary.Read 함수로 바이너리 데이터를 읽어 event 구조체로 디코딩
		// record.RawSample은 읽을 바이너리 데이터를 담고 있는 슬라이스로, 이를 바이트 버퍼로 변환하여 리더로 사용
		err = binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event)
		// nil --> 초기값을 할당하지 않고 변수를 만들었을 때 갖게 되는 값
		if err == nil {
			// Translate reason for blocking
			reason := "blocked PID"

			// Print out log
			log.Printf("[INFO] LSM blocked %s\n"+
				"\t PID: %d\n"+
				"\t Comm: %s\n", reason, event.Pid, unix.ByteSliceToString(event.Comm[:]))
		}
	}

	// for{}

	log.Println("Waiting for events..")
}
