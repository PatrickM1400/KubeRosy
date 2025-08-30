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

	sys_read_hook, _ := link.Kprobe("sys_read", objs.SysReadCallback, nil)
	defer sys_read_hook.Close()
	log.Println("sys_read kprobe attached!")

	sys_write_hook, _ := link.Kprobe("sys_write", objs.SysWriteCallback, nil)
	defer sys_write_hook.Close()
	log.Println("sys_write kprobe attached!")

	sys_open_hook, _ := link.Kprobe("sys_open", objs.SysOpenCallback, nil)
	defer sys_open_hook.Close()
	log.Println("sys_open kprobe attached!")

	sys_close_hook, _ := link.Kprobe("sys_close", objs.SysCloseCallback, nil)
	defer sys_close_hook.Close()
	log.Println("sys_close kprobe attached!")

	sys_mmap_hook, _ := link.Kprobe("sys_mmap", objs.SysMmapCallback, nil)
	defer sys_mmap_hook.Close()
	log.Println("sys_mmap kprobe attached!")

	sys_mprotect_hook, _ := link.Kprobe("sys_mprotect", objs.SysMprotectCallback, nil)
	defer sys_mprotect_hook.Close()
	log.Println("sys_mprotect kprobe attached!")

	sys_pread64_hook, _ := link.Kprobe("sys_pread64", objs.SysPread64Callback, nil)
	defer sys_pread64_hook.Close()
	log.Println("sys_pread64 kprobe attached!")

	sys_pwrite64_hook, _ := link.Kprobe("sys_pwrite64", objs.SysPwrite64Callback, nil)
	defer sys_pwrite64_hook.Close()
	log.Println("sys_pwrite64 kprobe attached!")

	sys_readv_hook, _ := link.Kprobe("sys_readv", objs.SysReadvCallback, nil)
	defer sys_readv_hook.Close()
	log.Println("sys_readv kprobe attached!")

	sys_writev_hook, _ := link.Kprobe("sys_writev", objs.SysWritevCallback, nil)
	defer sys_writev_hook.Close()
	log.Println("sys_writev kprobe attached!")

	sys_shmat_hook, _ := link.Kprobe("sys_shmat", objs.SysShmatCallback, nil)
	defer sys_shmat_hook.Close()
	log.Println("sys_shmat kprobe attached!")

	sys_sendfile_hook, _ := link.Kprobe("sys_sendfile", objs.SysSendfileCallback, nil)
	defer sys_sendfile_hook.Close()
	log.Println("sys_sendfile kprobe attached!")

	sys_socket_hook, _ := link.Kprobe("sys_socket", objs.SysSocketCallback, nil)
	defer sys_socket_hook.Close()
	log.Println("sys_socket kprobe attached!")

	sys_connect_hook, _ := link.Kprobe("sys_connect", objs.SysConnectCallback, nil)
	defer sys_connect_hook.Close()
	log.Println("sys_connect kprobe attached!")

	sys_accept_hook, _ := link.Kprobe("sys_accept", objs.SysAcceptCallback, nil)
	defer sys_accept_hook.Close()
	log.Println("sys_accept kprobe attached!")

	sys_sendto_hook, _ := link.Kprobe("sys_sendto", objs.SysSendtoCallback, nil)
	defer sys_sendto_hook.Close()
	log.Println("sys_sendto kprobe attached!")

	sys_recvfrom_hook, _ := link.Kprobe("sys_recvfrom", objs.SysRecvfromCallback, nil)
	defer sys_recvfrom_hook.Close()
	log.Println("sys_recvfrom kprobe attached!")

	sys_sendmsg_hook, _ := link.Kprobe("sys_sendmsg", objs.SysSendmsgCallback, nil)
	defer sys_sendmsg_hook.Close()
	log.Println("sys_sendmsg kprobe attached!")

	sys_recvmsg_hook, _ := link.Kprobe("sys_recvmsg", objs.SysRecvmsgCallback, nil)
	defer sys_recvmsg_hook.Close()
	log.Println("sys_recvmsg kprobe attached!")

	sys_shutdown_hook, _ := link.Kprobe("sys_shutdown", objs.SysShutdownCallback, nil)
	defer sys_shutdown_hook.Close()
	log.Println("sys_shutdown kprobe attached!")

	sys_bind_hook, _ := link.Kprobe("sys_bind", objs.SysBindCallback, nil)
	defer sys_bind_hook.Close()
	log.Println("sys_bind kprobe attached!")

	sys_listen_hook, _ := link.Kprobe("sys_listen", objs.SysListenCallback, nil)
	defer sys_listen_hook.Close()
	log.Println("sys_listen kprobe attached!")

	sys_getpeername_hook, _ := link.Kprobe("sys_getpeername", objs.SysGetpeernameCallback, nil)
	defer sys_getpeername_hook.Close()
	log.Println("sys_getpeername kprobe attached!")

	sys_socketpair_hook, _ := link.Kprobe("sys_socketpair", objs.SysSocketpairCallback, nil)
	defer sys_socketpair_hook.Close()
	log.Println("sys_socketpair kprobe attached!")

	sys_setsockopt_hook, _ := link.Kprobe("sys_setsockopt", objs.SysSetsockoptCallback, nil)
	defer sys_setsockopt_hook.Close()
	log.Println("sys_setsockopt kprobe attached!")

	sys_clone_hook, _ := link.Kprobe("sys_clone", objs.SysCloneCallback, nil)
	defer sys_clone_hook.Close()
	log.Println("sys_clone kprobe attached!")

	sys_fork_hook, _ := link.Kprobe("sys_fork", objs.SysForkCallback, nil)
	defer sys_fork_hook.Close()
	log.Println("sys_fork kprobe attached!")

	sys_vfork_hook, _ := link.Kprobe("sys_vfork", objs.SysVforkCallback, nil)
	defer sys_vfork_hook.Close()
	log.Println("sys_vfork kprobe attached!")

	sys_execve_hook, _ := link.Kprobe("sys_execve", objs.SysExecveCallback, nil)
	defer sys_execve_hook.Close()
	log.Println("sys_execve kprobe attached!")

	sys_fcntl_hook, _ := link.Kprobe("sys_fcntl", objs.SysFcntlCallback, nil)
	defer sys_fcntl_hook.Close()
	log.Println("sys_fcntl kprobe attached!")

	sys_ftruncate_hook, _ := link.Kprobe("sys_ftruncate", objs.SysFtruncateCallback, nil)
	defer sys_ftruncate_hook.Close()
	log.Println("sys_ftruncate kprobe attached!")

	sys_rename_hook, _ := link.Kprobe("sys_rename", objs.SysRenameCallback, nil)
	defer sys_rename_hook.Close()
	log.Println("sys_rename kprobe attached!")

	sys_mkdir_hook, _ := link.Kprobe("sys_mkdir", objs.SysMkdirCallback, nil)
	defer sys_mkdir_hook.Close()
	log.Println("sys_mkdir kprobe attached!")

	sys_rmdir_hook, _ := link.Kprobe("sys_rmdir", objs.SysRmdirCallback, nil)
	defer sys_rmdir_hook.Close()
	log.Println("sys_rmdir kprobe attached!")

	sys_creat_hook, _ := link.Kprobe("sys_creat", objs.SysCreatCallback, nil)
	defer sys_creat_hook.Close()
	log.Println("sys_creat kprobe attached!")

	sys_link_hook, _ := link.Kprobe("sys_link", objs.SysLinkCallback, nil)
	defer sys_link_hook.Close()
	log.Println("sys_link kprobe attached!")

	sys_unlink_hook, _ := link.Kprobe("sys_unlink", objs.SysUnlinkCallback, nil)
	defer sys_unlink_hook.Close()
	log.Println("sys_unlink kprobe attached!")

	sys_symlink_hook, _ := link.Kprobe("sys_symlink", objs.SysSymlinkCallback, nil)
	defer sys_symlink_hook.Close()
	log.Println("sys_symlink kprobe attached!")

	sys_chmod_hook, _ := link.Kprobe("sys_chmod", objs.SysChmodCallback, nil)
	defer sys_chmod_hook.Close()
	log.Println("sys_chmod kprobe attached!")

	sys_fchmod_hook, _ := link.Kprobe("sys_fchmod", objs.SysFchmodCallback, nil)
	defer sys_fchmod_hook.Close()
	log.Println("sys_fchmod kprobe attached!")

	sys_chown_hook, _ := link.Kprobe("sys_chown", objs.SysChownCallback, nil)
	defer sys_chown_hook.Close()
	log.Println("sys_chown kprobe attached!")

	sys_fchown_hook, _ := link.Kprobe("sys_fchown", objs.SysFchownCallback, nil)
	defer sys_fchown_hook.Close()
	log.Println("sys_fchown kprobe attached!")

	sys_lchown_hook, _ := link.Kprobe("sys_lchown", objs.SysLchownCallback, nil)
	defer sys_lchown_hook.Close()
	log.Println("sys_lchown kprobe attached!")

	sys_ptrace_hook, _ := link.Kprobe("sys_ptrace", objs.SysPtraceCallback, nil)
	defer sys_ptrace_hook.Close()
	log.Println("sys_ptrace kprobe attached!")

	sys_syslog_hook, _ := link.Kprobe("sys_syslog", objs.SysSyslogCallback, nil)
	defer sys_syslog_hook.Close()
	log.Println("sys_syslog kprobe attached!")

	sys_setuid_hook, _ := link.Kprobe("sys_setuid", objs.SysSetuidCallback, nil)
	defer sys_setuid_hook.Close()
	log.Println("sys_setuid kprobe attached!")

	sys_setgid_hook, _ := link.Kprobe("sys_setgid", objs.SysSetgidCallback, nil)
	defer sys_setgid_hook.Close()
	log.Println("sys_setgid kprobe attached!")

	sys_setpgid_hook, _ := link.Kprobe("sys_setpgid", objs.SysSetpgidCallback, nil)
	defer sys_setpgid_hook.Close()
	log.Println("sys_setpgid kprobe attached!")

	sys_getpgrp_hook, _ := link.Kprobe("sys_getpgrp", objs.SysGetpgrpCallback, nil)
	defer sys_getpgrp_hook.Close()
	log.Println("sys_getpgrp kprobe attached!")

	sys_setreuid_hook, _ := link.Kprobe("sys_setreuid", objs.SysSetreuidCallback, nil)
	defer sys_setreuid_hook.Close()
	log.Println("sys_setreuid kprobe attached!")

	sys_setregid_hook, _ := link.Kprobe("sys_setregid", objs.SysSetregidCallback, nil)
	defer sys_setregid_hook.Close()
	log.Println("sys_setregid kprobe attached!")

	sys_setgroups_hook, _ := link.Kprobe("sys_setgroups", objs.SysSetgroupsCallback, nil)
	defer sys_setgroups_hook.Close()
	log.Println("sys_setgroups kprobe attached!")

	sys_setresuid_hook, _ := link.Kprobe("sys_setresuid", objs.SysSetresuidCallback, nil)
	defer sys_setresuid_hook.Close()
	log.Println("sys_setresuid kprobe attached!")

	sys_setresgid_hook, _ := link.Kprobe("sys_setresgid", objs.SysSetresgidCallback, nil)
	defer sys_setresgid_hook.Close()
	log.Println("sys_setresgid kprobe attached!")

	sys_getsid_hook, _ := link.Kprobe("sys_getsid", objs.SysGetsidCallback, nil)
	defer sys_getsid_hook.Close()
	log.Println("sys_getsid kprobe attached!")

	sys_capget_hook, _ := link.Kprobe("sys_capget", objs.SysCapgetCallback, nil)
	defer sys_capget_hook.Close()
	log.Println("sys_capget kprobe attached!")

	sys_capset_hook, _ := link.Kprobe("sys_capset", objs.SysCapsetCallback, nil)
	defer sys_capset_hook.Close()
	log.Println("sys_capset kprobe attached!")

	sys_mknod_hook, _ := link.Kprobe("sys_mknod", objs.SysMknodCallback, nil)
	defer sys_mknod_hook.Close()
	log.Println("sys_mknod kprobe attached!")

	sys_uselib_hook, _ := link.Kprobe("sys_uselib", objs.SysUselibCallback, nil)
	defer sys_uselib_hook.Close()
	log.Println("sys_uselib kprobe attached!")

	sys_ustat_hook, _ := link.Kprobe("sys_ustat", objs.SysUstatCallback, nil)
	defer sys_ustat_hook.Close()
	log.Println("sys_ustat kprobe attached!")

	sys_statfs_hook, _ := link.Kprobe("sys_statfs", objs.SysStatfsCallback, nil)
	defer sys_statfs_hook.Close()
	log.Println("sys_statfs kprobe attached!")

	sys_fstatfs_hook, _ := link.Kprobe("sys_fstatfs", objs.SysFstatfsCallback, nil)
	defer sys_fstatfs_hook.Close()
	log.Println("sys_fstatfs kprobe attached!")

	sys_pivot_root_hook, _ := link.Kprobe("sys_pivot_root", objs.SysPivotRootCallback, nil)
	defer sys_pivot_root_hook.Close()
	log.Println("sys_pivot_root kprobe attached!")

	sys_chroot_hook, _ := link.Kprobe("sys_chroot", objs.SysChrootCallback, nil)
	defer sys_chroot_hook.Close()
	log.Println("sys_chroot kprobe attached!")

	sys_settimeofday_hook, _ := link.Kprobe("sys_settimeofday", objs.SysSettimeofdayCallback, nil)
	defer sys_settimeofday_hook.Close()
	log.Println("sys_settimeofday kprobe attached!")

	sys_swapon_hook, _ := link.Kprobe("sys_swapon", objs.SysSwaponCallback, nil)
	defer sys_swapon_hook.Close()
	log.Println("sys_swapon kprobe attached!")

	sys_swapoff_hook, _ := link.Kprobe("sys_swapoff", objs.SysSwapoffCallback, nil)
	defer sys_swapoff_hook.Close()
	log.Println("sys_swapoff kprobe attached!")

	sys_acct_hook, _ := link.Kprobe("sys_acct", objs.SysAcctCallback, nil)
	defer sys_acct_hook.Close()
	log.Println("sys_acct kprobe attached!")

	sys_quotactl_hook, _ := link.Kprobe("sys_quotactl", objs.SysQuotactlCallback, nil)
	defer sys_quotactl_hook.Close()
	log.Println("sys_quotactl kprobe attached!")

	sys_io_setup_hook, _ := link.Kprobe("sys_io_setup", objs.SysIoSetupCallback, nil)
	defer sys_io_setup_hook.Close()
	log.Println("sys_io_setup kprobe attached!")

	sys_remap_file_pages_hook, _ := link.Kprobe("sys_remap_file_pages", objs.SysRemapFilePagesCallback, nil)
	defer sys_remap_file_pages_hook.Close()
	log.Println("sys_remap_file_pages kprobe attached!")

	sys_clock_settime_hook, _ := link.Kprobe("sys_clock_settime", objs.SysClockSettimeCallback, nil)
	defer sys_clock_settime_hook.Close()
	log.Println("sys_clock_settime kprobe attached!")

	sys_inotify_add_watch_hook, _ := link.Kprobe("sys_inotify_add_watch", objs.SysInotifyAddWatchCallback, nil)
	defer sys_inotify_add_watch_hook.Close()
	log.Println("sys_inotify_add_watch kprobe attached!")

	sys_openat_hook, _ := link.Kprobe("sys_openat", objs.SysOpenatCallback, nil)
	defer sys_openat_hook.Close()
	log.Println("sys_openat kprobe attached!")

	sys_mkdirat_hook, _ := link.Kprobe("sys_mkdirat", objs.SysMkdiratCallback, nil)
	defer sys_mkdirat_hook.Close()
	log.Println("sys_mkdirat kprobe attached!")

	sys_fchownat_hook, _ := link.Kprobe("sys_fchownat", objs.SysFchownatCallback, nil)
	defer sys_fchownat_hook.Close()
	log.Println("sys_fchownat kprobe attached!")

	sys_renameat_hook, _ := link.Kprobe("sys_renameat", objs.SysRenameatCallback, nil)
	defer sys_renameat_hook.Close()
	log.Println("sys_renameat kprobe attached!")

	sys_linkat_hook, _ := link.Kprobe("sys_linkat", objs.SysLinkatCallback, nil)
	defer sys_linkat_hook.Close()
	log.Println("sys_linkat kprobe attached!")

	sys_symlinkat_hook, _ := link.Kprobe("sys_symlinkat", objs.SysSymlinkatCallback, nil)
	defer sys_symlinkat_hook.Close()
	log.Println("sys_symlinkat kprobe attached!")

	sys_fchmodat_hook, _ := link.Kprobe("sys_fchmodat", objs.SysFchmodatCallback, nil)
	defer sys_fchmodat_hook.Close()
	log.Println("sys_fchmodat kprobe attached!")

	sys_unshare_hook, _ := link.Kprobe("sys_unshare", objs.SysUnshareCallback, nil)
	defer sys_unshare_hook.Close()
	log.Println("sys_unshare kprobe attached!")

	sys_fallocate_hook, _ := link.Kprobe("sys_fallocate", objs.SysFallocateCallback, nil)
	defer sys_fallocate_hook.Close()
	log.Println("sys_fallocate kprobe attached!")

	sys_accept4_hook, _ := link.Kprobe("sys_accept4", objs.SysAccept4Callback, nil)
	defer sys_accept4_hook.Close()
	log.Println("sys_accept4 kprobe attached!")

	sys_preadv_hook, _ := link.Kprobe("sys_preadv", objs.SysPreadvCallback, nil)
	defer sys_preadv_hook.Close()
	log.Println("sys_preadv kprobe attached!")

	sys_pwritev_hook, _ := link.Kprobe("sys_pwritev", objs.SysPwritevCallback, nil)
	defer sys_pwritev_hook.Close()
	log.Println("sys_pwritev kprobe attached!")

	sys_recvmmsg_hook, _ := link.Kprobe("sys_recvmmsg", objs.SysRecvmmsgCallback, nil)
	defer sys_recvmmsg_hook.Close()
	log.Println("sys_recvmmsg kprobe attached!")

	sys_fanotify_mark_hook, _ := link.Kprobe("sys_fanotify_mark", objs.SysFanotifyMarkCallback, nil)
	defer sys_fanotify_mark_hook.Close()
	log.Println("sys_fanotify_mark kprobe attached!")

	sys_open_by_handle_at_hook, _ := link.Kprobe("sys_open_by_handle_at", objs.SysOpenByHandleAtCallback, nil)
	defer sys_open_by_handle_at_hook.Close()
	log.Println("sys_open_by_handle_at kprobe attached!")

	sys_sendmmsg_hook, _ := link.Kprobe("sys_sendmmsg", objs.SysSendmmsgCallback, nil)
	defer sys_sendmmsg_hook.Close()
	log.Println("sys_sendmmsg kprobe attached!")

	sys_setns_hook, _ := link.Kprobe("sys_setns", objs.SysSetnsCallback, nil)
	defer sys_setns_hook.Close()
	log.Println("sys_setns kprobe attached!")

	sys_renameat2_hook, _ := link.Kprobe("sys_renameat2", objs.SysRenameat2Callback, nil)
	defer sys_renameat2_hook.Close()
	log.Println("sys_renameat2 kprobe attached!")

	sys_execveat_hook, _ := link.Kprobe("sys_execveat", objs.SysExecveatCallback, nil)
	defer sys_execveat_hook.Close()
	log.Println("sys_execveat kprobe attached!")

	sys_copy_file_range_hook, _ := link.Kprobe("sys_copy_file_range", objs.SysCopyFileRangeCallback, nil)
	defer sys_copy_file_range_hook.Close()
	log.Println("sys_copy_file_range kprobe attached!")

	sys_preadv2_hook, _ := link.Kprobe("sys_preadv2", objs.SysPreadv2Callback, nil)
	defer sys_preadv2_hook.Close()
	log.Println("sys_preadv2 kprobe attached!")

	sys_pwritev2_hook, _ := link.Kprobe("sys_pwritev2", objs.SysPwritev2Callback, nil)
	defer sys_pwritev2_hook.Close()
	log.Println("sys_pwritev2 kprobe attached!")

	sys_pkey_mprotect_hook, _ := link.Kprobe("sys_pkey_mprotect", objs.SysPkeyMprotectCallback, nil)
	defer sys_pkey_mprotect_hook.Close()
	log.Println("sys_pkey_mprotect kprobe attached!")

	sys_io_uring_setup_hook, _ := link.Kprobe("sys_io_uring_setup", objs.SysIoUringSetupCallback, nil)
	defer sys_io_uring_setup_hook.Close()
	log.Println("sys_io_uring_setup kprobe attached!")

	sys_move_mount_hook, _ := link.Kprobe("sys_move_mount", objs.SysMoveMountCallback, nil)
	defer sys_move_mount_hook.Close()
	log.Println("sys_move_mount kprobe attached!")

	sys_fsconfig_hook, _ := link.Kprobe("sys_fsconfig", objs.SysFsconfigCallback, nil)
	defer sys_fsconfig_hook.Close()
	log.Println("sys_fsconfig kprobe attached!")

	sys_fsmount_hook, _ := link.Kprobe("sys_fsmount", objs.SysFsmountCallback, nil)
	defer sys_fsmount_hook.Close()
	log.Println("sys_fsmount kprobe attached!")

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
