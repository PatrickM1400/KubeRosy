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

	sys_write_hook, err := link.Kprobe("sys_write", objs.TempWriteCallback, nil)
	defer sys_write_hook.Close()
	log.Println("sys_write kprobe attached!")

	lsm_task_alloc, err := link.AttachLSM(link.LSMOptions{Program: objs.TaskAlloc})
	defer lsm_task_alloc.Close()
	log.Println("lsm_task_alloc Attached!")

	lsm_bprm_check, err := link.AttachLSM(link.LSMOptions{Program: objs.BprmCheck})
	defer lsm_bprm_check.Close()
	log.Println("lsm_bprm_check Attached!")

	lsm_ptrace_check, err := link.AttachLSM(link.LSMOptions{Program: objs.PtraceCheck})
	defer lsm_ptrace_check.Close()
	log.Println("lsm_ptrace_check Attached!")

	lsm_path_chmod, err := link.AttachLSM(link.LSMOptions{Program: objs.PathChmod})
	defer lsm_path_chmod.Close()
	log.Println("lsm_path_chmod Attached!")

	lsm_file_mprotect, err := link.AttachLSM(link.LSMOptions{Program: objs.FileMprotect})
	defer lsm_file_mprotect.Close()
	log.Println("lsm_file_mprotect Attached!")

	lsm_fix_setgid, err := link.AttachLSM(link.LSMOptions{Program: objs.FixSetgid})
	defer lsm_fix_setgid.Close()
	log.Println("lsm_fix_setgid Attached!")

	lsm_fix_setuid, err := link.AttachLSM(link.LSMOptions{Program: objs.FixSetuid})
	defer lsm_fix_setuid.Close()
	log.Println("lsm_fix_setuid Attached!")

	lsm_socket_accept, err := link.AttachLSM(link.LSMOptions{Program: objs.SocketAccept})
	defer lsm_socket_accept.Close()
	log.Println("lsm_socket_accept Attached!")

	lsm_socket_bind, err := link.AttachLSM(link.LSMOptions{Program: objs.SocketBind})
	defer lsm_socket_bind.Close()
	log.Println("lsm_socket_bind Attached!")

	lsm_socket_connect, err := link.AttachLSM(link.LSMOptions{Program: objs.SocketConnect})
	defer lsm_socket_connect.Close()
	log.Println("lsm_socket_connect Attached!")

	lsm_socket_listen, err := link.AttachLSM(link.LSMOptions{Program: objs.SocketListen})
	defer lsm_socket_listen.Close()
	log.Println("lsm_socket_listen Attached!")

	lsm_socket_recvmsg, err := link.AttachLSM(link.LSMOptions{Program: objs.SocketRecvmsg})
	defer lsm_socket_recvmsg.Close()
	log.Println("lsm_socket_recvmsg Attached!")

	lsm_socket_create, err := link.AttachLSM(link.LSMOptions{Program: objs.SocketCreate})
	defer lsm_socket_create.Close()
	log.Println("lsm_socket_create Attached!")

	lsm_file_permission, err := link.AttachLSM(link.LSMOptions{Program: objs.FilePermission})
	defer lsm_file_permission.Close()
	log.Println("lsm_file_permission Attached!")

	lsm_socket_getpeername, err := link.AttachLSM(link.LSMOptions{Program: objs.SocketGetpeername})
	defer lsm_socket_getpeername.Close()
	log.Println("lsm_socket_getpeername Attached!")

	// lsm_socket_getsockname, err := link.AttachLSM(link.LSMOptions{Program: objs.SocketGetsockname})
	// defer lsm_socket_getsockname.Close()
	// log.Println("lsm_socket_getsockname Attached!")

	// lsm_socket_getsockopt, err := link.AttachLSM(link.LSMOptions{Program: objs.SocketGetsockopt})
	// defer lsm_socket_getsockopt.Close()
	// log.Println("lsm_socket_getsockopt Attached!")

	lsm_socket_sendmsg, err := link.AttachLSM(link.LSMOptions{Program: objs.SocketSendmsg})
	defer lsm_socket_sendmsg.Close()
	log.Println("lsm_socket_sendmsg Attached!")

	lsm_socket_setsockopt, err := link.AttachLSM(link.LSMOptions{Program: objs.SocketSetsockopt})
	defer lsm_socket_setsockopt.Close()
	log.Println("lsm_socket_setsockopt Attached!")

	lsm_socket_shutdown, err := link.AttachLSM(link.LSMOptions{Program: objs.SocketShutdown})
	defer lsm_socket_shutdown.Close()
	log.Println("lsm_socket_shutdown Attached!")

	lsm_capable, err := link.AttachLSM(link.LSMOptions{Program: objs.Capable})
	defer lsm_capable.Close()
	log.Println("lsm_capable Attached!")

	lsm_capget, err := link.AttachLSM(link.LSMOptions{Program: objs.Capget})
	defer lsm_capget.Close()
	log.Println("lsm_capget Attached!")

	lsm_capset, err := link.AttachLSM(link.LSMOptions{Program: objs.Capset})
	defer lsm_capset.Close()
	log.Println("lsm_capset Attached!")

	lsm_quotactl, err := link.AttachLSM(link.LSMOptions{Program: objs.Quotactl})
	defer lsm_quotactl.Close()
	log.Println("lsm_quotactl Attached!")

	lsm_syslog, err := link.AttachLSM(link.LSMOptions{Program: objs.Syslog})
	defer lsm_syslog.Close()
	log.Println("lsm_syslog Attached!")

	lsm_settime, err := link.AttachLSM(link.LSMOptions{Program: objs.Settime})
	defer lsm_settime.Close()
	log.Println("lsm_settime Attached!")

	lsm_sb_free_mnt_opts, err := link.AttachLSM(link.LSMOptions{Program: objs.SbFreeMntOpts})
	defer lsm_sb_free_mnt_opts.Close()
	log.Println("lsm_sb_free_mnt_opts Attached!")

	lsm_sb_statfs, err := link.AttachLSM(link.LSMOptions{Program: objs.SbStatfs})
	defer lsm_sb_statfs.Close()
	log.Println("lsm_sb_statfs Attached!")

	lsm_sb_pivotroot, err := link.AttachLSM(link.LSMOptions{Program: objs.SbPivotroot})
	defer lsm_sb_pivotroot.Close()
	log.Println("lsm_sb_pivotroot Attached!")

	lsm_move_mount, err := link.AttachLSM(link.LSMOptions{Program: objs.MoveMount})
	defer lsm_move_mount.Close()
	log.Println("lsm_move_mount Attached!")

	lsm_path_notify, err := link.AttachLSM(link.LSMOptions{Program: objs.PathNotify})
	defer lsm_path_notify.Close()
	log.Println("lsm_path_notify Attached!")

	lsm_path_mkdir, err := link.AttachLSM(link.LSMOptions{Program: objs.PathMkdir})
	defer lsm_path_mkdir.Close()
	log.Println("lsm_path_mkdir Attached!")

	lsm_path_rmdir, err := link.AttachLSM(link.LSMOptions{Program: objs.PathRmdir})
	defer lsm_path_rmdir.Close()
	log.Println("lsm_path_rmdir Attached!")

	lsm_path_unlink, err := link.AttachLSM(link.LSMOptions{Program: objs.PathUnlink})
	defer lsm_path_unlink.Close()
	log.Println("lsm_path_unlink Attached!")

	lsm_path_symlink, err := link.AttachLSM(link.LSMOptions{Program: objs.PathSymlink})
	defer lsm_path_symlink.Close()
	log.Println("lsm_path_symlink Attached!")

	lsm_path_link, err := link.AttachLSM(link.LSMOptions{Program: objs.PathLink})
	defer lsm_path_link.Close()
	log.Println("lsm_path_link Attached!")

	lsm_path_rename, err := link.AttachLSM(link.LSMOptions{Program: objs.PathRename})
	defer lsm_path_rename.Close()
	log.Println("lsm_path_rename Attached!")

	lsm_path_truncate, err := link.AttachLSM(link.LSMOptions{Program: objs.PathTruncate})
	defer lsm_path_truncate.Close()
	log.Println("lsm_path_truncate Attached!")

	// lsm_path_chown, err := link.AttachLSM(link.LSMOptions{Program: objs.PathChown})
	// defer lsm_path_chown.Close()
	// log.Println("lsm_path_chown Attached!")

	lsm_path_chroot, err := link.AttachLSM(link.LSMOptions{Program: objs.PathChroot})
	defer lsm_path_chroot.Close()
	log.Println("lsm_path_chroot Attached!")

	lsm_mmap_file, err := link.AttachLSM(link.LSMOptions{Program: objs.MmapFile})
	defer lsm_mmap_file.Close()
	log.Println("lsm_mmap_file Attached!")

	lsm_mmap_addr, err := link.AttachLSM(link.LSMOptions{Program: objs.MmapAddr})
	defer lsm_mmap_addr.Close()
	log.Println("lsm_mmap_addr Attached!")

	lsm_file_fcntl, err := link.AttachLSM(link.LSMOptions{Program: objs.FileFcntl})
	defer lsm_file_fcntl.Close()
	log.Println("lsm_file_fcntl Attached!")

	lsm_task_setpgid, err := link.AttachLSM(link.LSMOptions{Program: objs.TaskSetpgid})
	defer lsm_task_setpgid.Close()
	log.Println("lsm_task_setpgid Attached!")

	lsm_task_getpgid, err := link.AttachLSM(link.LSMOptions{Program: objs.TaskGetpgid})
	defer lsm_task_getpgid.Close()
	log.Println("lsm_task_getpgid Attached!")

	lsm_task_getsid, err := link.AttachLSM(link.LSMOptions{Program: objs.TaskGetsid})
	defer lsm_task_getsid.Close()
	log.Println("lsm_task_getsid Attached!")

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
