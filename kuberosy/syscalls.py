

with open("syscalls.txt", "r") as file:
    with open("syscallFunc.txt", "w") as file2:
        lines = file.readlines()
        for line in lines:
            # print(line[2:-3])
            syscall = line[2:-3]

            # func = 'SEC("kprobe/sys_{}_entry")\n'\
            # "int BPF_KPROBE(sys_{}_callback)\n"\
            # "{{\n"\
            #     "\tu32 pid = bpf_get_current_pid_tgid() >> 32;\n"\
            #     "\tu8 comm[16] = {{0}};\n"\
            #     "\tbpf_get_current_comm(comm, 16);\n"\
            #     "\tstruct task_struct *task = (struct task_struct*)bpf_get_current_task();\n"\
            #     "\tif(!task)\n"\
            #         "\t\treturn 0;\n"\
            #     "\tstruct pid_mount_ns ns;\n"\
            #     "\tu32 pidns = getPidInum(task);\n"\
            #     "\tu32 mntns = getMntInum(task);\n"\
            #     "\tns.pidns = pidns;\n"\
            #     "\tns.mountns = mntns;\n"\
            #     "\tu32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);\n"\
            #     "\tif(!is_container_process)\n"\
            #         "\t\treturn 0;\n"\
            #     '\tbpf_printk("{} syscall triggered for pidns %u", pidns);\n'\
            #     "\treturn 0;\n"\
            # "}}\n\n".format(syscall,syscall,syscall)

            func = 	'sys_{}_hook, err := link.Kprobe("sys_{}", objs.Sys{}Callback, nil)\n'\
            'defer sys_{}_hook.Close()\n'\
            'log.Println("sys_{} kprobe attached!")\n\n'.format(syscall, syscall, syscall.capitalize(), syscall, syscall)

            file2.write(func)
