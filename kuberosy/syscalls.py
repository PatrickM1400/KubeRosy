

with open("syscalls2.txt", "r") as file:
    with open("syscallFunc.txt", "w") as file2:
        lines = file.readlines()
        for line in lines:
            # print(line[2:-3])
            syscall = line[10:-1]

            func = 'SEC("tracepoint/syscalls/sys_enter_{}")\n'\
            "int sys_{}_callback(struct trace_event_raw_sys_enter* ctx)\n"\
            "{{\n"\
                "\tu32 pid = bpf_get_current_pid_tgid() >> 32;\n"\
                "\tu8 comm[16] = {{0}};\n"\
                "\tbpf_get_current_comm(comm, 16);\n"\
                "\tstruct task_struct *task = (struct task_struct*)bpf_get_current_task();\n"\
                "\tif(!task)\n"\
                    "\t\treturn 0;\n"\
                "\tstruct pid_mount_ns ns;\n"\
                "\tu32 pidns = getPidInum(task);\n"\
                "\tu32 mntns = getMntInum(task);\n"\
                "\tns.pidns = pidns;\n"\
                "\tns.mountns = mntns;\n"\
                "\tu32 *is_container_process = bpf_map_lookup_elem(&monitoring_map, &ns);\n"\
                "\tif(!is_container_process)\n"\
                    "\t\treturn 0;\n"\
                "\t//if(!ctx) {{\n"\
                    '\t\t//bpf_printk("ctx is null");\n'\
                    "\t\t//return 0;}}\n"\
                '\t//u64 id = ctx->id;\n'\
                '\t//bpf_printk("{} syscall triggered for syscall num %u", id);\n'\
                '\t//set_syscall_map(id);\n'\
                "\treturn 0;\n"\
            "}}\n\n".format(syscall,syscall,syscall)

            # s2 = syscall.split('_')
            # res = s2[0].capitalize() + ''.join(word.capitalize() for word in s2[1:])

            # func = 	'sys_{}_hook, _ := link.Tracepoint("syscalls" ,"sys_enter_{}", objs.Sys{}Callback, nil)\n'\
            # 'defer sys_{}_hook.Close()\n'\
            # 'log.Println("sys_{} kprobe attached!")\n\n'.format(syscall, syscall, res, syscall, syscall)

            file2.write(func)
