with open('init_profile.txt') as file:
    line = file.readline()
    blocked_syscalls = line.split(",")
    blocked_syscalls = set([int(num) for num in blocked_syscalls])
    print(blocked_syscalls)
    allowed_syscalls = []
    for i in range(336):
        if i not in blocked_syscalls:
            allowed_syscalls.append(i)
    print(allowed_syscalls)