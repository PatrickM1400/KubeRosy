# KubeRosy

## About

![image-20250117180109050](./README.assets/image-20250117180109050.png)

KubeRosy is a container-specific system call security tool that uses eBPF and LSM Hooks to provide argument value-based filtering for system calls executed by containers. 

When you deploy a KubeRosy policy, it detects and enforces system call security policies against containers that match the policy's selectors and enforces the policy at the kernel level.

The following is an example of a KubeRosyPolicy that Block `socket` system calls from containers with `name = nginx`:

```yaml
apiVersion: security.kuberosy.com/v1
kind: KubeRosyPolicy
metadata:
    name: nginx
spec:
    selector:
        matchLabels:
            name: nginx
    action: Block
    syscall:
        - name: socket
```

