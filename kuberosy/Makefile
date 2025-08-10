# Set arguments accordingly
CLANG ?= clang-14
STRIP ?= llvm-strip-14
OBJCOPY ?= llvm-objcopy-14
#CFLAGS := -O2 -g -Wall -Werror $(CFLAGS)
CFLAGS := -O2 -g $(CFLAGS) -I/usr/include/x86_64-linux-gnu
# This will generate bpf_bpfel_x86 .o and .go automatically using bpf2go.
# Also generate monitoring.o for object file for main.go to use in the future.
generate: export BPF_CLANG := $(CLANG)
generate: export BPF_CFLAGS := $(CFLAGS)
generate:
	go generate ./...
	clang -target bpf -D__TARGET_ARCH_x86 -O2 -g -c monitoring.c -o monitoring.o

# This will clean up everything generated automatically.
clean:
	rm -f *.o
	rm -f bpf_bpfeb.go
	rm -f bpf_bpfel.go
	rm -f lsm_bpf_example_1
	rm -f bpf_bpfel_x86.go
	rm -f core

# This will autogenerate files and then will build.
build:
	make generate
	go build
