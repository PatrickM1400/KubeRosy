# Set arguments accordingly
CLANG ?= clang-14
STRIP ?= llvm-strip-14
OBJCOPY ?= llvm-objcopy-14
#CFLAGS := -O2 -g -Wall -Werror $(CFLAGS)
CFLAGS := -O2 -g $(CFLAGS)

# This will generate bpf_bpfeb and bpf_bpfel .o and .go automatically using bpf2go.
# Also generate monitoring.o for object file for main.go to use in the future.
generate: export BPF_CLANG := $(CLANG)
generate: export BPF_CFLAGS := $(CFLAGS)
generate:
	go generate ./...
	clang -O2 -target bpf -D__TARGET_ARCH_X86 -c monitoring.c -o monitoring.o -g

# This will clean up everything generated automatically.
clean:
	rm -f *.o
	rm -f bpf_bpfeb.go
	rm -f bpf_bpfel.go
	rm -f lsm_bpf_example_1

# This will autogenerate files and then will build.
build:
	make generate
	go build
