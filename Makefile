libbpf:
	# git submodule add https://github.com/libbpf/libbpf/ libbpf
	cd src/libbpf/src; make clean; BUILD_STATIC_ONLY=y make install

xdp_drop:
	clang -S -target bpf -D __BPF_TRACING__ -Wall -Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types -Werror -O2 -emit-llvm -c -g -o build/xdp_drop_k.ll src/xdp_drop/xdp_drop_k.c
	llc -march=bpf -filetype=obj -o build/xdp_drop_k.o build/xdp_drop_k.ll
	gcc -Wall -o build/xdp_drop_u src/xdp_drop/xdp_drop_u.c -l:libbpf.a -lelf -lz

hello_rb:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/hello_rb/vmlinux.h
	clang -g -O2 -c -target bpf -o src/hello_rb/hello_rb.o src/hello_rb/hello_rb.c
	cd src/hello_rb;go mod tidy;CC=gcc CGO_CFLAGS="-I /usr/include/bpf" CGO_LDFLAGS="/usr/lib/x86_64-linux-gnu/libbpf.a" go build -o ../../build/hello_rb
	cp src/hello_rb/hello_rb.o build/

all: xdp_drop, hello_rb

clean:
	rm build/*; rm src/hello_rb/vmlinux.h; rm src/hello_rb/hello_rb.o