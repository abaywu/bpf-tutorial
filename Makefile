libbpf:
	# git submodule add https://github.com/libbpf/libbpf/ libbpf
	cd src/libbpf/src; make clean; BUILD_STATIC_ONLY=y make install

xdp_drop:
	clang -S -target bpf -D __BPF_TRACING__ -Wall -Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types -Werror -O2 -emit-llvm -c -g -o build/xdp_drop_k.ll src/xdp_drop/xdp_drop_k.c
	llc -march=bpf -filetype=obj -o build/xdp_drop_k.o build/xdp_drop_k.ll
	gcc -Wall -o build/xdp_drop_u src/xdp_drop/xdp_drop_u.c -l:libbpf.a -lelf -lz

all: xdp_drop

clean:
	rm build/*