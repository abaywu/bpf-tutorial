install_libbpf:
	git submodule add https://github.com/libbpf/libbpf/ libbpf

xdp_drop:
	clang -S -target bpf -D __BPF_TRACING__ -I/build/root/usr/include -Wall -Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types -Werror -O2 -emit-llvm -c -g -o build/xdp_drop_k.ll xdp_drop_k.c
	llc -march=bpf -filetype=obj -o build/xdp_drop_k.o build/xdp_drop_k.ll
	gcc -Wall -I/build/root/usr/include -g -L/build/root/usr/lib64 -o build/xdp_drop_u xdp_drop_u.c -l:libbpf.a -lelf -lz
	
clean:
	rm build/*