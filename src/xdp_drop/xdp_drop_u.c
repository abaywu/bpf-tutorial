#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <net/if.h>
#include <linux/if_link.h>

#define EXIT_OK 0	
#define EXIT_FAIL 1
#define EXIT_FAIL_XDP 30
#define EXIT_FAIL_BPF 40

struct config
{
	__u32 xdp_flags;
	int ifindex;
	char *ifname;
	char filename[512];
};

int load_bpf_object_file__simple(const char *filename)
{
	int first_prog_fd = -1;
	struct bpf_object *obj;
	int err;

	/* 使用libbpf從BPF-ELF物件檔中取得BPF byte-code，然後載入到kernel透過bpf-syscall */
	err = bpf_prog_load(filename, BPF_PROG_TYPE_XDP, &obj, &first_prog_fd);
	if (err)
	{
		fprintf(stderr, "ERR: loading BPF-OBJ file(%s) (%d): %s\n",
				filename, err, strerror(-err));
		return -1;
	}
	return first_prog_fd;
}

int xdp_link_attach(int ifindex, __u32 xdp_flags, int prog_fd)
{
	int err;

	/* 使用libbpf提供的XDP net_device link-level hook helper來hook到NIC driver */
	err = bpf_set_link_xdp_fd(ifindex, prog_fd, xdp_flags);
	if (err == -EEXIST && !(xdp_flags & XDP_FLAGS_UPDATE_IF_NOEXIST))
	{
		__u32 old_flags = xdp_flags;
		err = bpf_set_link_xdp_fd(ifindex, -1, xdp_flags);
		if (!err)
			err = bpf_set_link_xdp_fd(ifindex, prog_fd, old_flags);
	}

	if (err < 0)
	{
		fprintf(stderr, "ERR: "
						"ifindex(%d) link set xdp fd failed (%d): %s\n",
				ifindex, -err, strerror(-err));

		switch (-err)
		{
		case EBUSY:
		case EEXIST:
			fprintf(stderr, "Hint: XDP already loaded on device"
							" use --force to swap/replace\n");
			break;
		case EOPNOTSUPP:
			fprintf(stderr, "Hint: Native-XDP not supported"
							" use --skb-mode or --auto-mode\n");
			break;
		default:
			break;
		}
		return EXIT_FAIL_XDP;
	}

	return EXIT_OK;
}

int main()
{
	char filename[256] = "xdp_drop_k.o";
	int prog_fd, err;

	struct config cfg = {
		.xdp_flags = XDP_FLAGS_DRV_MODE, // 另一種 XDP_FLAGS_SKB_MODE
		.ifindex = -1,
		.ifname = "eth0",
	};

	cfg.ifindex = if_nametoindex(cfg.ifname);
	fprintf(stdout, "Success: Getting if index: %d\n", cfg.ifindex);

	/* 載入 BPF-ELF object 檔並取得第一個 BPF_prog FD */
	prog_fd = load_bpf_object_file__simple(filename);
	if (prog_fd <= 0)
	{
		fprintf(stderr, "ERR: loading file: %s\n", filename);
		return EXIT_FAIL_BPF;
	}
	
	err = xdp_link_attach(cfg.ifindex, cfg.xdp_flags, prog_fd);
	if (err)
		return err;

	printf("Success: Loading "
		   "XDP program on device:%s(ifindex:%d)\n",
		   cfg.ifname, cfg.ifindex);
	return EXIT_OK;
}
