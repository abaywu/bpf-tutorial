# bpf-tutorial

這個專案主要整理BPF範例程式，組織編排後收集放在這邊，希望可以提供點幫助也正在學習BPF的程式編寫的朋友。

目前收集的範例有：

* [C] XDP DROP, 使用XDP_DROP來展示XDP的功能
* [Golang] Hello_rb, 使用bpf ringbuffer將資料由kernel送資料到userspace程式，取得process id與hello字串。

## 1. 測試環境準備

### Kernel

本專案目前只在Ubuntu平台上進行開發與測試。建議測試版本可以使用Ubuntu 21.04。如果使用其他版本的Linux記得使用BTF支援的kenel。確定你的Linux kernel編譯選項CONFIG_DEBUG_INFO_BTF=y kconfig有選定。詳細的Linux版本可以參考[libbpf README](https://github.com/libbpf/libbpf#bpf-co-re-compile-once--run-everywhere)。

### libbpf

**由libbpf原始程式碼編譯**

```bash=
git clone https://github.com/libbpf/libbpf/ libbpf
```

編譯libbpf, 例如將libbpf編譯到/build/root這個路徑，可以依據自行設定編譯到不同的位置

```
BUILD_STATIC_ONLY=y PKG_CONFIG_PATH=/build/root/lib64/pkgconfig DESTDIR=/build/root make install
```

可以使用本專案的Makefile
```
make libbpf
```

**由Ubuntu套件libbpf-dev**

```bash=
# apt-get install libbpf-dev
```

### bpftool

```bash=
# apt install linux-tools-common linux-tools-generic
```

## 2. Build sample code

### Dependencies

```bash=
# apt-get install libbpf-dev make clang llvm libelf-dev gcc-multilib
```

選擇你要編譯的範例
例如你要編譯xdp_drop這個範例：
```
make xdp_drop
```

成功編譯後會產生執行檔在build/這個資料夾中

## 參考來源

* https://github.com/xdp-project/xdp-tutorial

