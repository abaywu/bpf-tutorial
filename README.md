# bpf-tutorial

這個專案主要匯集一些bpf的範例程式，可以幫助學習BPF的程式編寫。

目前收集的範例有：

* XDP DROP

## Build libbpf

下載libbpf程式碼
```
git submodule add https://github.com/libbpf/libbpf/ libbpf
```
也可以使用Makefile中的install_libbpf來完成

編譯libbpf, 此範例會將libbpf編譯到/build/root這個路徑，可以依據自行設定編譯到不同的位置
```
BUILD_STATIC_ONLY=y PKG_CONFIG_PATH=/build/root/lib64/pkgconfig DESTDIR=/build/root make install
```

## Build sample code

選擇你要編譯的範例
例如你要編譯xdp_drop這個範例：
```
make xdp_drop
```

成功編譯後會產生執行檔在build/這個資料夾中

## 參考來源

* https://github.com/xdp-project/xdp-tutorial

