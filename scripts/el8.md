```
dnf install bpftool
dnf install make gcc gcc-c++
dnf install libbpf
dnf install llvm
dnf install clang
dnf install libstdc++-devel.x86_64
dnf install libgcc.x86_64
dnf install elfutils-libelf.x86_64
dnf install zlib-devel
dnf install make gcc gcc-c++
dnf install libelf.pc
dnf install elfutils-libelf-devel
dnf install make gcc gcc-c++
dnf install compiler-rt clang llvm-devel
dnf install ncurses-devel ncurses-c++-libs.x86_64
rustup toolchain install 1.59
dnf install kernel-header kernel-devel
dnf install kernel-headers kernel-devel
dnf install kernel
dnf --enablerepo=powertools install libbpf-devel
```


```
# pwd
/root/redbpf/redbpf-probes/include
cp /usr/include/bpf/bpf_helper_defs.h ./
cp /usr/include/bpf/bpf_helpers.h ./
```
