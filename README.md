clean-dns-tool
===

xdp/bpf approach to filter gfw DNS hijackers

## Building
```
cargo build
./target/debug/bpf-clean-dns -i eth0
```

## Perform
```
dig @9.9.9.9 www.google.com
```
