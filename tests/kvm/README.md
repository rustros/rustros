# 回归测试（KVM 测试机）

整套回归测试都在一台有 KVM 的测试机上跑：QEMU 只用 `-accel kvm`，不退回软件模拟。每次运行先由 `kvm_check.sh` 确认 KVM 确实生效，否则停止。

## 运行

在开发机上：

```sh
tools/kvm-test.sh root@<测试机>          # 或者先 export RUSTROS_KVM_HOST=root@<测试机>
```

它把当前工作区复制到测试机上同样的路径（测试机保留自己的 `build/`，里面有更新密钥），运行 `tests/kvm/run_all.sh`，打印汇总；有测试失败时返回非零。

直接在测试机上：`bash tests/kvm/run_all.sh`。工作目录（镜像、日志、结果）是 `$KVM_WORK`，默认 `/root/rustros-test`；结果在 `$KVM_WORK/groups/*/out`。

## 测试机需要的软件

`qemu-system-x86 ovmf python3 openssl iperf3 iproute2`，Rust 工具链（`~/.cargo/bin`），以及 `make` 用到的 `grub-pc-bin grub-efi-amd64-bin mtools dosfstools nasm`。转发分析的 Linux 参照还需要 `busybox-static nftables bpftool clang libbpf-dev`。

## 套件的组成

- **单独跑的计时测试：** 性能（`perf_test.py`）、用户态进程（`proc_test.py`，比较有死循环进程时和没有时的吞吐）、转发基准（`fwd_bench.py`：TCP 1 流和 4 流，64 字节 UDP 用 pktgen 测 1 流和 16 流）。
- **并行分组：** 其余测试分 7 组同时跑，每组在自己的目录副本里，端口整体错开 1000 的倍数。
- **测试证书：** `make_certs.sh` 每次运行时生成一次性的测试 CA 和网站证书，仓库里不存私钥。
- **测试地址：** 用文档专用地址段（198.51.100.0/24、203.0.113.0/24）和 QEMU 的用户网络（10.0.2.0/24）。

## 转发分析

`tests/kvm/fwd_analysis.sh [测量版内核的源码树]`：RustROS 和 Linux 内核转发、nftables、XDP 在同样的虚拟机配置下对比，每项单独跑 3 次。`fwd_bench.py` 的选项（`ROUTER`、`GEN`、`FLOWS`、`MQ`、`SPIN` 等）见它开头的说明。Linux 参照由 `linux-router/build.sh` 用测试机自己的内核做成。
