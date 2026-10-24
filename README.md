# RustROS

一个"空壳"式的 Rust unikernel：系统只提供启动、驱动、一个主机协议栈（ARP/IPv4/ICMP/UDP/TCP）和 socket 接口，**路由、NAT、防火墙、DHCP 这类网络功能都交给应用**。多个应用和内核编译进同一个镜像，都在 ring 0 运行，按端口共享协议栈，隔离靠 Rust 的内存安全保证。

- 一张 raw 盘同时支持 **BIOS 和 UEFI** 启动（GRUB 2 + multiboot2）
- 面向 KVM/VPS：**virtio-net**、**virtio-blk**，modern（1.0）和 legacy 设备都支持
- **在线更新**：通过网络上传新内核写入备用槽，试启动一次，确认后才切换；不确认就自动回滚
- **内核保持在 256 KiB 以内**：内核只做内存、中断、包转发路径和模块加载；设备驱动（virtio-blk、virtio-net）、协议栈、存储服务（分区、kvstore、A/B 槽、开机日志）、模块管理（安装、选择运行形式、开机顺序）、rescue、dhcp、updater 是随内核一起放在槽里的引导模块，其中的服务都能在运行中换成安装的新版本（见“服务的热替换”）；文件系统驱动（ext4）、应用、WebAssembly 运行时都是可以在线安装和更新的模块
- unsafe 只出现在 `kernel/`（以及 `wasmhost` 的一处）；其余 crate 和应用都是 `#![forbid(unsafe_code)]`

## 目录结构

```
kernel/        HAL（启动、CPU、内存、控制台、PCI、看门狗）+ 组装和调度、模块加载、服务替换（services.rs）、用户态进程（proc.rs/vm.rs/frames.rs：ring 3、每进程地址空间、按需分页、写时复制）   ← 唯一含 unsafe 的地方
api/           rustros-api：应用接口 App/Sys、类型、错误码、WebAssembly ABI（无依赖）
util/          rustros-util：给应用用的工具：Conn、地址和报文工具、SHA-256/HMAC
devices/       设备接口：BlockDevice、NetDevice
netstack/      协议栈：以太网/ARP/IPv4/ICMP/UDP/TCP + 多应用 socket 分发；网络配置：生效、候选、apply/确认/超时回滚，读取与保存（命令行/grubenv，util::netconf）；交给下一个版本的状态（handover.rs）。引导模块里是不带状态交接的引导版，完整的在 netstack 模块里
tcpip/         协议栈里每个包都要经过的部分：IPv4 接口（以太网、ARP、IP、ICMP、路由）和 TCP，按 -O3 编译，netstack 的其余部分按 -Os；引导模块里的引导版全部按 -Os，让启动镜像放得进 256 KiB 的槽
kvstore/       键值存储引擎（断电安全）
storage/       存储服务（在引导模块里，可替换）：GPT 分区、kvstore、A/B 槽与 grubenv、开机日志、files 分区
modman/        模块管理（在引导模块里，可替换）：已装模块的存放（sys/app/<名>/）、安装/删除/切换、选择原生或 WebAssembly 形式、模块的角色（服务、文件系统驱动）和开机顺序、崩溃后关掉原生形式、镜像自带模块；内核只负责加载和运行
virtio/        virtio-pci 传输层、PCI 配置空间、virtio-blk 和 virtio-net 驱动（在引导模块里，可替换：设备复位后由新驱动接管）
slots/         A/B 内核槽位 + grubenv（在线更新、试启动、回滚）
wasmhost/      WebAssembly 运行时（wasmi），可选：`make WASM=0` 不带它
apps/          原生应用：shell、echo、httpd、updater
user/          用户态测试程序（单独的 workspace）：无 libc 的静态 ELF，发 Linux x86-64 系统调用（hello、badptr、spin、forktest）
wasm/          WebAssembly 应用（单独的 workspace）：guest 库 + 示例 echo、crashy
modules 里另有：linux（用户态进程的 Linux 系统调用），netstack/storage/modman/virtio（替换启动镜像里的同类服务）
tools/         mkimg.py 生成 raw 盘；pack.py 把内核打成自解压 ELF（LZ4）以放进 256 KiB 槽位；rustros-update.py 在线更新/管理客户端
```

依赖方向是单向的：

```
应用 ──► api + util
kernel ──► api / util / devices / virtio::pci
引导模块 ──► virtio, storage, netstack（引导版）, modman, rescue, dhcp, updater ──► api / util / devices
服务模块 ──► netstack、storage、modman、virtio（各自单独一个模块，替换启动镜像里的同类服务）
```

除了 `kernel`，所有 crate 都是 `#![forbid(unsafe_code)]`，`wasmhost` 例外，它有一处 unsafe，用来在一次 guest 调用期间把 `Sys` 借给 host 函数。不碰硬件的服务（kvstore、slots、storage）都可以在宿主机上做单元测试：

```sh
for c in kvstore slots storage; do cargo test -p $c --target x86_64-unknown-linux-gnu; done
```

## 构建与运行

依赖：Rust 稳定版加 `x86_64-unknown-none` target，以及 `grub-pc-bin grub-efi-amd64-bin mtools dosfstools python3`，测试还需要 `qemu-system-x86 ovmf`。

```sh
rustup target add x86_64-unknown-none
make IP=192.168.1.10/24 GW=192.168.1.1      # 生成 build/rustros.img（65 MiB）
make run-bios                                # 或 make run-uefi，串口即控制台
```

`build/rustros.img` 就是成品 raw 盘，可以直接 `dd` 到磁盘，或上传到 VPS。首次构建会生成随机更新密钥，保存在 `build/update.key`。

改 IP 不需要重新构建：直接编辑 ESP 分区里的 `/boot/grub/grub.cfg`，修改 `ip=` 和 `gw=`。

## 部署到 VPS

VPS 需要支持上传自定义 raw 镜像，使用 virtio 网卡和磁盘（KVM 类主机基本都是），内存至少 256 MiB（内核堆 96 MiB）。RustROS 不支持 DHCP，地址可以在控制台里设置后保存：

```sh
make -B APPS="shell updater" IP= GW= KEY_FILE=build/online.key   # 不带 IP 的线上镜像
dd if=build/rustros.img bs=4M | ssh root@<救援系统> "dd of=/dev/vda bs=4M conv=fsync"
```

启动后在 VPS 控制台输入：

```
ip 203.0.113.10/24 203.0.113.1
mtu 1450        # 可选，按实际网络填
save            # 写入 grubenv，以后重启和在线更新都会保留
```

之后的更新：`make update APPS="shell updater" HOST=203.0.113.10 KEY_FILE=build/online.key`。也可以在构建时直接用 `IP=`/`GW=`/`MTU=` 写入默认值；只要用 `save` 保存过，就以保存的为准。

- **不要把 echo 放到公网**：UDP echo 会被人伪造源地址，当成反射攻击的跳板。
- **网关不在子网内也能用**：比如 `/32` 地址配一个链路外的网关，RustROS 照样会对网关发 ARP。
- **注意 MTU**：云平台的 MTU 经常小于 1500（常见 1450），要按实际填写，否则 TCP 大包会被丢弃，在线更新也会失败。
- **磁盘大小**：镜像只有 65 MiB，VPS 磁盘比它大没关系，多出来的空间不会被使用。

## 数据分区与存储

首次启动时，RustROS 会把 ESP 之后的剩余空间建成 MBR 分区 2（类型 0xDA），在上面运行 `kvstore`：

- **只追加写日志：** 每条记录从扇区边界开始，带 CRC32 校验和随机 salt。断电最多丢掉正在写的那一条。
- **两半交替整理：** 一半写满后，把有效数据整理到另一半，最后写新头部，这一步就是提交点。
- **内存索引：** 启动时把全部有效数据读进内存，所以存储引擎最多只用分区开头的 256 MiB，有效数据上限 16 MiB。
- **在线更新不碰数据分区：** 更新只写 ESP 里的内核槽。
- **重新 dd 镜像也不会丢数据：** 镜像只覆盖开头 65 MiB，RustROS 会在同一位置重新登记分区，前提是 ESP 大小不变。
- **单元测试：** `cargo test -p kvstore --target x86_64-unknown-linux-gnu`，包括 3000 轮随机断电（写入撕裂）测试。

## WebAssembly 应用

应用有两种运行方式，**用的是同一份代码**（都实现 `rustros_api::App`）：

| | 原生（编进内核） | WebAssembly（运行时安装） |
|---|---|---|
| 性能 | 最快 | 解释执行（wasmi），慢一个数量级 |
| 更新 | 在线更新内核，需要重启 | `module-install` 立即替换，不用重启，其他应用不受影响 |
| 故障隔离 | panic 会导致整机重启 | 只停这一个实例，释放它的 socket，退避后重启（1、2、4…60 秒） |
| 死循环 | 软件看门狗重启整机 | 每次调用限 5000 万指令（fuel），超出就停掉实例 |
| 内存 | 共用内核堆 | 每个实例上限 16 MiB |
| 权限 | 全部 | 不能重启、改网络、做内核更新、管理模块 |

把一个应用打包成模块，只需要一行：

```rust
// wasm/apps/echo/src/lib.rs —— 和内置 echo 完全相同的代码
rustros_guest::export_app!(echo::Echo::new());
```

```sh
make wasm                                                   # 生成 build/wasm/*.wasm
tools/rustros-update.py HOST module-install echo build/wasm/echo_wasm.wasm
tools/rustros-update.py HOST module-remove echo
tools/rustros-update.py HOST info                            # 包括各模块的状态和重启次数
```

- **模块存储：** 模块保存在数据分区（kvstore 的 `sys/wasm/` 下，应用访问不到），开机自动启动，单个模块最大 1 MiB。
- **控制台：** shell 的 `wasm` 命令可以列出模块，`wasm rm <名字>` 可以删除。
- **隔离：** 每个模块和原生应用一样有自己的 socket 归属和 kv 命名空间，崩溃重启后数据仍在。
- **ABI：** 定义在 `rustros_api::abi`，guest 侧实现在 `wasm/guest`。
- **稳定后转原生：** 把同一个 crate 加进 `kernel/Cargo.toml` 的 feature 和 `make_apps()`，就变成原生应用。

## 崩溃与看门狗

原生应用没有进程隔离（WebAssembly 应用见上一节）：它们和内核都在 ring 0、同一地址空间里运行，应用之间不会写坏彼此的内存（safe Rust 保证），但 panic 或卡死会影响整机。因此目标是**任何故障都在几秒到一分钟内自动恢复**：

- **panic / CPU 异常：** 打印原因，写入 grubenv 的 `last_panic`（附运行时长），2 秒后重启。下次启动时会打印出来；shell 的 `crash` 命令和远程 `rustros-update.py HOST info` 都能看到。如果是试启动的新内核崩溃，重启后会自动回到旧槽位。
- **软件看门狗（30 秒）：** 时钟中断负责检查主循环的心跳，应用死循环会触发重启。
- **硬件看门狗（60 秒）：** 如果有 i6300esb 设备（KVM/Proxmox 可加 `-device i6300esb`），连内核关中断卡死也能重启。没有这个设备就只靠软件看门狗。
- **测试命令（shell）：** `crash panic`、`crash hang`、`crash freeze`，分别用来测试上面三种情况。

## 在线更新

```sh
make update HOST=192.168.1.10               # 编译、上传、等新内核起来、确认
# 或者分步执行：
tools/rustros-update.py HOST upload build/rustros.elf   # make 生成的打包内核
tools/rustros-update.py HOST confirm
tools/rustros-update.py HOST status
tools/rustros-update.py HOST info     # 运行时长、槽位、地址、存储、上次崩溃原因（需要密钥）
```

流程如下：

1. ESP 里有两个预分配、物理连续的槽位 `/boot/kernel-a.elf` 和 `/boot/kernel-b.elf`（镜像默认 2 MiB，每个槽 256 KiB；内核连同引导模块正好 256 KiB）。内核从启动参数得知它们的扇区号，更新时直接写扇区，不改动 FAT。
2. 上传前先校验头部的 HMAC-SHA256（服务端每次连接下发随机 nonce，防止重放），通过后才写盘。整个镜像的 HMAC 校验通过后，才在 `grubenv` 里写 `try_slot`。
3. GRUB 只会用 `try_slot` 启动一次，并且会先把它清掉。新内核必须在 5 分钟内确认（`confirm`），否则自动重启。如果新内核起不来，断电重启也会回到 `boot_slot`；加载失败时，GRUB 会走 fallback 菜单项。
4. 试启动期间拒绝再次上传，避免覆盖用来回滚的旧内核。

**无损扩容。** 槽不够大时，`rustros-update.py HOST esp-grow 8 1024` 把 ESP 在线扩到 8 MiB、槽扩到 1 MiB，数据分区不动：先在 ESP 后面的空闲启动区（64 MiB 以内）写好一份更大的新 ESP（GRUB、grub.cfg、grubenv、两个槽里的内核原样拷过去，只改 grub.cfg 里的扇区号），读回校验，再只改 GPT 里 ESP 那一项的位置，然后重启。切换之前断电，用的还是旧 ESP；切换之后断电，用的是已经校验过的新 ESP。分区编号和 GUID 不变，BIOS 和 UEFI 都照常找到它。

## 用户态进程（ring 3）

容器里的 Linux 程序需要真正的进程：ring 3、每个进程独立的地址空间、Linux 系统调用。这些机制在内核里（`proc.rs`、`vm.rs`、`frames.rs`），系统调用的具体实现在可热替换的 `linux` 模块里。

- **数据面优先：** 进程只在主循环本来要睡觉时才运行；任何中断（网卡、1ms 时钟）立刻把 CPU 交还给主循环。一个进程死循环也不会拖慢转发或控制台。
- **地址空间：** 内核的映射（恒等映射、设备：PML4 前 128 项）在所有进程里相同；用户区（64 TiB 以上）每个进程各自用 4 KiB 页。内存按需清零分配，`fork` 时写时复制。
- **系统调用：** 内核只接 `syscall`、保存寄存器、把编号和参数交给 `linux` 模块（号和 errno 都按 Linux x86-64）。进程状态在内核，所以模块能在进程运行中替换。
- **故障隔离：** 进程访问了不该碰的内存只杀它自己，整机不受影响。崩溃的进程不影响内核。
- **管理：** `rustros-update.py HOST run <程序> [参数...]` 启动一个进程，`ps` 列出，`kill <pid>` 结束。
- **现在有的系统调用：** 控制台输出（fd 1/2）、`mmap`（匿名）/`munmap`/`brk`、`fork`/`wait4`/`exit`、`arch_prctl`、`uname`、`clock_gettime`、若干查询；其余返回 `ENOSYS`。文件、信号、线程等随 M2/M3 补齐。
- **测试：** `proc_test.py`（BIOS 和 UEFI）：ring 3 跑程序、fork/wait/写时复制、坏指针只杀进程、死循环下转发照常、运行中替换 `linux` 模块。测试程序在 `user/`，`make user` 编译。

## 服务的热替换

启动镜像里的服务（驱动、存储、协议栈、模块管理）都可以在运行中换成新版本，不用重启。做法和安装应用一样：用 `module-install` 装一个导出同类服务的模块。

```sh
make modules
tools/rustros-update.py HOST module-install netstack build/modules/netstack.mod   # 协议栈
tools/rustros-update.py HOST module-install storage  build/modules/storage.mod    # 存储服务
tools/rustros-update.py HOST module-install modman   build/modules/modman.mod     # 模块管理
tools/rustros-update.py HOST module-install virtio   build/modules/virtio.mod     # virtio-blk、virtio-net 驱动
tools/rustros-update.py HOST module-remove storage                                # 换回启动镜像里的版本
```

替换在两轮主循环之间进行，这时没有正在进行的调用：

1. 加载新版本，检查接口指纹（`API_FINGERPRINT`）。
2. 旧版本把状态写成两个版本都认识的格式，新版本接过去。每个版本声明自己能读的最新格式，并且能读所有更旧的格式。
3. 调用方切到新版本，旧版本和它的代码随后卸载。
4. 任何一步失败，旧版本照常运行，状态不丢。

各服务交接的内容：

| 服务 | 交接什么 | 说明 |
|---|---|---|
| 协议栈 | 全部状态：配置、ARP 缓存、socket、TCP 连接（序号、收发缓冲、定时器）、epoll 实例和就绪队列、UDP 和原始 socket 的队列 | 已有连接不断，应用手里的 socket 编号不变 |
| 存储 | 启动盘本身，加上本次开机日志写到了哪里；其余都在盘上 | 正在写内核槽（在线更新）时拒绝替换，写完再装一次 |
| 模块管理 | 还没执行的模块操作队列 | |
| 驱动 | 不交接 | 设备先复位，再由新驱动重新接管，网络会断开片刻，TCP 自己重传。换掉启动盘的驱动时，存储服务先交出磁盘，再接着用新驱动 |

**协议栈的引导版。** 启动镜像要放进 256 KiB 的槽，所以里面的协议栈是按体积编译、不带状态交接的引导版，只负责联网和拉取模块。

- 镜像默认把完整的、按速度编译的 `netstack` 模块带在磁盘上（`DISK_MODULES=netstack`），第一次开机时安装。
- 以后每次开机，它都在任何应用运行之前接替引导版。这时引导版里除了网络配置还没有别的状态，交接配置就够了。
- 之后的协议栈更新都在运行中完成，带完整的状态交接。
- 例外：运行中从引导版换成安装的协议栈，或者删掉安装的协议栈回到引导版，都要到下次开机才生效。

**安全网：**

- **崩溃按代码地址归属。** CPU 异常的地址、panic 的模块、卡死时的指令地址落在哪个安装的模块里，就记在它头上。下次开机关掉它，回到启动镜像里的版本。
- **安全模式。** 连续三次不稳定启动后进入安全模式，不启动任何安装的模块，只用启动镜像里的服务。
- **版本检查。** 内核更新以后，启动镜像里的服务可能比以前安装的新。版本更旧的服务模块不会被使用，用 `mod rm` 删掉即可。

**测试：** `hot_test.py` 在 BIOS 下跑一遍，再在 UEFI 加 legacy virtio 设备下跑一遍：

- 在 24 MB 的 HTTPS 下载和 16 MB 的 TCP 回环数据流进行中替换协议栈，两者都完整结束，空闲连接也还能用。
- 在数据流进行中替换 virtio 驱动，数据流同样完整。
- 存储和模块管理替换后再删掉，换回启动镜像里的版本。

## 写自己的应用

在 `apps/` 下新建一个 crate，实现 `rustros_api::App`，然后在 `kernel/Cargo.toml` 里加成 feature，在 `kernel/src/main.rs` 的 `make_apps()` 里注册：

```rust
pub trait App {
    fn name(&self) -> &'static str;
    fn start(&mut self, sys: &mut dyn Sys) {}                          // 打开 socket
    fn poll(&mut self, sys: &mut dyn Sys) {}                           // 每轮主循环（≤1ms）
    fn key(&mut self, sys: &mut dyn Sys, c: u8) {}                     // 控制台输入
    fn on_frame(&mut self, sys: &mut dyn Sys, f: &[u8]) -> bool { false } // 协议栈之前看到原始帧
}
```

`Sys` 提供的能力：
- **socket（Linux 语义，`rustros_api::socket`）：** `socket`、`bind`、`listen`、`accept`（带 accept4 的标志）、`connect`、`sendto`/`recvfrom`、`shutdown`、`close`、`getsockname`/`getpeername`、`setsockopt`/`getsockopt`、`ioctl`（`FIONREAD`、`SIOCOUTQ`、`FIONBIO`）。
  - 常量、标志、选项名和错误码都用 Linux（x86_64）的值，将来的 Linux 兼容层可以原样传递。
  - 地址是带地址族的 `SockAddr`，留了 IPv6 的位置。`AF_INET6` 在协议栈支持 IPv6 之前返回 `EAFNOSUPPORT`。
  - **不包括 Unix 域套接字**（`AF_UNIX`）：它属于以后的 VFS / 进程层，现在返回 `EAFNOSUPPORT`。
  - 常用的组合（监听端口、发起连接、绑定 UDP 端口、连接是否已建立）在 `rustros_util::sock` 里。
- **就绪通知：** 协议栈在 socket 状态变化的那一刻主动通知，不靠上层轮询。
  - `epoll_create`、`epoll_ctl`（支持 `EPOLLET`、`EPOLLONESHOT`）、`epoll_wait`。
  - `sock_poll` 返回当前就绪状态和这个 socket 的事件计数。
  - 以后的阻塞调用和进程层的 epoll 挂在同一个通知点（`Link::notify`）上。
- **持久存储：** `kv_get`、`kv_put`、`kv_delete`、`kv_keys`、`storage_info`。每个应用只能访问自己的命名空间；调用返回时，数据已经写入磁盘。
- **网络配置和查询：** `net_info`、`net_config`、`arp_table`、`tcp_connections`
- **原始帧：** `send_frame`
- **其他：** 时间、启动参数、打印、随机数、重启、更新槽、上次崩溃原因

接口说明：
- 所有 socket 调用都是非阻塞的：没数据时返回 `EAGAIN`，`connect` 返回 `EINPROGRESS`，结果由 `EPOLLOUT`/`EPOLLERR` 和 `SO_ERROR` 给出。阻塞、超时和 `SIGPIPE` 是以后进程层的事，协议栈只返回 `EPIPE`（`MSG_NOSIGNAL` 照收）。
- 端口冲突时返回 `EADDRINUSE`；`SO_REUSEPORT` 接口已留，暂未实现（`ENOPROTOOPT`）。
- 暂未实现：TCP 只监听某一个本机地址（现在所有地址都接受）、UDP 用 `AF_UNSPEC` 解除 connect、已 connect 的 UDP 收到 ICMP 不可达时报 `ECONNREFUSED`。
- 每个 socket 只能由创建它的应用使用。
- TCP 应用可以用 `rustros_util::conn::Conn`，它帮你处理部分写入和关闭前刷完数据。
- NAT、交换、隧道这类按包处理的应用，用 `on_frame` 直接处理原始帧，不经过 socket 层。

## 长期目标

**纯 Rust 极致转发流量 + 自己的容器运行时跑 Go/PostgreSQL 等业务，几乎所有更新都不需要重启。**

- **数据面（Data Plane）由 RustROS 负责**：路由、NAT、VPN、代理这类网络流量，由纯 Rust 的高性能数据面直接处理，追求极致转发性能。
- **业务跑在容器里**：容器运行时由我们用 Rust 从零写成 RustROS 的原生组件（不使用、也不参照 Docker 的代码）。
  - 用法与 Docker 一致，兼容 compose 文件（`compose.yaml`、`docker-compose.yml`）和 OCI 镜像格式；内部测试阶段命令叫 `docker`，对外发布前改用自己的名字。
  - 一个 **Linux 兼容层**只负责运行容器里的 Linux 程序。它按手册页、POSIX 规范、实际行为和 LTP 测试实现，不照着 Linux 内核源码翻译。
  - 隔离（独立根目录、独立进程编号空间）用 RustROS 自己的机制实现；只有容器里的程序自己调用时，才需要模拟命名空间相关的系统调用。
  - 初期只用 host 网络；镜像层解包到 ext4 上。
  - 第一个目标：`docker compose up -d` 启动一个 Debian 13 容器，`docker exec -it` 进去能 `apt install`、能用 curl 上网。
- 不走虚拟化（VMX）这条路：云主机（例如阿里云 ECS）通常不提供嵌套虚拟化。也不靠 WebAssembly：PostgreSQL 这类软件搬不过去。

**热更新：几乎所有更新都在运行中完成，不需要重启。**

模块可以在运行中替换，内核只能靠重启更换，所以内核里的每一行代码都是"改了就得重启"的代码。衡量内核的标准是"多久需要改一次"，而不只是字节数。

1. **内核只放机制，不放策略和功能**：
   - 留在内核：内存管理、中断、调度核心、系统调用入口和分发、模块加载与替换、数据包路径最底层的收发；用户态进程的机制（地址空间、物理内存、fork/exec/wait、按需分页和写时复制）也在内核，这样系统调用模块可以在进程运行中替换。
   - 做成可热替换的模块：协议栈、网络配置、驱动、存储、文件系统（VFS、ext4）、Linux 兼容层、容器运行时、控制台、各种应用，以及具体的包处理逻辑（包处理模块）。
   - 继续瘦身是日常收敛的一部分，优先把将来会经常改动的代码移出内核。
2. **系统调用**：内核里只做入口和分发（`syscall` 进入，进程状态在内核），Linux 系统调用的具体实现放在可热更新的 `linux` 模块里（`rustros_api::module::Syscalls`），它会是以后改动最频繁的部分。
3. **有状态的模块要有热更新策略**，在设计接口时就定下来：
   - 无状态的直接替换；
   - 把状态交接给新版本（例如替换协议栈时，已有的 TCP 连接不断）；
   - 或者等它空闲（排空）后再替换。
4. **热更新要有回归测试**：例如替换协议栈模块时已有 TCP 连接不断，替换兼容层时运行中的容器不受影响。

现状：

- 启动镜像里的服务（协议栈、存储、模块管理、驱动）已经可以在运行中替换，协议栈带完整的状态交接，见“服务的热替换”。
- 安装的模块（应用、ext4、WebAssembly 运行时）本来就能在线替换，但它们是重启式的：应用丢掉自己的 socket，ext4 先卸载再由新驱动挂载，WebAssembly 实例在新运行时上重新启动。
- 内核本身更新仍然需要重启。

**启动镜像保持最小、不变**：原始启动镜像（256 KiB 的内核槽）不扩容，只保留启动、联网、拉取模块和救援所需的部分。其他组件，包括将来兼容 Linux 的完整版本（兼容层、VFS、容器运行时等），一律作为模块缓存在磁盘上、开机从磁盘加载、通过网络更新，或随离线安装包写到磁盘上。

为此要铺的路（详细里程碑和验收标准见项目笔记）：

1. **socket 接口按 Linux 语义重做**：就绪主动通知（epoll、边沿触发），地址留 IPv6 的位置。
2. **进程和用户态**：ring 3、每个进程独立的地址空间、系统调用入口、抢占式调度（数据面优先）；以后再做多核。
   - 以后要加：给进程保留最低 CPU 份额，转发满负荷时业务进程也不会完全饿死（现在进程只在主循环空闲时运行）。
3. **VFS 和 POSIX 级的 ext4**（做成模块）：按偏移读写、truncate、fsync、原子 rename、硬链接和符号链接、权限、属主和时间、jbd2 日志；/tmp、/dev、/proc。
4. **Linux 兼容层模块**：系统调用（clone、futex、mmap、epoll、信号……）、伪终端、网络系统调用。
5. **容器运行时**：导入镜像、compose、`run/exec/ps/stop/rm/logs`。
6. **业务和网络的衔接**：容器的网络接到 RustROS 的数据面上，转发路径不经过兼容层和容器运行时。
7. **硬件驱动全部用 Rust 写（纯血 Rust）**：兼容层只兼容系统调用层，不搬 Linux 的内核驱动。物理机需要的驱动用 Rust 写成驱动模块（`Driver` 接口），先做 NVMe 和 Intel 网卡（e1000e、ixgbe、i40e），RAID 用 Rust 的软 RAID（硬件 RAID 卡设成直通）。

## 现状与限制

- 单核，轮询驱动（网卡/磁盘不用中断，PIT 只用来唤醒 `hlt`）
- TCP 只按序接收（乱序段丢弃，等对方重传），重传采用 go-back-N，没有窗口缩放
- 不支持 IPv4 分片，没有 IPv6
- 只支持 virtio 设备；物理机网卡和 AHCI/NVMe 暂不支持
- 没有 i6300esb 的机器上，如果内核关着中断卡死（应用代码做不到这一点，只有内核 bug 会），需要手动重启
- VPS 磁盘以后再扩容的话，数据分区不会自动变大（目前有 256 MiB 上限，也用不上更大的空间）
- grub.cfg 里明文保存着更新密钥，能读这块盘的人就能拿到密钥

## 许可

RustROS 是闭源的专有软件，见 [LICENSE](LICENSE)：源码保密；rustros.com 发布的官方文件（内核、模块、镜像）可以免费装在自己的机器上用，不能转卖、再分发或逆向。

用到的第三方代码都是宽松许可（MIT、Apache-2.0、BSD、ISC），没有 GPL 代码进内核或模块；它们要求的版权声明和许可全文由 `tools/notices.py` 生成，随每个版本发布（`THIRD-PARTY-NOTICES.txt`）。镜像里的 GRUB 是 GPLv3 的独立程序，只引导内核、不传染；它的源码包（Debian 的 grub2，与构建用的版本一致）随版本发布在 `releases/sources/`。

保持闭源要守住的规矩：驱动照硬件手册写，不翻译 Linux 驱动（逐行移植算衍生作品）；Linux 兼容模块只实现系统调用接口，不抄 Linux 代码；新增依赖先看许可，GPL/LGPL/AGPL 的不用。
