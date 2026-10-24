# RustROS

RustROS 是一个用 Rust 编写的路由器操作系统，面向云服务器、VPS 和 KVM 虚拟机。

- **转发和网络功能**：路由、NAT 与端口转发、VLAN、L2TP、WireGuard、CAKE 流量整形
- **网页管理**：网络配置先作为候选，应用后需要确认，超时没有确认就自动回滚
- **在线更新**：新内核写入备用槽，先试启动一次，确认后才切换；起不来就自动回到原来的内核
- **热替换**：协议栈、存储、驱动和应用模块都能在系统运行中替换，大多数更新不用重启
- **小巧的启动镜像**：2 MiB 的磁盘镜像，同时支持 BIOS 和 UEFI 启动；virtio-net、virtio-blk（modern 和 legacy）

## 安装和文档

- 网站：<https://rustros.com>
- 安装：`curl -fsSL https://rustros.com/install.sh | sh`（先试启动，确认正常后才写入系统盘）
- 文档：<https://rustros.com/docs/>

## 许可

RustROS 是闭源软件，源代码不公开。发行版中附带的第三方组件按各自的许可提供，说明随发行版一起发布。

---

RustROS is a router operating system written in Rust for cloud servers, VPS and KVM virtual machines: routing, NAT and port forwarding, VLAN, L2TP, WireGuard, CAKE shaping, a web admin with confirm-or-revert network changes, online updates with a trial boot and automatic rollback, and hot replacement of the network stack, storage, drivers and apps. A 2 MiB disk image boots on BIOS and UEFI.

Website: <https://rustros.com> · Install: `curl -fsSL https://rustros.com/install.sh | sh` · Docs: <https://rustros.com/docs/>

RustROS is proprietary software; its source code is not published.
