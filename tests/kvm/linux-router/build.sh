#!/bin/bash
# The Linux reference router for the forwarding measurements (fwd_bench.py
# ROUTER=linux-*): an initramfs for the test box's own kernel that configures
# the two NICs exactly as RustROS is configured in fwd_bench.py and then
# forwards with plain kernel forwarding, a stateful nftables forward chain,
# or an XDP program (xdp_fwd.c), as the kernel command line says
# (router=fwd|nft|xdp).
#
#   linux-router/build.sh OUT_DIR    -> OUT_DIR/linux-router.cpio.gz
#
# Needs busybox-static, nftables, bpftool, clang and libbpf-dev on the box.
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:?usage: build.sh OUT_DIR}
K=${KERNEL_RELEASE:-$(uname -r)}
D=$(mktemp -d)
trap 'rm -rf $D' EXIT
mkdir -p $D/{bin,sbin,lib,lib64,usr/lib,proc,sys,dev,tmp,mods,etc,run}
cp /usr/bin/busybox $D/bin/
for a in sh mount sysctl cat echo sleep ls insmod sed basename; do ln -sf busybox $D/bin/$a; done
# real ip (iproute2), nft and bpftool, with their libraries
for b in /usr/bin/ip /usr/sbin/nft /usr/sbin/bpftool; do
  cp $b $D/bin/
  for l in $(ldd $b | grep -o "/[^ ]*"); do mkdir -p $D$(dirname $l); cp -L $l $D$l; done
done
cp -L /lib64/ld-linux-x86-64.so.2 $D/lib64/
# kernel modules, decompressed, in load order
: > $D/mods/order
for m in virtio_net nf_tables nft_ct nf_conntrack nft_chain_nat nf_nat nft_nat; do
  for f in $(modprobe -S $K --show-depends $m | awk '/^insmod/ {print $2}'); do
    n=$(basename $f .xz)
    if ! grep -qx "$n" $D/mods/order; then xz -dc $f > $D/mods/$n; echo $n >> $D/mods/order; fi
  done
done
clang -O2 -g -target bpf -I/usr/include/x86_64-linux-gnu -c $HERE/xdp_fwd.c -o $D/etc/xdp_fwd.o
cat > $D/init <<'INIT'
#!/bin/sh
mount -t proc proc /proc; mount -t sysfs sys /sys; mount -t devtmpfs dev /dev
mount -t bpf bpf /sys/fs/bpf 2>/dev/null
for m in $(cat /mods/order); do insmod /mods/$m 2>/dev/null; done
MODE=$(sed -n "s/.*router=\([a-z0-9]*\).*/\1/p" /proc/cmdline)
sleep 1
# the NICs by MAC, as in fwd_bench.py (nic1 towards fa, nic2 towards fb)
for d in /sys/class/net/*; do
  case $(cat $d/address) in
    52:54:00:f0:00:01) A=$(basename $d);;
    52:54:00:f0:00:02) B=$(basename $d);;
  esac
done
ip link set lo up; ip link set $A up; ip link set $B up
ip addr add 10.10.1.1/24 dev $A; ip addr add 10.10.2.1/24 dev $B
sysctl -qw net.ipv4.ip_forward=1
case $MODE in
  nft)
    nft -f /etc/fwd.nft;;
  xdp)
    # native (driver) mode only: no silent fallback to generic XDP
    bpftool prog load /etc/xdp_fwd.o /sys/fs/bpf/xdp_fwd type xdp && echo "xdp: loaded"
    bpftool net attach xdpdrv pinned /sys/fs/bpf/xdp_fwd dev $A && echo "xdp: attached to $A"
    bpftool net attach xdpdrv pinned /sys/fs/bpf/xdp_fwd dev $B && echo "xdp: attached to $B";;
esac
echo "LINUX ROUTER READY mode=$MODE nics=$A,$B"
exec sh </dev/console >/dev/console 2>&1
INIT
chmod +x $D/init
# nftables: a stateful forward filter (connection tracking), as a typical router has
cat > $D/etc/fwd.nft <<'NFT'
table inet filter {
  chain forward {
    type filter hook forward priority 0; policy drop;
    ct state established,related accept
    ip saddr 10.10.1.0/24 ip daddr 10.10.2.0/24 accept
    ip saddr 10.10.2.0/24 ip daddr 10.10.1.0/24 accept
  }
}
NFT
mkdir -p "$OUT"
(cd $D && find . | cpio -o -H newc 2>/dev/null | gzip -1 > "$OUT/linux-router.cpio.gz")
ls -l "$OUT/linux-router.cpio.gz"
