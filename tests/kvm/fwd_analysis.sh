#!/bin/bash
# The forwarding analysis (on the KVM test box): RustROS against Linux kernel
# forwarding, nftables and XDP in the same VM configuration; 64-byte UDP with pktgen in 1 and 16 flows, TCP with
# 1, 2, 4 and 8 streams. Every test alone, RUNS=3 runs of 10 s each.
# Results in $KVM_WORK/fwdan/results.txt.
#
#   fwd_analysis.sh [rustros-stages-root]
#
# With a second argument, also the stage breakdown from a RustROS
# measurement build (make APPS=stages SIZE_MB=8 in that tree).
T=$(cd "$(dirname "$0")" && pwd)
R=$(cd "$T/../.." && pwd)
S=${KVM_WORK:-/root/rustros-test}/fwdan
mkdir -p $S && cp -a $T/fwd_bench.py $T/kvm_check.sh $S/
OUT=$S/results.txt
: > $OUT
bash $T/kvm_check.sh >> $OUT || exit 1
bash $T/linux-router/build.sh $S >> $OUT || exit 1
ROUTERS="rustros linux-fwd linux-nft linux-xdp"
run() { echo "## $*" >> $OUT; (cd $S && env RUNS=3 SECS=10 "$@" timeout 1800 python3 fwd_bench.py bios) 2>&1 | grep -aE "^fwd|busy|kpps on|RustROS:|FAIL|Traceback" >> $OUT; }
for r in $ROUTERS; do
  for f in 1 16; do run ROOT=$R ROUTER=$r GEN=pktgen FLOWS=$f; done
  run ROOT=$R ROUTER=$r GEN=tcpflows
done
if [ -n "$1" ]; then
  run ROOT=$1 ROUTER=rustros GEN=pktgen FLOWS=1
  run ROOT=$1 ROUTER=rustros GEN=pktgen FLOWS=16
  run ROOT=$1 ROUTER=rustros GEN=iperf
fi
echo DONE >> $OUT
