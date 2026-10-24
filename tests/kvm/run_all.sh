#!/bin/bash
# The whole regression suite, on the KVM test box (see README.md here; from
# a development machine: tools/kvm-test.sh <host>):
#  - every kernel variant is built once, up front, each into its own root
#    (builds/<variant>: build/ plus links to tools/ and target/), test
#    images with a short stable-boot time (rustros.stable=20, instead of 120 s);
#  - the timing tests run alone: the performance test, the user-mode process
#    tests (throughput under a spinning process) and the forwarding benchmark;
#  - the rest runs in parallel groups, each in its own copy of this
#    directory with its ports shifted by 1000 x (group + 1).
# The repository is the one this script is in; the work directory (images,
# logs, results) is $KVM_WORK, by default /root/rustros-test. Results:
# $KVM_WORK/groups/*/out, summed up at the end with the number of failures.
export PATH=$HOME/.cargo/bin:$PATH
T=$(cd "$(dirname "$0")" && pwd)
R=$(cd "$T/../.." && pwd)
S=${KVM_WORK:-/root/rustros-test}
B=$S/builds
mkdir -p $S
exec 9>$S/run.lock
flock -n 9 || { echo "another test run is active, stopping"; exit 1; }
export RUSTROS_LOCKED=1
bash $T/kvm_check.sh || exit 1
T0=$(date +%s)
STABLE="rustros.stable=20"

# ---------------------------------------------------------------- builds
cd $R
variant() {  # name, make arguments
    local v=$1; shift
    make -B CMDLINE="$STABLE" "$@" >>$S/build.log 2>&1 || { echo "BUILD FAILED ($v, build.log)"; tail -20 $S/build.log; exit 1; }
    rm -rf $B/$v && mkdir -p $B/$v && cp -a build $B/$v/build && ln -s $R/tools $B/$v/tools && ln -s $R/target $B/$v/target
}
: > $S/build.log
make modules >>$S/build.log 2>&1 && make wasm >>$S/build.log 2>&1 && make user >>$S/build.log 2>&1 || { echo "BUILD FAILED (modules/wasm/user, build.log)"; tail -20 $S/build.log; exit 1; }
variant default
python3 tools/mkimg.py build/rustros.elf $B/default/build/big.img --size-mb 8 --ip 10.0.2.15/24 --gw 10.0.2.2 --key-file build/update.key --cmdline "$STABLE" >>$S/build.log 2>&1
python3 tools/mkimg.py build/rustros.elf $B/default/build/dhcp.img --key-file build/update.key --cmdline "$STABLE" >>$S/build.log 2>&1
# the layout of the deployed boxes: 2 MiB with 256 KiB slots (esp-grow, slots-grow)
python3 tools/mkimg.py build/rustros.elf $B/default/build/slots256.img --slot-kb 256 --bundle netstack=build/modules/netstack.mod --key-file build/update.key --cmdline "rustros.stable=5" >>$S/build.log 2>&1
variant su APPS="shell updater" SIZE_MB=8
variant seh APPS="shell echo httpd updater" SIZE_MB=8
make -B >>$S/build.log 2>&1   # the repo's own build/ back to the plain default
echo "builds: $(( $(date +%s) - T0 )) s; kernel $(stat -c %s $B/default/build/rustros.elf) bytes"
# throwaway TLS material for the HTTPS tests, fresh for every run
rm -rf $S/panelmock && bash $T/make_certs.sh $S

# ---------------------------------------------------------------- one test
# a copy of the tests in its own directory
tests_into() { mkdir -p $1 && cp -a $T/*.py $T/*.sh $S/panelmock $1/; }
# run <dir> <variant> <name> <env...> -- <command...>
run() {
    local d=$1 v=$2 name=$3; shift 3
    local envs=(); while [ "$1" != "--" ]; do envs+=("$1"); shift; done; shift
    local t=$(date +%s)
    (cd $d && env ROOT=$B/$v "${envs[@]}" timeout 1800 "$@") > "$d/log-$name" 2>&1
    local res=$(grep -aE "^(FAIL|ALL OK)|Traceback" "$d/log-$name" | head -2 | tr '\n' ' ')
    [ -z "$res" ] && res=$(tr -d '\r' < "$d/log-$name" | grep -aE "^net: (nic0|ip)|rescue>" | head -2 | tr '\n' ' ')
    echo "== $name ($(( $(date +%s) - t )) s): $res" >> $d/out
}

# ---------------------------------------------------------------- timing tests, alone
mkdir -p $S/groups && rm -rf $S/groups/*
P=$S/groups/perf; tests_into $P
run $P default perf DISK_MB=300 -- python3 perf_test.py bios
grep -aE "udp ping|tcp echo" $P/log-perf >> $P/out
# user-mode processes: alone too (they measure throughput under a process
# that spins for ever, against the same measurement without it)
run $P default "proc bios" DISK_MB=300 -- python3 proc_test.py bios
run $P default "proc uefi" DISK_MB=300 -- python3 proc_test.py uefi
grep -ah "spinner" "$P/log-proc bios" "$P/log-proc uefi" >> $P/out

# ---------------------------------------------------------------- parallel groups
PORTS="17777 17001 19000 28820 23400 19202 19201 18766 18089 18088 19203 18557 18490 11701 28123 19301 18580 18581"
group() {  # number, then "variant|name|env...|command" items
    local n=$1; shift
    local d=$S/groups/g$n; tests_into $d
    local shift_by=$(( (n + 1) * 1000 ))
    for p in $PORTS; do sed -i "s/\b$p\b/$(( p + shift_by ))/g" $d/*.py; done
    for item in "$@"; do
        IFS='|' read -r v name envs cmd <<< "$item"
        run $d $v "$name" $envs -- $cmd
    done
}
group 0 "default|static nat||python3 snat_test.py bios" "default|router||python3 router_test.py bios" "default|cake|DISK_MB=300|python3 cake_test.py bios" \
        "default|mq|DISK_MB=300|python3 mq_test.py bios" "default|nat||python3 nat_test.py bios" "default|l2tp|DISK_MB=300|python3 l2tp_test.py bios" &
group 1 "default|vlan||python3 vlan_test.py bios" "default|cand||python3 cand_test.py bios" "default|legacy nic bios|DISK_MB=300|python3 bootlog.py bios legacy" \
        "default|legacy nic uefi|DISK_MB=1200|python3 bootlog.py uefi legacy" "default|dhcp|IMG=dhcp.img DISK_MB=1200|python3 dhcp_test.py uefi" &
group 2 "default|rescue bios|DISK_MB=1200|python3 rescue_test.py bios" "default|rescue uefi|DISK_MB=1200|python3 rescue_test.py uefi" \
        "default|layout bios|IMG=rustros.img DISK_MB=1200|python3 layout_test.py bios" "default|layout uefi|IMG=rustros.img DISK_MB=1200|python3 layout_test.py uefi" \
        "default|layout big|IMG=big.img DISK_MB=1200|python3 layout_test.py bios" &
group 3 "default|grow bios|IMG=slots256.img DISK_MB=1200|python3 grow_test.py bios" "default|grow uefi|IMG=slots256.img DISK_MB=1200|python3 grow_test.py uefi" \
        "default|sites|IMG=rustros.img DISK_MB=1200|python3 sites_test.py bios" "default|webadmin|IMG=rustros.img DISK_MB=1200|python3 webadmin_test.py bios" \
        "default|pkg|IMG=rustros.img DISK_MB=1200|python3 pkg_test.py bios" &
group 4 "su|bootloop|DISK_MB=300|python3 bootloop_test.py bios" "su|modules|DISK_MB=300|python3 module_test.py bios" &
group 5 "seh|update bios|IMG=rustros.img DISK_MB=1200|python3 test.py bios update" "seh|update uefi|IMG=rustros.img DISK_MB=1200|python3 test.py uefi update" \
        "seh|store bios|IMG=rustros.img DISK_MB=1200|python3 store_test.py bios" "seh|store uefi|IMG=rustros.img DISK_MB=1200|python3 store_test.py uefi" \
        "seh|watchdog|WDT=1 DISK_MB=300|python3 wdt_test.py bios" &
group 6 "default|hot bios|IMG=rustros.img DISK_MB=1200|python3 hot_test.py bios" "default|hot uefi legacy|IMG=rustros.img DISK_MB=1200|python3 hot_test.py uefi legacy" \
        "default|curl|DISK_MB=300|python3 curl_test.py bios" &
group 7 "default|slots-grow bios|IMG=slots256.img DISK_MB=300|python3 slots_grow_test.py bios" \
        "default|slots-grow uefi|IMG=slots256.img DISK_MB=300|python3 slots_grow_test.py uefi" &
wait

# ---------------------------------------------------------------- forwarding benchmark, alone
# TCP 1 and 4 streams (iperf3), 64-byte UDP in 1 and 16 flows (pktgen)
F=$S/groups/fwd; tests_into $F
run $F default fwd -- python3 fwd_bench.py bios
grep -a "^fwd " $F/log-fwd >> $F/out

cat $S/groups/perf/out $S/groups/g*/out $S/groups/fwd/out
echo "failed: $(cat $S/groups/*/out | grep -c 'FAIL\|Traceback')"
echo "DONE in $(( $(date +%s) - T0 )) s"
