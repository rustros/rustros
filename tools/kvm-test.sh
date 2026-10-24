#!/bin/bash
# Run the whole regression suite on the KVM test box from a development
# machine: copy this working tree's files to the box (the same path there; the box
# keeps its own build/ with the update key), run tests/kvm/run_all.sh, show
# the summary. Exits non-zero when a test failed.
#
#   tools/kvm-test.sh [user@host]      (or set RUSTROS_KVM_HOST)
#
# All QEMU tests run on the KVM box only, with -accel kvm (never software
# emulation); tests/kvm/kvm_check.sh stops the run if KVM is not in effect.
set -e
HOST=${1:-$RUSTROS_KVM_HOST}
[ -n "$HOST" ] || { echo "usage: tools/kvm-test.sh user@host (or RUSTROS_KVM_HOST)"; exit 2; }
R=$(cd "$(dirname "$0")/.." && pwd)
cd $R
# what git tracks plus new files it does not ignore (no build output, nothing
# excluded locally)
{ git ls-files; git ls-files --others --exclude-standard; } | tar cf - -T - | ssh -o BatchMode=yes $HOST "mkdir -p $R && cd $R && tar xmf -"
out=$(ssh -o BatchMode=yes $HOST "bash $R/tests/kvm/run_all.sh" | tee /dev/stderr)
grep -q "^failed: 0$" <<< "$out"
