#!/bin/bash
# Every test run starts here: QEMU must really run with KVM (no software emulation).
out=$(printf 'info kvm\nquit\n' | timeout 60 qemu-system-x86_64 -accel kvm -machine q35 -display none -nodefaults -S -monitor stdio 2>&1)
if echo "$out" | grep -q "kvm support: enabled"; then
    echo "kvm: enabled"
else
    echo "KVM NOT IN EFFECT, stopping: $out"
    exit 1
fi
