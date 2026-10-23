# RustROS: build a raw disk image that boots on BIOS and UEFI.
#   make                  build build/rustros.img
#   make run-bios         boot it in QEMU (SeaBIOS)
#   make run-uefi         boot it in QEMU (OVMF)
#   make update HOST=...  push the current kernel to a running RustROS
#   make wasm             build the WebAssembly modules in wasm/ into build/wasm/
#   make modules          build the native modules in modules/ into build/modules/
#
# Default network settings written into grub.cfg (IP= empty: set them on the
# console with 'ip' + 'save'; saved settings always win):
IP  ?= 10.0.2.15/24
GW  ?= 10.0.2.2
MTU ?=
KEY ?=
# image size in MiB (default 2: 256 KiB kernel slots; a kernel with apps built in needs 8)
SIZE_MB ?=
# more kernel arguments in grub.cfg (test images: CMDLINE=rustros.stable=20)
CMDLINE ?=
# Modules built into the kernel (everything else is a loadable module, see modules/):
# apps built into the kernel itself (none: rescue, dhcp and the updater are the boot module)
APPS ?=
# one binary with rescue, dhcp and the updater (modules/boot)
BOOT_MODULES := boot
# The online update key is generated once and kept here:
KEY_FILE ?= build/update.key

KERNEL := target/x86_64-unknown-none/release/rustros
# what goes into a slot: the kernel behind a self-extracting stub (tools/pack.py)
PACKED := build/rustros.elf
IMG    := build/rustros.img
OVMF   ?= /usr/share/OVMF/OVMF_CODE_4M.fd
OVMF_VARS ?= /usr/share/OVMF/OVMF_VARS_4M.fd
HOST   ?= 127.0.0.1
PORT   ?= 9000

QEMU := qemu-system-x86_64 -m 256 -serial stdio \
	-drive file=$(IMG),format=raw,if=virtio \
	-nic user,model=virtio-net-pci,hostfwd=tcp:127.0.0.1:8080-:80,hostfwd=tcp:127.0.0.1:9000-:9000,hostfwd=tcp:127.0.0.1:7777-:7

.PHONY: all kernel bootmods $(PACKED) wasm modules run-bios run-uefi update clean
all: $(IMG)

kernel:
	cargo build --release -p rustros-kernel --no-default-features --features "$(APPS)"

$(PACKED): kernel bootmods tools/pack.py
	@mkdir -p build
	python3 tools/pack.py $(KERNEL) $@ $(foreach m,$(BOOT_MODULES),--boot=$(m)=build/modules/$(m).mod)

$(IMG): $(PACKED) tools/mkimg.py
	python3 tools/mkimg.py $(PACKED) $@ $(if $(IP),--ip $(IP)) $(if $(GW),--gw $(GW)) --key-file $(KEY_FILE) $(if $(MTU),--mtu $(MTU)) $(if $(KEY),--key $(KEY)) $(if $(SIZE_MB),--size-mb $(SIZE_MB)) $(if $(CMDLINE),--cmdline "$(CMDLINE)")

wasm:
	cd wasm && cargo build --release
	@mkdir -p build/wasm
	cp wasm/target/wasm32-unknown-unknown/release/*.wasm build/wasm/

# the boot modules, built with the kernel (same API)
bootmods:
	cd modules && cargo build --release $(foreach m,$(BOOT_MODULES),-p $(m)-mod)
	@mkdir -p build/modules
	@for m in $(BOOT_MODULES); do cp modules/target/x86_64-unknown-none/release/$$m build/modules/$$m.mod; done

modules:
	cd modules && cargo build --release
	@mkdir -p build/modules
	@for f in modules/target/x86_64-unknown-none/release/*; do \
		[ -f "$$f" ] && [ -x "$$f" ] && cp "$$f" build/modules/$$(basename $$f).mod; done; ls build/modules

run-bios: $(IMG)
	$(QEMU)

build/OVMF_VARS.fd:
	@mkdir -p build
	cp $(OVMF_VARS) $@

run-uefi: $(IMG) build/OVMF_VARS.fd
	$(QEMU) -drive if=pflash,format=raw,readonly=on,file=$(OVMF) -drive if=pflash,format=raw,file=build/OVMF_VARS.fd

update: $(PACKED)
	python3 tools/rustros-update.py $(HOST) upload $(PACKED) --port $(PORT) --key-file $(KEY_FILE) --wait

clean:
	cargo clean
	cd wasm && cargo clean
	cd modules && cargo clean
	rm -rf build
