#!/bin/bash
# fw_jump.elf is from openbsi releases (version 0.1, platform/qemu/virt/).
# The load address (addr parameter) is hardcoded in fw_jump.elf, e.g.:
#  https://github.com/riscv/opensbi/blob/master/platform/qemu/virt/config.mk#L24
#  (Oh yes, they changed the exact address 1 day after I started using it.)
# And also the kernel (FW_JUMP_ADDR_PHY).
qemu-system-riscv64 -M virt -m 256M -kernel bin/fw_jump.elf -device loader,file=kernel/build/kernel.bin,addr=0x80200000 -nographic -serial stdio -monitor tcp::1234,server,nowait -gdb tcp::1235 -initrd initrd.tar
