#!/bin/bash
riscv64-linux-gnu-gdb kernel/build/kernel.elf -ex "target remote localhost:1235"
