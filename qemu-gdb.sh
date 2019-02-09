#!/bin/bash
riscv64-linux-gnu-gdb kernel/kernel.elf -ex "target remote localhost:1235"
