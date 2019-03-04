.text
.globl _start
_start:
.option push
.option norelax
    lla gp, __global_pointer$
.option pop
    call main
    li a7, 2 /* SYS_DEBUG_STOP */
    ecall
