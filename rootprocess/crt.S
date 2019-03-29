.text
.globl _start
_start:
.option push
.option norelax
    lla gp, __global_pointer$
.option pop
    call crt_init
    li t6, 2 /* SYS_DEBUG_STOP */
    ecall
