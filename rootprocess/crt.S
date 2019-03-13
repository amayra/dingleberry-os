.text
.globl _start
_start:
.option push
.option norelax
    lla gp, __global_pointer$
.option pop
    call crt_init
    li a0, 0 /* argc */
    li a1, 0 /* argv */
    call main
    li a7, 2 /* SYS_DEBUG_STOP */
    ecall
