.text
.globl _start
_start:
    call main
    li a7, 2 /* SYS_DEBUG_STOP */
    ecall
