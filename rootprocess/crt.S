.text
.globl _start
_start:
    call main
    li a7, 2 /* debug_stop */
    ecall

