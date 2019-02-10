/*
 * Copyright (C) 2012 Regents of the University of California
 * Copyright (C) 2017 SiFive
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   as published by the Free Software Foundation, version 2.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 */

#include "memory.h"

OUTPUT_ARCH(riscv)
ENTRY(_start)

SECTIONS
{
    /* Beginning of code and text segment */
    . = LOAD_OFFSET;

    .text : AT(ADDR(.text) - LOAD_OFFSET) {
        _text = .;
        _stext = .;
        /* The boot loader jumps at the start of the binary, thus objdump must
         * output .init.text as byte 0. */
        _start = .;
        *(.init.text .init.text.*)
        . = ALIGN(8);
        *(.text .text.fixup)
        *(.ref.text)
        *(.fixup)
        _etext = .;
    }

    . = ALIGN(PAGE_SIZE);

    .rodata : AT(ADDR(.rodata) - LOAD_OFFSET) {
        _srodata = .;
        *(.rodata) *(.rodata.*)
        *(.srodata*)
        _erodata = .;
    }

    . = ALIGN(PAGE_SIZE);

    .data : AT(ADDR(.data) - LOAD_OFFSET) {
        _sdata = .;
        /* https://www.sifive.com/blog/all-aboard-part-3-linker-relaxation-in-riscv-toolchain */
        __global_pointer$ = . + 0x800;
        *(.data)
    }
    .sdata : {
        *(.sdata*)
        /* End of data section */
        _edata = .;
    }

    _sbss = .;
    .bss : AT(ADDR(.bss) - LOAD_OFFSET) {
        *(.sbss*)
        *(.bss..page_aligned)
        *(.dynbss)
        *(.bss)
        *(COMMON)
    }
    _ebss = .;

    .notes : AT(ADDR(.notes) - LOAD_OFFSET) {
        __start_notes = .;
        KEEP(*(.note.*))
        __stop_notes = .;
    }

    .rel.dyn : {
        *(.rel.dyn*)
    }

    _end = .;

    /*
    STABS_DEBUG
    DWARF_DEBUG
    */

    /DISCARD/ : {
        *(.discard)
        *(.discard.*)
    }
}
