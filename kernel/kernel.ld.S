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
    _start = .;
    __init_begin = .;
    .head.text : AT(ADDR(.head.text) - LOAD_OFFSET) {
        KEEP(*(.head.text))
    }
    . = ALIGN(PAGE_SIZE);
    .init.text : AT(ADDR(.init.text) - LOAD_OFFSET) {
        _sinittext = .;
        *(.init.text .init.text.*)
        *(.text.startup)
        _einittext = .;
    }
    .init.data : AT(ADDR(.init.data) - LOAD_OFFSET) {
        *(.init.rodata .init.rodata.*)
        . = ALIGN(16);
        __setup_start = .;
        KEEP(*(.init.setup))
        __setup_end = .;
        . = ALIGN(4);
        __initramfs_start = .;
        KEEP(*(.init.ramfs))
        . = ALIGN(8);
        KEEP(*(.init.ramfs.info))
    }
    __init_end = .;

    .text : {
        _text = .;
        _stext = .;
        . = ALIGN(8);
        *(.text .text.fixup)
        *(.ref.text)
        *(.fixup)
        _etext = .;
    }

    /* Start of data section */
    _sdata = .;
    . = ALIGN((L1_CACHE_BYTES));
    .rodata : AT(ADDR(.rodata) - LOAD_OFFSET) {
        __start_rodata = .;
        *(.rodata) *(.rodata.*)
    }
    .srodata : {
        *(.srodata*)
    }

    . = ALIGN(PAGE_SIZE);
    .data : AT(ADDR(.data) - LOAD_OFFSET) {
        *(.data)
    }
    .sdata : {
        __global_pointer$ = . + 0x800;
        *(.sdata*)
        /* End of data section */
        _edata = .;
        *(.sbss*)
    }

    __bss_start = .;
    .bss : AT(ADDR(.bss) - LOAD_OFFSET) {
        *(.bss..page_aligned)
        *(.dynbss)
        *(.bss)
        *(COMMON)
    }
    __bss_stop = .;

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
