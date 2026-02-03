#const mmio = struct {
    KBD_CLEAR = 0x3ff
    KBD_AVAIL = 0x3fe
    KBD_GET_CHAR = 0x3fd
    TERM_PUT_CHAR = 0x3fc
    TERM_CLR = 0x3fb
    ENTER_ACTIVE = 0x3fa
    ENTER_CLEAR = 0x3f9
}

#const k_addrs = struct {
    K_BUFFER_START = 0x20
    K_BUFFER_END = 0x40
    FLAG = 0x60
}

#const k_services = struct { ;---> note that these are memory addresses also
    getc = 0x41
    putc = 0x42
    puthex8 = 0x43
    puts = 0x44
    readline = 0x45
    cls = 0x46
    store8 = 0x47
    load8 = 0x48
    cmp_strings = 0x49
    save_regs = 0x4a
    ascii_to_hex = 0x4b
}

#const errors = struct {
    INVALID_COMMAND = 0x01
    INVALID_HEX_CHAR = 0x02  
}

#const pgrm_start_addrs = struct {
    terminal = struct {
        hi2_bits = 0b01
        lo8_bits = 0x0c5
        
        ;literal value ---> 0x173

        table_addr = 0x051
    }
}

#const general_addresses = struct {
    hex_table_start = 0x250
}

#bankdef initial
{
    bits = 24
    addr = 0x0
    size = 0x2000 ; was 0x20 before
    outp = 24*0x0  
}

#subruledef cond_codes {
    neg => 0b0000
    pos => 0b0001
    ze => 0b0010
    eq => 0b0010
    nze => 0b0011
    neq => 0b0011
    uge => 0b0100
    ult => 0b0101
    ov => 0b0110
    nov => 0b0111
    ugt => 0b1000
    ule => 0b1001
    sge => 0b1010
    slt => 0b1011
    sgt => 0b1100
    sle => 0b1101
    un => 0b1110
}

#subruledef special_codes {
    FLAGS       => 0b000
    SHIFT_AMT   => 0b001
    TWO_TMP     => 0b010
    TST_LED     => 0b011
    COPY_MODE   => 0b100
    ERR_INFO    => 0b101
    PGRM_START_ADDR     => 0b110
}

#subruledef addr_special_codes {
    PC              => 0b000
    SP              => 0b001
    CSP             => 0b010
    C_R             => 0b011
    PGRM_START      => 0b100
    SYSRET          => 0b101
    INT_RET         => 0b110
}

#ruledef {
    add r{reg_dest_a}, r{reg_source_b}                  => 0b00000 @ reg_dest_a`3 @ reg_source_b`3 @ 0b00000 @ 0b00000000
    sub r{reg_dest_a}, r{reg_source_b}                  => 0b00001 @ reg_dest_a`3 @ reg_source_b`3 @ 0b00000 @ 0b00000000
    shl r{reg_dest_a}                                   => 0b00010 @ reg_dest_a`3 @ 0b000          @ 0b00000 @ 0b00000000
    shr r{reg_dest_a}                                   => 0b00011 @ reg_dest_a`3 @ 0b000          @ 0b00000 @ 0b00000000
    and r{reg_dest_a}, r{reg_source_b}                  => 0b00100 @ reg_dest_a`3 @ reg_source_b`3 @ 0b00000 @ 0b00000000
    or  r{reg_dest_a}, r{reg_source_b}                  => 0b00101 @ reg_dest_a`3 @ reg_source_b`3 @ 0b00000 @ 0b00000000
    xor r{reg_dest_a}, r{reg_source_b}                  => 0b00110 @ reg_dest_a`3 @ reg_source_b`3 @ 0b00000 @ 0b00000000

    intret                                              => 0b00111 @ 0b000       @ 0b000           @ 0b00000 @ 0b00000000
    mov r{reg_dest_a}, r{reg_source_b}                  => 0b01000 @ reg_dest_a`3 @ reg_source_b`3 @ 0b00000 @ 0b00000000
    ldi r{reg_dest_a}, {imm8}                           => 0b01001 @ reg_dest_a`3 @ 0b000          @ 0b00000 @ imm8`8
    nop                                                 => 0b01010 @ 0b000       @ 0b000           @ 0b00000 @ 0b00000000

    rar r{reg_dest_a}, {addr_src_b: addr_special_codes} => 0b01011 @ reg_dest_a`3 @addr_src_b`3 @ 0b00000 @ 0b00000000
    adc r{reg_dest_a}, r{reg_source_b}                  => 0b01100 @ reg_dest_a`3 @ reg_source_b`3 @ 0b00000 @ 0b00000000
    sbc r{reg_dest_a}, r{reg_source_b}                  => 0b01101 @ reg_dest_a`3 @ reg_source_b`3 @ 0b00000 @ 0b00000000
    rsr r{reg_dest_a}, {src_b: special_codes}           => 0b01110 @ reg_dest_a`3 @ src_b`3 @ 0b00000 @ 0b00000000 ; reg dest is main, reg source is special
    wsr {dst_a: special_codes}, r{reg_source_b}         => 0b01111 @ dst_a`3 @ reg_source_b`3 @ 0b00000 @ 0b00000000 ; reg dest is special, reg source is main

    halt                                                => 0b10000 @ 0b000       @ 0b000           @ 0b00000 @ 0b00000000

    joci {condition: cond_codes} [{imm10}]              => 0b10001 @ 0b0 @ 0b000            @ 0b0 @ condition`4 @ imm10`10
    jocr {condition: cond_codes} [r{reg_source_a}]      => 0b10001 @ 0b1 @ reg_source_a`3 @ 0b0 @ condition`4 @ 0b0000000000

    jroci {condition: cond_codes} [{imm10}]             => 0b10010 @ 0b0 @ 0b000            @ 0b0 @ condition`4 @ imm10`10
    jrocr {condition: cond_codes} [r{reg_source_a}]     => 0b10010 @ 0b1 @ reg_source_a`3 @ 0b0 @ condition`4 @ 0b0000000000

    cmp r{register_a}, r{register_b}                    => 0b10011 @ register_a`3 @ register_b`3 @ 0b00000 @ 0b00000000
    ld r{reg_dest_a}, [{imm10_addr}]                    => 0b10100 @ reg_dest_a`3 @ 0b000000 @ imm10_addr`10
    st [{imm10_addr}], r{reg_source_b}                  => 0b10101 @ 0b000 @ reg_source_b`3 @ 0b000 @ imm10_addr`10
    ldr r{reg_dest_a}, [r{addr_source_b}]               => 0b10110 @ reg_dest_a`3 @ addr_source_b`3 @ 0b0000000000000
    str [r{addr_source_b}], r{reg_source_a}             => 0b10111 @ reg_source_a`3 @ addr_source_b`3 @ 0b0000000000000
    isp                                                 => 0b11000 @ 0b000000000 @ 0b1111000000
    push r{reg_source_b}                                => 0b11001 @ 0b000 @ reg_source_b`3 @ 0b0000000000000
    pop r{reg_dest_a}                                   => 0b11010 @ reg_dest_a`3 @ 0b000 @ 0b0000000000000
    call [{imm10_addr}]                                 => 0b11011 @ 0b000 @ 0b000 @ 0b000 @ imm10_addr`10
    regcall [r{addr_source_b}]                          => 0b11011 @ 0b000 @ addr_source_b`3 @ 0b100 @ 0b0000000000
    ret                                                 => 0b11100 @ 0b000 @ 0b000 @ 0b000 @ 0b0000000000
    cim {imm8}                                          => 0b11101 @ 0b000 @ 0b000 @ 0b00000 @ imm8`8 ;can be either 0 or 1 
    syscall                                             => 0b11110 @ 0b000 @ 0b000 @ 0b00000 @ 0b00000000  
    sysret                                              => 0b11111 @ 0b000 @ 0b000 @ 0b00000 @ 0b00000000 

    copy_stop                                           => 0xffffff ;not really an instruction, disables copy mode via hardware only | the CPU will execute this but it does nothing   
                  
    ;-------------------------------------------------------------------------------------------------------------------------------------------------------- aliases

    jz [{imm10}] => asm {
        joci ze [{imm10}]
    }

    jnz [{imm10}] => asm {
        joci nze [{imm10}]
    }

    jmp [{imm10}] => asm {
        joci un [{imm10}]
    }

    juge [{imm10}] => asm {
        joci uge [{imm10}]
    }
    
    jc [{imm10}] => asm {
        joci uge [{imm10}]
    }
    
    syscall {id} => asm {
        ldi r0, {id}
        syscall
    }
    ;-------------------------------------------------------------------------------------------------------------------------------------------------------- mini functions

    getc() => asm {
        ld r0, [mmio.KBD_GET_CHAR]
    }

    putc() => asm {
        pop r0
        st [mmio.TERM_PUT_CHAR], r0
    }

    push_and_store({lo8}, {hi2}, {value}) => asm { ;----> will clobber r1
            ldi r1, {hi2} ;----> hi2
            push r1
            ldi r1, {lo8} ;----> lo8
            push r1
            ldi r1, {value} ;----> value
            push r1
            syscall k_services.store8
    }

    printc({char}, r{reg_num}) => asm {
        ldi r{reg_num}, {char}
        push r{reg_num}
        syscall k_services.putc
    }

    deref_argp(arg{arg_num}) => asm { ;---> gets argp value which is a pointer to a string in RAM, clobbers r0,r1, TWO_TMP
        ;---> puts lo8 in r0
        ldi r3, term_addrs.string_pointers.argp.argp{arg_num} - 0x200 ;---> pointer to another pointer for the argument string
        ldi r1, 0b10 ;---> lives in memory area 0x2XX so hi2 bits should be 0b10
        push r1 ;---> hi2
        push r3 ;---> lo8
        syscall k_services.load8
    }
    ;-------------------------------------------------------------------------------------> kernel functions
    __printc_no_syscall({char}, r{reg_num}) => asm {
        ldi r{reg_num}, {char}
        st [mmio.TERM_PUT_CHAR], r{reg_num}
    }

    __kernel_store({address}, {value}, r{reg_num}) => asm  {
        ldi r{reg_num}, {value}
        st [{address}], r{reg_num}
    }
    ;----------------------------------------------> all caps aliases/functions for very important stuff

    !SET_INSTRUCTION_MODE {imode} => asm {
        cim {imode}
    }

    !INITIALIZE_STACK_POINTER => asm {
        isp
    }

    !SET_COPY_MODE_PARAMS {params} => asm {
        ldi r0, {params}
        wsr COPY_MODE, r0
    }

    !SET_COPY_MODE_REG r{num} => asm {
        wsr COPY_MODE, r{num}
    }
}

;----------------------------> kernel/boot code starts here

kernel:
    on_boot:
        !SET_INSTRUCTION_MODE 0
        !INITIALIZE_STACK_POINTER
        .loading_txt:
            __printc_no_syscall("B", r0)
        .os_copy:
            !SET_COPY_MODE_PARAMS 0b0001
            .os_funcs:
                SYSCALL_HANDLER: ;---> service number will be in r0
                    ldi r1, 0
                    wsr TWO_TMP, r1
                    ldr r1, [r0]
                    regcall [r1]
                    sysret
                os_initialize:
                    !SET_INSTRUCTION_MODE 1
                    __printc_no_syscall("O", r0)
                    call [k_prepare_svcids]
                    call [k_prepare_pgrm_start_ids]
                    __printc_no_syscall("O", r0)
                    .write_flag:
                        __kernel_store(0x060, "F", r0)
                        __kernel_store(0x061, "L", r0)
                        __kernel_store(0x062, "A", r0)
                        __kernel_store(0x063, "G", r0)
                        __kernel_store(0x064, "{", r0)
                        __kernel_store(0x065, "3", r0)
                        __kernel_store(0x066, "e", r0)
                        __kernel_store(0x067, "c", r0)
                        __kernel_store(0x068, "8", r0)
                        __kernel_store(0x069, "}", r0)
                    .write_hex_table:
                        __kernel_store(0x250, "0", r0)
                        __kernel_store(0x251, "1", r0)
                        __kernel_store(0x252, "2", r0)
                        __kernel_store(0x253, "3", r0)
                        __kernel_store(0x254, "4", r0)
                        __kernel_store(0x255, "5", r0)
                        __kernel_store(0x256, "6", r0)
                        __kernel_store(0x257, "7", r0)
                        __kernel_store(0x258, "8", r0)
                        __kernel_store(0x259, "9", r0)
                        __kernel_store(0x25a, "a", r0)
                        __kernel_store(0x25b, "b", r0)
                        __kernel_store(0x25c, "c", r0)
                        __kernel_store(0x25d, "d", r0)
                        __kernel_store(0x25e, "e", r0)
                        __kernel_store(0x25f, "f", r0)
                    __printc_no_syscall("T", r0)
                    ldi r0, 1
                    push r0
                    jmp [load_rom]
                k_prepare_svcids:
                    ldi r0, k_getc
                    st [k_services.getc], r0
                    ldi r0, k_putc
                    st [k_services.putc], r0
                    ldi r0, k_puthex8
                    st [k_services.puthex8], r0
                    ldi r0, k_puts
                    st [k_services.puts], r0
                    ldi r0, k_readline
                    st [k_services.readline], r0
                    ldi r0, k_cls
                    st [k_services.cls], r0
                    ldi r0, k_store8
                    st [k_services.store8], r0
                    ldi r0, k_load8
                    st [k_services.load8], r0
                    ldi r0, k_cmp_strings
                    st [k_services.cmp_strings], r0
                    ldi r0, k_save_regs
                    st [k_services.save_regs], r0
                    ldi r0, k_ascii_to_hex
                    st [k_services.ascii_to_hex], r0
                    ret
                k_prepare_pgrm_start_ids:
                    ldi r0, pgrm_start_addrs.terminal.lo8_bits
                    st [pgrm_start_addrs.terminal.table_addr], r0
                    ret
                k_getc:
                    getc()
                    ret
                k_putc: ;---> takes one argument | ascii value of the character
                    putc()
                    ret
                k_puthex8: ;---> takes one argument | 8 bit value to convert to hexadecimal to print in console
                    pop r0
                    .seperate_4bits:
                        mov r1, r0
                        ldi r2, 0b00001111
                        and r0, r2
                        ldi r2, 0b11110000
                        and r1, r2
                        ldi r2, 0x04
                        wsr SHIFT_AMT, r2
                        shr r1
                        ldi r2, 0b10 ;---> setting hi2 bits
                        wsr TWO_TMP, r2
                    .fetch_char_from_table:
                        ldi r2, general_addresses.hex_table_start - 0x200
                        add r0, r2
                        ldr r0, [r0]
                        add r1, r2
                        ldr r1, [r1]
                    .printhex:
                        mov r2, r0
                        push r1
                        call [k_putc]
                        push r2
                        call [k_putc]
                    .cleanup:
                        ldi r2, 1
                        wsr SHIFT_AMT, r2
                    ret
                k__HELPER__a2h: ;---> not syscallable
                    ldi r1, 0 ;---> offset pointer
                    .check:
                        ldi r3, 16
                        cmp r1, r3
                        jz [.invalid]
                        ldi r2, general_addresses.hex_table_start - 0x200 ;---> main pointer
                        add r2, r1
                        ldr r3, [r2]
                        cmp r0, r3
                        jz [.char_found]
                        ldi r3, 1
                        add r1, r3
                        jmp [.check] 
                    .char_found:
                        push r1
                        ret
                    .invalid:
                        ldi r1, 0xff
                        ret
                k_ascii_to_hex: ;---> takes two arguments | (ascii_lo, ascii_hi), hex bit will be in r0
                    ldi r0, 0b10
                    wsr TWO_TMP, r0
                    pop r0 ;---> ascii_lo
                    st [0x200], r0 ;---> save for later
                    pop r0 ;---> ascii_hi
                    .get_hi:
                        call [k__HELPER__a2h] ;---> ascii_hi converted version pushed
                        ..hi_check:
                            ldi r2, 0xff
                            cmp r2, r1
                            jz [.invalid_return]
                    .get_lo:
                        ld r0, [0x200]
                        call [k__HELPER__a2h] ;---> ascii_lo converted version pushed
                        ..lo_check:
                            ldi r2, 0xff
                            cmp r2, r1
                            jz [.invalid_return]
                    ldi r0, 4
                    wsr SHIFT_AMT, r0
                    .convert:
                        pop r1 ;---> ascii_lo
                        pop r0 ;---> ascii_hi
                        shl r0 ;---> hex = (hi << 4) + low
                        add r0, r1
                    .cleanup:
                        ldi r1, 1
                        wsr SHIFT_AMT, r1
                        ret
                    .invalid_return:
                        ldi r0, errors.INVALID_HEX_CHAR
                        wsr ERR_INFO, r0
                        ret
                k_puts: ;---> takes two arguments | pointer into RAM for the string, lo8 and hi2
                    pop r0 ;---> low 8 bits
                    pop r1 ;---> high 2 bits
                    wsr TWO_TMP, r1 ;---> do not give a pointer that will overflow or we'll be in big trouble
                    .printing:
                        ldr r1, [r0]
                        ldi r2, 0
                        cmp r1, r2
                        jz [.print_end]
                        st [mmio.TERM_PUT_CHAR], r1
                        ldi r2, 1
                        add r0, r2
                        jmp [.printing]
                    .print_end:
                        ret
                k_cmp_strings: ;---> needs a syscall so that we can load from RAM directly & its not super slow
                    ;---> // needs 2 arguments, lo8 bits of s1 pointer, lo8 bits of s2 pointer, hi2 bits will be 0b01             
                    pop r0 ;---> lo8 bits of s1 pointer
                    pop r1 ;---> lo8 bits of s2 pointer
                    ldi r2, 1
                    wsr TWO_TMP, r2
                    .cmp_loop:
                        ldr r2, [r0]
                        ldr r3, [r1]
                        cmp r2, r3
                        jnz [..strings_different]
                        ..null_check:
                            ldi r4, 0
                            cmp r2, r4
                            jnz [..continue]
                            ...first_char_zero:
                                cmp r3, r4
                                jz [..strings_same]
                                jmp [..continue]
                        ..continue:
                            ldi r2, 1
                            add r0, r2
                            add r1, r2
                            jmp [.cmp_loop]
                        ..strings_different:
                            ldi r0, 1
                            ret
                        ..strings_same:
                            ldi r0, 0
                            ret
                k_readline: ;---> obsolete don't call this
                    ret
                k_cls:
                    ldi r0, 1
                    st [mmio.TERM_CLR], r0
                    ret
                k_store8: ;---> takes three arguments | (value, lo8, hi2)
                    pop r0 ;---> value
                    pop r1 ;---> lo8
                    pop r2 ;---> hi2
                    wsr TWO_TMP, r2
                    str [r1], r0
                    ret
                k_load8: ;---> takes two arguments | (lo8, hi2)
                    pop r1 ;---> lo8
                    pop r0 ;---> hi2
                    wsr TWO_TMP, r0
                    ldr r0, [r1]
                    ret
                k_save_regs: ;---> needs r0 on stack
                    pop r0
                    st [0x200], r0
                    st [0x201], r1
                    st [0x202], r2
                    st [0x203], r3
                    st [0x204], r4
                    st [0x205], r5
                    st [0x206], r6
                    st [0x207], r7
                    ret
                k_panic: 
                    isp ;---> this needs to do more later 
                load_rom: ;---> takes one argument | the rom id to load //// note this has to be the final os function so we don't need to jump to other addresses // only jump to this address do not call it
                    pop r0
                    ldi r1, 0x050
                    add r1, r0
                    ldi r2, 0
                    wsr TWO_TMP, r2
                    ldr r2, [r1]
                    ldi r1, pgrm_start_addrs.terminal.hi2_bits
                    wsr TWO_TMP, r1
                    wsr PGRM_START_ADDR, r2
                    shl r0
                    ldi r1, 1
                    add r0, r1
                    !SET_COPY_MODE_REG r0           
        .copy_stop:
            copy_stop
        .intitalize:
            jmp [os_initialize]
