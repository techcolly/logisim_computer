;--------------------------> start of constants

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

    UNAUTHORIZED_READ = 0xa0
    UNAUTHORIZED_WRITE = 0xa1

    KERNEL_PANIC = 0xee  
}

#const pgrm_start_addrs = struct { ;---> this is for the kernel to know where to load the terminal to in memory
    terminal = struct {
        hi2_bits = 0b10
        lo8_bits = 0x04b
        ;literal value ---> 0x1d8
        table_addr = 0x051
    }
}

#const term_addrs = struct { ;---> this is for the terminal only, the kernel doesn't care about this

    string_pointers = struct {

        prompt = 0x100
        error_template = 0x102

        cmds = struct {
            c = 0x105
            r = 0x107
            pm = 0x109
            psh = 0x10c
            pop = 0x110
            s = 0x114
            l = 0x116
            rs = 0x118
            ra = 0x11b
            ec = 0x11e
        }

        argp = struct { ;---> argument pointers
            argp1 = 0x2a0
            argp2 = 0x2a1
            argp3 = 0x2a2
            argp4 = 0x2a3
            argp_mem_block = 0x2af
        }

    }

    buffer_start = 0x150
    buffer_end = 0x170
}

#const general_addresses = struct {
    FLAG = 0x060
    
    error_information = 0x1ff

    save_register_0 = 0x200
    save_register_1 = 0x201
    save_register_2 = 0x202
    save_register_3 = 0x203
    save_register_4 = 0x204
    save_register_5 = 0x205
    save_register_6 = 0x206
    save_register_7 = 0x207

    hex_table_start = 0x210
}

;--------------------------> end of constants


;-------------------------------------------> start of opcodes, mneumonics, rules for the assembler

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
    INT_RET         => 0b110 ;---> this doesn't do anything
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

    ;---------------> end of opcodes, mneumonics, rules for the assembler
    
    ;-----------------> start of alternate versions of certain opcodes (for assembler)

    rar r{reg_dest_a}, {id}                             => 0b01011 @ reg_dest_a`3 @id`3 @ 0b00000 @ 0b00000000
    rsr r{reg_dest_a}, {id}                             => 0b01110 @ reg_dest_a`3 @id`3 @ 0b00000 @ 0b00000000 ; reg dest is main, reg source is special

    ;-----------------> end of alternate versions of certain opcodes

    ;------------------------------------> aliases and macros below

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

    jult [{imm10}] => asm {
        joci ult [{imm10}]
    }

    jc [{imm10}] => asm {
        joci uge [{imm10}]
    }

    syscall {id} => asm {
        ldi r0, {id}
        syscall
    }

    getc() => asm {
        ld r0, [mmio.KBD_GET_CHAR]
    }

    putc() => asm {
        pop r0
        st [mmio.TERM_PUT_CHAR], r0
    }

    push_and_store({hi2}, {lo8}, {value}) => asm { ;----> will clobber r1
            ldi r1, {hi2} ;----> hi2
            push r1
            ldi r1, {lo8} ;----> lo8
            push r1
            ldi r1, {value} ;----> value
            push r1
            syscall k_services.store8
    }

    push_and_store_reg({hi2}, {lo8}, r{reg_num}) => asm { ;----> will clobber r0
            ldi r0, {hi2} ;----> hi2
            push r0
            ldi r0, {lo8} ;----> lo8
            push r0
            mov r0, r{reg_num} ;----> value
            push r0
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

    deref_argp_hi2() => asm {
        ldi r3, 0b10
        push r3 ;---> hi2
        ldi r3, term_addrs.string_pointers.argp.argp_mem_block - 0x200
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