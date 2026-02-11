;--------------------------> start of constants

;//////////////////////////// ---> <mmio addresses>
#const IO_KBD_CLR = 0x3ff
#const IO_KBD_AVAIL = 0x3fe
#const IO_KBD_GETC = 0x3fd
#const IO_TERM_PUTC = 0x3fc
#const IO_TERM_CLR = 0x3fb
#const IO_ENTER_ACTIVE = 0x3fa
#const IO_ENTER_CLR = 0x3f9
;//////////////////////////// ---> </mmio addresses>

;//////////////////////////// ---> <general kernel addresses>
#const SYS_TBL_STRT = 0x041
;//////////////////////////// ---> </general kernel addresses>

;//////////////////////////// ---> <syscall ids>
#const SYS_GETC = 0
#const SYS_PUTC = 1
#const SYS_PUTHEX8 = 2
#const SYS_PUTS = 3
#const SYS_READLINE = 4
#const SYS_CLS = 5
#const SYS_STORE8 = 6
#const SYS_LOAD8 = 7
#const SYS_CMP_STR = 8
#const SYS_SAVE_REGS = 9
#const SYS_ASCII_2HEX = 10
;//////////////////////////// ---> </syscall ids>

;//////////////////////////// ---> <program start addresses>
#const TERM_STRT_HI2 = 0b10
#const TERM_STRT_LO8 = 0x050
#const TERM_STRT_TBL_ADDR = 0x051
;//////////////////////////// ---> </program start addresses>

;//////////////////////////// ---> <errors>
#const ERR_INVAL_CMD = 0x01
#const ERR_INVAL_HEXC = 0x02
#const SYS_ERR_UNAUTH_READ = 0xa0
#const SYS_ERR_UNAUTH_WRITE = 0xa1
#const SYS_ERR_KRNL_PANIC = 0xee
;//////////////////////////// ---> </errors>

;//////////////////////////// ---> <terminal addresses>
#const T_PROMPT = 0x100
#const T_ERR_TMPLATE = 0x102
#const T_CMD_C = 0x105
#const T_CMD_R = 0x107
#const T_CMD_PM = 0x109
#const T_CMD_PSH = 0x10c
#const T_CMD_POP = 0x110
#const T_CMD_S = 0x114
#const T_CMD_L = 0x116
#const T_CMD_RS = 0x118
#const T_CMD_RA = 0x11b
#const T_CMD_EC = 0x11e
#const T_BUF_START = 0x150
#const T_BUF_END = 0x170
#const T_ARGP_1 = 0x2a0
#const T_ARGP_2 = 0x2a1
#const T_ARGP_3 = 0x2a2
#const T_ARGP_4 = 0x2a3
#const T_ARGP_HI2 = 0x2af
;//////////////////////////// ---> </terminal addresses>

;//////////////////////////// ---> <general addresses>
#const FLAG = 0x060
#const INFO_ERR = 0x1ff
#const SV_REG_0 = 0x200
#const SV_REG_1 = 0x201
#const SV_REG_2 = 0x202
#const SV_REG_3 = 0x203
#const SV_REG_4 = 0x204
#const SV_REG_5 = 0x205
#const SV_REG_6 = 0x206
#const SV_REG_7 = 0x207
#const HEX_TBL = 0x210
;//////////////////////////// ---> </general addresses>


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
    callr [r{addr_source_b}]                            => 0b11011 @ 0b000 @ addr_source_b`3 @ 0b100 @ 0b0000000000
    ret                                                 => 0b11100 @ 0b000 @ 0b000 @ 0b000 @ 0b0000000000
    cim {imm8}                                          => 0b11101 @ 0b000 @ 0b000 @ 0b00000 @ imm8`8 ;can be either 0 or 1 
    syscall                                             => 0b11110 @ 0b000 @ 0b000 @ 0b00000 @ 0b00000000  
    sysret                                              => 0b11111 @ 0b000 @ 0b000 @ 0b00000 @ 0b00000000 

    *_copy_stop                                         => 0xffffff ;not really an instruction, disables copy mode via hardware only | the CPU will execute this but it does nothing   

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
        ldi         r0, {id}
        syscall
    }

    %__krnl_getc => asm {
        ld          r0, [IO_KBD_GETC]
    }

    %__krnl_putc => asm {
        pop         r0
        st          [IO_TERM_PUTC], r0
    }

    %std_store hi({hi2}), lo({lo8}), {value} => asm { ;----> will clobber r1
        ldi         r1, {hi2} ;----> hi2
        push        r1
        ldi         r1, {lo8} ;----> lo8
        push        r1
        ldi         r1, {value} ;----> value
        push        r1
        syscall     SYS_STORE8
    }

    %printc {char}, @r{reg_num} => asm {
        ldi         r{reg_num}, {char}
        push        r{reg_num}
        syscall     SYS_PUTC
    }

    %deref_arg arg{arg_num} => asm { ;---> gets argp value which is a pointer to a string in RAM, clobbers r0,r1, TWO_TMP
        ;---> puts lo8 in r0
        ldi         r3, T_ARGP_{arg_num} - 0x200 ;---> pointer to another pointer for the argument string
        ldi         r1, 0b10 ;---> lives in memory area 0x2XX so hi2 bits should be 0b10
        push        r1 ;---> hi2
        push        r3 ;---> lo8
        syscall     SYS_LOAD8
    }

    %deref_argp_hi2 => asm {
        ldi         r3, 0b10
        push        r3 ;---> hi2
        ldi         r3, T_ARGP_HI2 - 0x200
        push        r3 ;---> lo8
        syscall     SYS_LOAD8
    }
    ;-------------------------------------------------------------------------------------> kernel functions

    %__krnl_printc {char}, @r{reg_num} => asm {
        ldi         r{reg_num}, {char}
        st          [IO_TERM_PUTC], r{reg_num}
    }

    %__krnl_store addr({address}), {value}, @r{reg_num} => asm  {
        ldi         r{reg_num}, {value}
        st          [{address}], r{reg_num}
    }
    
    ;----------------------------------------------> all caps aliases/functions for very important stuff

    !___INSTRUCTION_MODE {imode} => asm {
        cim         {imode}
    }

    !___INITIALIZE_STACK_POINTER => asm {
        isp
    }

    !___COPY_MODE {params} => asm {
        ldi         r0, {params}
        wsr         COPY_MODE, r0
    }

    !___COPY_MODE_REG r{num} => asm {
        wsr         COPY_MODE, r{num}
    }

}