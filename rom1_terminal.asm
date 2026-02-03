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
}

#const term_addrs = struct {

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
        }

    }

    buffer_start = 0x150
    buffer_end = 0x170
}

#const general_addresses = struct {
    hex_table_start = 0x250
}

#bankdef terminal
{
    bits = 24
    addr = 0x0f5
    size = 0x2000 ; was 0x20 before
    outp = 24*0x0f5  
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

    joci {condition: cond_codes} [{imm10}]                => 0b10001 @ 0b0 @ 0b000            @ 0b0 @ condition`4 @ imm10`10
    jocr {condition: cond_codes} [r{reg_source_a}]      => 0b10001 @ 0b1 @ reg_source_a`3 @ 0b0 @ condition`4 @ 0b0000000000

    jroci {condition: cond_codes} [{imm10}]               => 0b10010 @ 0b0 @ 0b000            @ 0b0 @ condition`4 @ imm10`10
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

    push_and_store_reg({lo8}, {hi2}, r{reg_num}) => asm { ;----> will clobber r0
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

    ;-------------------------------------------------------------------------------------> kernel functions

    __printc_no_syscall({char}, r{reg_num}) => asm {
        ldi r{reg_num}, {char}
        st [mmio.TERM_PUT_CHAR], r{reg_num}
    }

}

terminal:
    funcs:
        control_funcs:
            print_prompt:
                ldi r0, term_addrs.string_pointers.prompt - 0x100 ;---> low 8 bits of prompt for terminal
                ldi r1, 0b01
                push r1
                push r0
                syscall k_services.puts
                ret
            print_error: ;---> error code must be on the stack
                pop r4
                wsr ERR_INFO, r4
                ldi r0, term_addrs.string_pointers.error_template - 0x100 ;---> low 8 bits of prompt for terminal
                ldi r1, 0b01
                push r1 ;---> hi2
                push r0 ;---> lo8
                syscall k_services.puts
                push r4
                syscall k_services.puthex8
                ret
            clear_buffer:
                ldi r4, 0
                ldi r5, 1
                ldi r7, term_addrs.buffer_start - 0x100
                ldi r6, term_addrs.buffer_end - 0x100

                .clearing:
                    push r5 ;---> hi2
                    push r7 ;---> lo8
                    push r4 ;---> value
                    syscall k_services.store8

                    cmp r7, r6
                    jz [.clear_done]

                    add r7, r5
                    jmp [.clearing]

                .clear_done:
                    ldi r7, term_addrs.buffer_start - 0x100
                    ret
            cmd_match_check_helper:
                    ldi r7, term_addrs.buffer_start - 0x100
                    push r1
                    push r7
                    syscall k_services.cmp_strings
                    ldi r2, 0
                    cmp r0, r2
                    ret

        user_funcs:
            c:
                syscall k_services.cls
                call [print_prompt]
                ret
            r:
                syscall k_services.save_regs
                ldi r7, 0b10 
                ldi r6, 0
                ldi r5, 1
                ldi r4, 8
                .print_regs:
                    push r7 ;---> hi2
                    push r6 ;---> lo8
                    syscall k_services.load8
                    push r0
                    syscall k_services.puthex8
                    printc(" ", r3)
                    add r6, r5
                    cmp r4, r6
                    jnz [.print_regs]

                .printing_done:
                    printc("\n", r0)
                    call [print_prompt]
                    ret
            pm:
                ldi r7, 0x00 ;---> pointer to program memory, lo8 bits
                ldi r6, 1  ;---> pointer to program memory, hi2 bits
                ldi r4, 1 ;---> will increment the pointer by this much

                .pmemd_loop:
                    push r6 ;---> hi2
                    push r7 ;---> lo8
                    syscall k_services.load8
                    mov r2, r0
                    push r2
                    syscall k_services.puthex8
                    ..check_if_newline_needed:
                        ldi r5, 0b00011111
                        and r5, r7
                        ldi r0, 0b00011111
                        cmp r5, r0
                        jnz [..space]
                        ...newline:
                            printc("\n", r1)
                            jmp [..continue]
                        ..space:
                            printc(" ", r1)
                    ..continue:
                        add r7, r4
                    ..bounds_check:
                        jc [..are_we_finished]
                        jmp [.pmemd_loop]
                            ..are_we_finished:
                                ldi r5, 0b10
                                cmp r6, r5
                                jnz [...need_pointer_inc]
                                ...finished:
                                    printc("\n", r0)
                                    call [r] ;---> r prints the prompt
                                    ret
                                ...need_pointer_inc:
                                    add r6, r4
                                    jmp [.pmemd_loop]
            pop:
                pop r0 ;---> we just print and pop the first value on the stack
                call [print_prompt]
                ret
            psh:
                deref_argp(arg1) ;---> dereference argp pointer to get string pointer
                ;---> lo8 in r0
                ldi r4, 0b01 ;---> hi2
                mov r5, r0 ;---> copy lo8 to r5 as it will get clobbered
                push r4 ;---> hi2
                push r5 ;---> lo8
                syscall k_services.load8
                mov r6, r0 ;---> move first part of hex value to r6 (upper part)
                ldi r0, 1
                add r5, r0 ;---> advance pointer to string over by 1
                push r4
                push r5
                syscall k_services.load8
                mov r7, r0 ;---> move second part of hex value to r7 (lower part)
                push r6
                push r7
                syscall k_services.ascii_to_hex
                push r0
                call [print_prompt]
                ret
            ec: ;---> this one is a bit confusing
                deref_argp(arg1) ;---> lo8 in r0
                ldi r1, 0b01
                push r1 ;---> push hi2
                push r0 ;---> push lo8
                syscall k_services.puts
                printc("\n", r0)
                call [print_prompt]
                ret
            rs:
                rsr r0, FLAGS
                push r0
                syscall k_services.puthex8
                printc(" ", r0)
                rsr r0, SHIFT_AMT
                push r0
                syscall k_services.puthex8
                printc(" ", r0)
                rsr r0, TWO_TMP
                push r0
                syscall k_services.puthex8
                printc(" ", r0)
                rsr r0, TST_LED
                push r0
                syscall k_services.puthex8
                printc(" ", r0)
                rsr r0, COPY_MODE
                push r0
                syscall k_services.puthex8
                printc(" ", r0)
                rsr r0, ERR_INFO
                push r0
                syscall k_services.puthex8
                printc("\n", r0)
                call [print_prompt]
                ret

    .load_strings:
        .prompt:
            push_and_store(0x00, 0b01, ">")
            push_and_store(0x01, 0b01, "\0")
        .error_template:
            push_and_store(0x02, 0b01, "E")
            push_and_store(0x03, 0b01, ":")
            push_and_store(0x04, 0b01, "\0")
        .commands:
            ..c: ;---> clear screen
                push_and_store(0x05, 0b01, "c")
                push_and_store(0x06, 0b01, "\0")
            ..r: ;---> print registers
                push_and_store(0x07, 0b01, "r")
                push_and_store(0x08, 0b01, "\0")
            ..pm: ;---> dump program memory
                push_and_store(0x09, 0b01, "p")
                push_and_store(0x0a, 0b01, "m")
                push_and_store(0x0b, 0b01, "\0")
            ..psh: ;---> push value onto stack
                push_and_store(0x0c, 0b01, "p")
                push_and_store(0x0d, 0b01, "s") 
                push_and_store(0x0e, 0b01, "h")
                push_and_store(0x0f, 0b01, "\0")
            ..pop: ;---> pop value off of stack
                push_and_store(0x10, 0b01, "p")
                push_and_store(0x11, 0b01, "o")
                push_and_store(0x12, 0b01, "p") 
                push_and_store(0x13, 0b01, "\0")
            ..s: ;---> store value to memory
                push_and_store(0x14, 0b01, "s")
                push_and_store(0x15, 0b01, "\0")
            ..l: ;---> look at value in memory
                push_and_store(0x16, 0b01, "l")
                push_and_store(0x17, 0b01, "\0")
            ..rs: ;---> read special (register)
                push_and_store(0x18, 0b01, "r")
                push_and_store(0x19, 0b01, "s")
                push_and_store(0x1a, 0b01, "\0")
            ..ra: ;---> read address (register)
                push_and_store(0x1b, 0b01, "r")
                push_and_store(0x1c, 0b01, "a")
                push_and_store(0x1d, 0b01, "\0")
            ..ec: ;---> echo input back to user
                push_and_store(0x1e, 0b01, "e")
                push_and_store(0x1f, 0b01, "c")
                push_and_store(0x20, 0b01, "\0")
            
    main:
        syscall k_services.cls
        ldi r7, term_addrs.buffer_start - 0x100 ;----> lower 8 bits of buffer pointer
        call [print_prompt]
        .main_loop:
            syscall k_services.getc
            .null_check:
                ldi r1, "\0"
                cmp r0, r1
                jz [.main_loop]

            .backspace_check:
                ldi r1, 8 ;---> ascii code for backspace
                cmp r0, r1
                jz [.backspace_handler]

            .newline_check:
                ldi r1, "\n"
                cmp r0, r1
                jz [.newline_handler]
            
            .new_char_handler:
                .store_char:
                    ldi r1, 0b01 
                    mov r6, r0 ;---> copy of ascii value for later as it will be overwritten soon
                    push r1 ;----> hi2
                    push r7 ;----> lo8
                    push r0 ;----> value
                    syscall k_services.store8
                    ldi r0, 1
                    add r7, r0
                .echo_char:
                    push r6
                    syscall k_services.putc
                jmp [.main_loop]

            .backspace_handler:
                mov r6, r0 ;---> copy of ascii value for later
                ldi r1, 0b01
                sub r7, r1 ;---> move pointer backwards
                push r1 ;---> hi2
                push r7 ;---> lo8
                sub r1, r1 
                push r1 ;---> value (resetting to 0)
                syscall k_services.store8
                push r6 
                syscall k_services.putc ;---> echoing backspace character
                jmp [.main_loop]

            .newline_handler:
                push r0
                syscall k_services.putc 
                ldi r7, term_addrs.buffer_start - 0x100
                ldi r4, " "
                ldi r6, "\0"
                ldi r5, 1
                ldi r3, 0 ; ---> lo8 bits to be added to 0x2a0 for arg pointer

                ..test_for_command_end:
                    push r5 ;---> hi2
                    push r7 ;---> lo8
                    syscall k_services.load8
                    cmp r0, r4
                    jz [...is_a_space]
                        ...not_a_space:
                            add r7, r5
                            ....is_null:
                                cmp r0, r6
                                jz [.check_if_c]
                            jmp [..test_for_command_end]

                        ...is_a_space:
                            ldi r1, "\0"
                            push r5 ;---> hi2
                            push r7 ;---> lo8
                            push r1 ;---> value
                            syscall k_services.store8
                            add r7, r5
                            ldi r0, 0b10 ;---> hi2 (will be 0b10 always)
                            push r0 ;---> push it to stack
                            ldi r0, 0x0a0 ;---> lo8
                            add r0, r3 ;---> add arg counter to lo8 for next argument ptr
                            push r0 ;---> push lo8
                            ldi r0, 1
                            add r3, r0 ;---> increment pointer for arg counter
                            push r7 ;---> value
                            syscall k_services.store8
                            jmp [..test_for_command_end]
                
        ;---------------------------------------> command parsing starts here

                .check_if_c:
                    ldi r1, term_addrs.string_pointers.cmds.c - 0x100
                    call [cmd_match_check_helper]
                    jnz [.check_if_r]

                .c_handler:
                            call [c]
                            call [clear_buffer]
                            jmp [.main_loop]

                .check_if_r:
                    ldi r1, term_addrs.string_pointers.cmds.r - 0x100
                    call [cmd_match_check_helper]
                    jnz [.check_if_pm]

                .r_handler:
                            push r0
                            call [r]
                            call [clear_buffer]
                            jmp [.main_loop]

                .check_if_pm:
                    ldi r1, term_addrs.string_pointers.cmds.pm - 0x100
                    call [cmd_match_check_helper]
                    jnz [.check_if_pop]

                .pmemd_handler:
                            push r0
                            call [pm]
                            call [clear_buffer]
                            jmp [.main_loop]

                .check_if_pop:
                    ldi r1, term_addrs.string_pointers.cmds.pop - 0x100
                    call [cmd_match_check_helper]
                    jnz [.check_if_psh]

                .pop_handler:
                            call [pop]
                            call [clear_buffer]
                            jmp [.main_loop]

                .check_if_psh:
                    ldi r1, term_addrs.string_pointers.cmds.psh - 0x100
                    call [cmd_match_check_helper]
                    jnz [.check_if_ec]

                .psh_handler:
                            call [psh]
                            call [clear_buffer]
                            jmp [.main_loop]

                .check_if_ec:
                    ldi r1, term_addrs.string_pointers.cmds.ec - 0x100
                    call [cmd_match_check_helper]
                    jnz [.check_if_rs]

                .ec_handler:
                            call [ec]
                            call [clear_buffer]
                            jmp [.main_loop]

                .check_if_rs:
                    ldi r1, term_addrs.string_pointers.cmds.rs - 0x100
                    call [cmd_match_check_helper]
                    jnz [.invalid_command_handler]

                .rs_handler:
                            call [rs]
                            call [clear_buffer]
                            jmp [.main_loop]

                .invalid_command_handler:
                    ldi r0, errors.INVALID_COMMAND
                    wsr ERR_INFO, r0
                    push r0
                    call [print_error]
                    ldi r0, "\n"
                    push r0
                    syscall k_services.putc
                    call [print_prompt]
                    call [clear_buffer]
                    jmp [.main_loop]

    end_copy:
        copy_stop

