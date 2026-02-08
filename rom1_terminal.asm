#include "rules_and_constants.asm"

;-----------------------------------------> ignore this
#bankdef terminal
{
    bits = 24
    addr = 0x113
    size = 0x2000
    outp = 24*0x113  
}
;-----------------------------------------> ignore this

;---> terminal code starts below
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
                ldi r0, term_addrs.string_pointers.error_template - 0x100 ;---> low 8 bits of prompt for terminal
                ldi r1, 0b01
                push r1 ;---> hi2
                push r0 ;---> lo8
                syscall k_services.puts
                push r4
                syscall k_services.puthex8
                printc("\n", r0)
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
            error_handler:
                wsr ERR_INFO, r1
                push r1
                call [print_error]
                ret
                
        user_funcs:
            helper_arg_ascii_to_hex: ;---> result in r0, clobbers r0, r1, r2, r3
            ;---> assumes r4 is argp hi2, r7 is 1, r0 is arg lo8 already
                mov r2, r0
                push r4 ;---> hi2 (*arg)
                push r2 ;---> lo8 (*arg)
                syscall k_services.load8
                mov r3, r0 ;---> lo8 (**arg), first ascii value (hi)
                add r2, r7
                push r4
                push r2
                syscall k_services.load8
                mov r2, r0 ;---> lo8 (**arg), second ascii value (lo)
                push r3
                push r2
                syscall k_services.ascii_to_hex ;---> (**arg), hex value
                ret
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
                syscall k_services.puthex8 ;---> this pops the value and prints it already
                printc("\n", r0)
                call [print_prompt]
                ret
            psh:
                deref_argp_hi2()
                mov r4, r0
                ldi r7, 1

                deref_argp(arg1)
                call [helper_arg_ascii_to_hex]
                push r0
                call [print_prompt]
                ret
            ec: ;---> this one is a bit confusing
                deref_argp_hi2() 
                push r0 ;---> push hi2
                deref_argp(arg1)
                push r0 ;---> push lo8
                syscall k_services.puts
                printc("\n", r0)
                call [print_prompt]
                ret
            helper_rs:
                push r0
                syscall k_services.puthex8
                printc(" ", r0)
                ret
            rs:
                rsr r0, FLAGS
                call [helper_rs]
                rsr r0, SHIFT_AMT
                call [helper_rs]
                rsr r0, TWO_TMP
                call [helper_rs]
                rsr r0, TST_LED
                call [helper_rs]
                rsr r0, COPY_MODE
                call [helper_rs]
                rsr r0, ERR_INFO
                call [helper_rs]
                printc("\n", r0)
                call [print_prompt]
                ret
            helper_ra:
                rsr r1, TWO_TMP
                push r1
                syscall k_services.puthex8
                push r3
                syscall k_services.puthex8
                printc(" ", r0)
                ret
            ra:
                rar r3, PC
                call [helper_ra]
                rar r3, SP
                call [helper_ra]
                rar r3, CSP
                call [helper_ra]
                rar r3, C_R
                call [helper_ra]
                rar r3, PGRM_START
                call [helper_ra]
                rar r3, SYSRET
                call [helper_ra]
                rar r3, INT_RET
                call [helper_ra]
                printc("\n", r0)
                call [print_prompt]
                ret
            s:
                deref_argp_hi2() ;---> hi2 (of all arg pointers) in r0
                mov r4, r0
                ldi r7, 1

                deref_argp(arg1) ;---> lo8 (of arg1 string pointer) in r0
                call [helper_arg_ascii_to_hex]
                mov r5, r0 ;---> address hi2

                deref_argp(arg2) ;---> lo8 (of arg2 string pointer) in r0
                call [helper_arg_ascii_to_hex]
                mov r6, r0 ;---> address lo8

                deref_argp(arg3) ;---> lo8 (of arg3 string pointer) in r0
                call [helper_arg_ascii_to_hex]
                mov r7, r0 ;---> value to store

                push r5
                push r6
                push r7
                syscall k_services.store8
    
                call [print_prompt]
                ret
            l:
                deref_argp_hi2()
                mov r4, r0
                ldi r7, 1

                deref_argp(arg1)
                call [helper_arg_ascii_to_hex]
                mov r5, r0

                deref_argp(arg2)
                call [helper_arg_ascii_to_hex]
                mov r6, r0

                push r5
                push r6

                syscall k_services.load8

                push r0
                syscall k_services.puthex8

                printc("\n", r0)

                call [print_prompt]

                ret
    .load_strings:
        .prompt:
            push_and_store(0b01, 0x00, ">")
            push_and_store(0b01, 0x01, "\0")
        .error_template:
            push_and_store(0b01, 0x02, "E")
            push_and_store(0b01, 0x03, ":")
            push_and_store(0b01, 0x04, "\0")
        .commands:
            ..c: ;---> clear screen
                push_and_store(0b01, 0x05, "c")
                push_and_store(0b01, 0x06, "\0")
            ..r: ;---> print registers
                push_and_store(0b01, 0x07, "r")
                push_and_store(0b01, 0x08, "\0")
            ..pm: ;---> dump program memory
                push_and_store(0b01, 0x09, "p")
                push_and_store(0b01, 0x0a, "m")
                push_and_store(0b01, 0x0b, "\0")
            ..psh: ;---> push value onto stack
                push_and_store(0b01, 0x0c, "p")
                push_and_store(0b01, 0x0d, "s") 
                push_and_store(0b01, 0x0e, "h")
                push_and_store(0b01, 0x0f, "\0")
            ..pop: ;---> pop value off of stack
                push_and_store(0b01, 0x10, "p")
                push_and_store(0b01, 0x11, "o")
                push_and_store(0b01, 0x12, "p") 
                push_and_store(0b01, 0x13, "\0")
            ..s: ;---> store value to memory
                push_and_store(0b01, 0x14, "s")
                push_and_store(0b01, 0x15, "\0")
            ..l: ;---> look at value in memory
                push_and_store(0b01, 0x16, "l")
                push_and_store(0b01, 0x17, "\0")
            ..rs: ;---> read special (register)
                push_and_store(0b01, 0x18, "r")
                push_and_store(0b01, 0x19, "s")
                push_and_store(0b01, 0x1a, "\0")
            ..ra: ;---> read address (register)
                push_and_store(0b01, 0x1b, "r")
                push_and_store(0b01, 0x1c, "a")
                push_and_store(0b01, 0x1d, "\0")
            ..ec: ;---> echo input back to user
                push_and_store(0b01, 0x1e, "e")
                push_and_store(0b01, 0x1f, "c")
                push_and_store(0b01, 0x20, "\0")
    main:
        .store_hi2_bits_of_arguments:
            push_and_store(0b10, 0xaf, 1)
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

                .pm_handler:
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
                    jnz [.check_if_ra]

                .rs_handler:
                            call [rs]
                            call [clear_buffer]
                            jmp [.main_loop]

                .check_if_ra:
                    ldi r1, term_addrs.string_pointers.cmds.ra - 0x100
                    call [cmd_match_check_helper]
                    jnz [.check_if_l]

                .ra_handler:
                            call [ra]
                            call [clear_buffer]
                            jmp [.main_loop]

                .check_if_l:
                    ldi r1, term_addrs.string_pointers.cmds.l - 0x100
                    call [cmd_match_check_helper]
                    jnz [.check_if_s]

                .l_handler:
                            call [l]
                            call [clear_buffer]
                            jmp [.main_loop]

                .check_if_s:
                    ldi r1, term_addrs.string_pointers.cmds.s - 0x100
                    call [cmd_match_check_helper]
                    jnz [.invalid_command_handler]

                .s_handler:
                            call [s]
                            call [clear_buffer]
                            jmp [.main_loop]

                .invalid_command_handler:
                    ldi r1, errors.INVALID_COMMAND
                    call [error_handler]
                    call [print_prompt]
                    call [clear_buffer]
                    jmp [.main_loop]

    end_copy:
        copy_stop

