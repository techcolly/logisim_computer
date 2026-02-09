#include "rules_and_constants.asm"

;-----------------------------------------> ignore this
#bankdef kernel
{
    bits = 24
    addr = 0x0
    size = 0x2000
    outp = 24*0x0  
}
;-----------------------------------------> ignore this

;---> kernel code starts below
kernel:
    on_boot:

        !SET_INSTRUCTION_MODE 0
        !INITIALIZE_STACK_POINTER
        __printc_no_syscall("B", r0)

        .os_copy:
            !SET_COPY_MODE_PARAMS 0b0001

            .os_funcs: 

                SYSCALL_HANDLER: ;---> service number will be in r0
                
                    ldi                 r1, 0
                    wsr                 TWO_TMP, r1
                    ldi                 r1, 11
                    cmp                 r0, r1
                    juge                [k_panic]           ;panic if invalid id
                    ldi                 r1, 0x041
                    add                 r0, r1
                    ldr                 r1, [r0]
                    regcall             [r1]
                    sysret

                os_initialize:
                    !SET_INSTRUCTION_MODE 1
                    __printc_no_syscall("O", r0)

                    call                [k_prepare_svcids]
                    call                [k_prepare_pgrm_start_ids]
                    
                    __printc_no_syscall("O", r0)

                    .write_flag:
                        __kernel_store(general_addresses.FLAG + 0x000, "F", r0)
                        __kernel_store(general_addresses.FLAG + 0x001, "L", r0)
                        __kernel_store(general_addresses.FLAG + 0x002, "A", r0)
                        __kernel_store(general_addresses.FLAG + 0x003, "G", r0)
                        __kernel_store(general_addresses.FLAG + 0x004, "{", r0)
                        __kernel_store(general_addresses.FLAG + 0x005, "3", r0)
                        __kernel_store(general_addresses.FLAG + 0x006, "e", r0)
                        __kernel_store(general_addresses.FLAG + 0x007, "c", r0)
                        __kernel_store(general_addresses.FLAG + 0x008, "8", r0)
                        __kernel_store(general_addresses.FLAG + 0x009, "}", r0)
                    .write_hex_table:
                        __kernel_store(general_addresses.hex_table_start + 0x000, "0", r0)
                        __kernel_store(general_addresses.hex_table_start + 0x001, "1", r0)
                        __kernel_store(general_addresses.hex_table_start + 0x002, "2", r0)
                        __kernel_store(general_addresses.hex_table_start + 0x003, "3", r0)
                        __kernel_store(general_addresses.hex_table_start + 0x004, "4", r0)
                        __kernel_store(general_addresses.hex_table_start + 0x005, "5", r0)
                        __kernel_store(general_addresses.hex_table_start + 0x006, "6", r0)
                        __kernel_store(general_addresses.hex_table_start + 0x007, "7", r0)
                        __kernel_store(general_addresses.hex_table_start + 0x008, "8", r0)
                        __kernel_store(general_addresses.hex_table_start + 0x009, "9", r0)
                        __kernel_store(general_addresses.hex_table_start + 0x00a, "a", r0)
                        __kernel_store(general_addresses.hex_table_start + 0x00b, "b", r0)
                        __kernel_store(general_addresses.hex_table_start + 0x00c, "c", r0)
                        __kernel_store(general_addresses.hex_table_start + 0x00d, "d", r0)
                        __kernel_store(general_addresses.hex_table_start + 0x00e, "e", r0)
                        __kernel_store(general_addresses.hex_table_start + 0x00f, "f", r0)
                    __printc_no_syscall("T", r0)

                    ldi                 r0, 1
                    push                r0
                    jmp                 [__LOAD_ROM_FILE__]
                    
                k_prepare_svcids:
                    ldi                 r0, k_getc
                    st                  [k_services.getc + 0x041], r0
                    ldi                 r0, k_putc
                    st                  [k_services.putc + 0x041], r0
                    ldi                 r0, k_puthex8
                    st                  [k_services.puthex8 + 0x041], r0
                    ldi                 r0, k_puts
                    st                  [k_services.puts + 0x041], r0
                    ldi                 r0, k_readline
                    st                  [k_services.readline + 0x041], r0
                    ldi                 r0, k_cls
                    st                  [k_services.cls + 0x041], r0
                    ldi                 r0, k_store8
                    st                  [k_services.store8 + 0x041], r0
                    ldi                 r0, k_load8
                    st                  [k_services.load8 + 0x041], r0
                    ldi                 r0, k_cmp_strings
                    st                  [k_services.cmp_strings + 0x041], r0
                    ldi                 r0, k_save_regs
                    st                  [k_services.save_regs + 0x041], r0
                    ldi                 r0, k_ascii_to_hex
                    st                  [k_services.ascii_to_hex + 0x041], r0
                    ret

                k_prepare_pgrm_start_ids:
                    ldi                 r0, pgrm_start_addrs.terminal.lo8_bits
                    st                  [pgrm_start_addrs.terminal.table_addr], r0
                    ret

                k_getc:
                    getc()
                    ret

                k_putc: ;---> takes one argument | ascii value of the character
                    putc()
                    ret

                k_puthex8: ;---> takes one argument | 8 bit value to convert to hexadecimal to print in console
                    pop                 r0

                    .seperate_4bits:
                        mov                 r1, r0
                        ldi                 r2, 0b00001111
                        and                 r0, r2
                        ldi                 r2, 0b11110000
                        and                 r1, r2
                        ldi                 r2, 0x04
                        wsr                 SHIFT_AMT, r2
                        shr                 r1
                        ldi                 r2, 0b10            ;setting hi2 bits
                        wsr                 TWO_TMP, r2

                    .fetch_char_from_table:
                        ldi                 r2, general_addresses.hex_table_start - 0x200
                        add                 r0, r2
                        ldr                 r0, [r0]
                        add                 r1, r2
                        ldr                 r1, [r1]

                    .printhex:
                        mov                 r2, r0
                        push                r1
                        call                [k_putc]
                        push                r2
                        call                [k_putc]

                    .cleanup:
                        ldi                 r2, 1
                        wsr                 SHIFT_AMT, r2
                        
                    ret

                k__internal__convert_char: ;---> not syscallable
                    ldi                 r1, 0 ;---> offset pointer
                    .check:
                        ldi                 r2, general_addresses.hex_table_start - 0x200 ;---> main pointer
                        add                 r2, r1
                        ldr                 r3, [r2]
                        cmp                 r0, r3
                        jz                  [.char_found]
                        ldi                 r3, 1
                        add                 r1, r3
                        jmp                 [.check] 
                    .char_found:
                        push                r1
                        ret
                k_ascii_to_hex: ;---> takes two arguments | (ascii_lo, ascii_hi), hex bit will be in r0
                    ldi                 r0, 0b10
                    wsr                 TWO_TMP, r0
                    pop                 r0 ;---> ascii_lo
                    st                  [general_addresses.save_register_0], r0 ;---> save for later
                    pop                 r0 ;---> ascii_hi
                    .get_hi:
                        call                [k__internal__convert_char] ;---> ascii_hi converted version pushed
                    .get_lo:
                        ld                  r0, [general_addresses.save_register_0]
                        call                [k__internal__convert_char] ;---> ascii_lo converted version pushed
                    ldi                 r0, 4
                    wsr                 SHIFT_AMT, r0
                    .convert:
                        pop                 r1 ;---> ascii_lo
                        pop                 r0 ;---> ascii_hi
                        shl                 r0 ;---> hex = (hi << 4) + low
                        add                 r0, r1
                    .cleanup:
                        ldi                 r1, 1
                        wsr                 SHIFT_AMT, r1
                        ret
                k_puts: ;---> takes two arguments | pointer into RAM for the string, lo8 and hi2
                    pop                 r0 ;---> low 8 bits
                    pop                 r1 ;---> high 2 bits
                    wsr                 TWO_TMP, r1 ;---> do not give a pointer that will overflow or we'll be in big trouble
                    .printing:
                        ldr                 r1, [r0]
                        ldi                 r2, 0
                        cmp                 r1, r2
                        jz                  [.print_end]
                        st                  [mmio.TERM_PUT_CHAR], r1
                        ldi                 r2, 1
                        add                 r0, r2
                        jmp                 [.printing]
                    .print_end:
                        ret
                k_cmp_strings: ;---> needs a syscall so that we can load from RAM directly & its not super slow
                    ;---> // needs 2 arguments, lo8 bits of s1 pointer, lo8 bits of s2 pointer, hi2 bits will be 0b01             
                    pop                 r0 ;---> lo8 bits of s1 pointer
                    pop                 r1 ;---> lo8 bits of s2 pointer
                    ldi                 r2, 1
                    wsr                 TWO_TMP, r2
                    .cmp_loop:
                        ldr                 r2, [r0]
                        ldr                 r3, [r1]
                        cmp                 r2, r3
                        jnz                 [..strings_different]
                        ..null_check:
                            ldi                 r4, 0
                            cmp                 r2, r4
                            jnz                 [..continue]
                            ...first_char_zero:
                                cmp                 r3, r4
                                jz                  [..strings_same]
                                jmp                 [..continue]
                        ..continue:
                            ldi                 r2, 1
                            add                 r0, r2
                            add                 r1, r2
                            jmp                 [.cmp_loop]
                        ..strings_different:
                            ldi                 r0, 1
                            ret
                        ..strings_same:
                            ldi                 r0, 0
                            ret
                k_readline: ;---> obsolete don't call this
                    ret
                k_cls:
                    ldi                 r0, 1
                    st                  [mmio.TERM_CLR], r0
                    ret
                k_store8: ;---> takes three arguments | (value, lo8, hi2)
                    pop                 r0 ;---> value
                    pop                 r1 ;---> lo8
                    pop                 r2 ;---> hi2
                    st                  [general_addresses.save_register_1], r1
                    .permission_check_st8:
                        ldi                 r1, 0b01
                        cmp                 r2, r1
                        jz                  [.store8_continue]
                        ldi                 r1, 0b10
                        cmp                 r2, r1
                        jz                  [.store8_continue]
                        ldi                 r1, errors.UNAUTHORIZED_WRITE
                        call                [k__internal_error_handler]
                        ret
                    .store8_continue:
                        ld                  r1, [general_addresses.save_register_1]
                        wsr                 TWO_TMP, r2
                        str                 [r1], r0
                        ret
                k_load8: ;---> takes two arguments | (lo8, hi2)
                    pop                 r1 ;---> lo8
                    pop                 r0 ;---> hi2
                    st                  [general_addresses.save_register_1], r1
                    .permission_check_ld8:
                        ldi                 r1, 0b01
                        cmp                 r0, r1
                        jz                  [.load8_continue]
                        ldi                 r1, 0b10
                        cmp                 r0, r1
                        jz                  [.load8_continue]
                        ldi                 r1, errors.UNAUTHORIZED_READ
                        call                [k__internal_error_handler]
                        ret
                    .load8_continue:
                        ld                  r1, [general_addresses.save_register_1]
                        wsr                 TWO_TMP, r0
                        ldr                 r0, [r1]
                        ret
                k__internal__print_k_err:
                    __printc_no_syscall("K", r1) ;---> this K: means that the kernel is throwing the error instead of someone else
                    __printc_no_syscall(":", r1) 
                    ret
                k__internal_error_handler:
                    wsr                 ERR_INFO, r1
                    st                  [general_addresses.error_information], r1
                    call                [k__internal__print_k_err]
                    ld                  r1, [general_addresses.error_information] ;---> this function must only clobber r1
                    push                r1
                    call                [k_puthex8]
                    __printc_no_syscall("\n", r1)
                    ret
                k_save_regs: ;---> needs r0 on stack
                    pop                 r0
                    st                  [general_addresses.save_register_0], r0
                    st                  [general_addresses.save_register_1], r1
                    st                  [general_addresses.save_register_2], r2
                    st                  [general_addresses.save_register_3], r3
                    st                  [general_addresses.save_register_4], r4
                    st                  [general_addresses.save_register_5], r5
                    st                  [general_addresses.save_register_6], r6
                    st                  [general_addresses.save_register_7], r7
                    ret
                k_panic: 
                    ldi                 r1, errors.KERNEL_PANIC
                    wsr                 ERR_INFO, r1
                    call                [k__internal_error_handler] ;---> might work or it might not
                    call                [on_boot] ;---> reinitialize the entire OS, we have no space to do anything else lol
                __LOAD_ROM_FILE__: ;---> takes one argument | the rom id to load 
                    ;---> note this has to be the final os function so we don't need to jump to other addresses 
                    ;---> only jump to this address do not call it | this function does not return
                    pop                 r0
                    ldi                 r1, 0x050
                    add                 r1, r0
                    ldi                 r2, 0
                    wsr                 TWO_TMP, r2
                    ldr                 r2, [r1]
                    ldi                 r1, pgrm_start_addrs.terminal.hi2_bits
                    wsr                 TWO_TMP, r1
                    wsr                 PGRM_START_ADDR, r2
                    shl                 r0
                    ldi                 r1, 1
                    add                 r0, r1
                    !SET_COPY_MODE_REG r0           
        .copy_stop:
            copy_stop
        .intitalize:
            jmp                 [os_initialize]
