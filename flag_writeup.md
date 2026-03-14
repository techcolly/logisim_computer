# Flag Writeup

---

The kernel stores a flag into memory during the boot sequence, at address `FLAG`. To properly win the CTF challenge, the participant must find a way to read the flag string and display it in the terminal.

To achieve this, one may begin by noticing that the `T_ARGP_1,2,3,4` addresses store the `lo8` bits of a pointer to an argument string, and `T_ARGP_HI2` stores `hi2` bits of that pointer. `T_ARGP_HI2` will contain a `1`, because we know that terminal strings are required to be in the `0x1XX` region of memory. Therefore, the pointer to an argument string is given by `(T_ARGP_HI2 << 8) + T_ARGP_1,2,3,4`. Execute the command `s 02 af 00`, which sets `T_ARGP_HI2 = 0`. Now, any command arguments entered will be read from the `0xXXX` region of memory, rather than `0x1XX` where the terminal buffer and argument strings normally live. From this point on, most terminal commands will not be usable.

Let's analyze the following block of assembly code from `rom1_terminal.asm`:
```
.newline_handler:
    push        r0
    syscall     SYS_PUTC 
    ldi         r7, T_BUF_START - 0x100
    ldi         r4, " "
    ldi         r6, "\0"
    ldi         r5, 1
    ldi         r3, 0 ; ---> lo8 bits to be added to 0x2a0 for arg pointer
    ..test_for_command_end:
        push        r5 ;---> hi2
        push        r7 ;---> lo8
        syscall     SYS_LOAD8
        cmp         r0, r4
        jz          [...is_a_space]
            ...not_a_space:
                add         r7, r5
                ....is_null:
                    cmp         r0, r6
                    jz          [.check_if_c]
                jmp         [..test_for_command_end]

            ...is_a_space:
                ldi         r1, "\0"
                push        r5 ;---> hi2
                push        r7 ;---> lo8
                push        r1 ;---> value
                syscall     SYS_STORE8
                add         r7, r5
                ldi         r0, 0b10 ;---> hi2 (will be 0b10 always)
                push        r0 ;---> push it to stack
                ldi         r0, 0x0a0 ;---> lo8
                add         r0, r3 ;---> add arg counter to lo8 for next argument ptr
                push        r0 ;---> push lo8
                ldi         r0, 1
                add         r3, r0 ;---> increment pointer for arg counter
                push        r7 ;---> value
                syscall     SYS_STORE8
                jmp         [..test_for_command_end]
```
This tells us that `T_ARGP_1,2,3,4` values are only updated if the command entered has that many arguments. For example, if a user enters a command and only provides one argument, then only `T_ARGP_1` will be updated, and `T_ARGP_2,3,4` will retain their previous values. 

The `ec` command echoes user input back to the terminal. Specifically, `ec` prints the string stored at `(T_ARGP_HI2 << 8) + T_ARGP_1`. We know that `FLAG` = `0x060`, and `T_ARGP_HI2` is already set to `0` from our previous command. So, all that's left is to get `T_ARGP_1` to point to `0x060`. Recall that our previous command was `s 02 af 00`. Because `T_BUF_START` = `0x150`, and the first argument begins at `0x152`, we know that `T_ARGP_1` must currently hold the value `0x052`. Let's craft a command such that the first argument begins at `0x060`. Such a command would need to be 15 characters long followed by one argument, so that the space character is at `0x15F` and `T_ARGP_1` points to the first argument at `0x060`. The command `0123456789abcde 1` satisfies these requirements. Despite this being an invalid command that isn't recognized by the terminal, entering it will still update `T_ARGP_1`. 

At this point, `(T_ARGP_HI2 << 8) + T_ARGP_1` = `0x060`. Run `ec` with no arguments, so that argument pointers maintain their malformed state from our previous "command". `ec` will print the string stored at `0x060`, and the flag will be printed to the terminal.