# Terminal Documentation

---

TCTerminal is a minimal user-mode terminal program with ten commands. Users may use this program to inspect and/or modify the system state, given the appropriate permissions. The terminal program runs in user mode.

Addresses `0x113`-`0x24f` contain terminal functions that should not be directly called from outside terminal code. To safely enter the terminal after initialization, jump to the beginning of the main loop at memory address `0x250`. When the terminal begins, it will store the `hi2` bits  of the argument pointers at memory address `0x2af`. Since strings must live in `0x1XX`, this number will always be `1`. It will then clear the screen, load the `lo8` bits of the buffer pointer (`T_BUF_START - 0x100`), and print the prompt. The following process will then run in an indefinite loop until externally halted:

- Get one character from the keyboard. This involves a system call (`SYS_CLS`)
- Check if this character is the null character. If it is, jump back to the beginning of the loop, otherwise continue.
- Check if this character is the backspace character. If it is, jump to the backspace handler, otherwise continue.
    - The backspace handler moves the buffer pointer back one byte, replaces the backspace character with a null character (`SYS_STORE8`), echoes the backspace character to the terminal (`SYS_PUTC`), and then returns to the main loop.
- Check if this character is the newline character. If it is, jump to the newline handler, otherwise continue.
    - The newline character first prints the character to the console  (`SYS_PUTC`). Afterwards, it will reset the buffer pointer back to `T_BUF_START - 0x100` and walk through the string, replacing any spaces between arguments with a null character for easier readability later (`SYS_LOAD8`, `SYS_STORE8`). Each time a space is encountered, it will store a pointer to the next argument (one byte past the current buffer pointer) in `T_ARGP_1...T_ARGP_4` (`SYS_STORE8`). Once this function finishes, it will then jump to the command parser.
- If neither of the above three conditions are true, then store the character to the buffer (`SYS_STORE8`), echo it to the terminal (`SYS_PUTC`), and jump back to the beginning of the loop.
- Once the newline handler concludes, if it's called, it will then jump to the command parser. The command table is stored in RAM beginning at memory address `0x100`. The newline handler will walk through and compare the entered command against each entry in the table (`SYS_CMP_STR`). If a match is found, jump to the appropriate command handler. Otherwise call the error handler with code `ERR_INVAL_CMD`, print the prompt, clear the buffer and jump back to the main loop.
---

| Command | Arguments             | What it does                                        | Syscalls used by this command                | Modifies Program Memory (Y/N) | Special Notes                                                                   |
| ------- | --------------------- | --------------------------------------------------- | -------------------------------------------- | ----------------------------- | ------------------------------------------------------------------------------- |
| `c`     | —                     | clear the screen and re-print the prompt            | `SYS_CLS`, `SYS_PUTS`                        | N                             | —                                                                               |
| `r`     | —                     | print saved registers (`SV_REG_0..SV_REG_7`) as hex | `SYS_SAVE_REGS`, `SYS_LOAD8`, `SYS_PUTHEX8`  | N                             | —                                                                               |
| `pm`    | —                     | dump program memory as hex with spacing/newlines    | `SYS_LOAD8`, `SYS_PUTHEX8`                   | N                             | prints 32 bytes per line beginning at `0x100` (inclusive)                       |
| `pop`   | —                     | pop stack value and print it as hex                 | `SYS_PUTHEX8`                                | N                             | —                                                                               |
| `psh`   | `<hex_byte>`          | push a user-supplied hex byte onto the stack        | `SYS_LOAD8`, `SYS_ASCII_2HEX`                | N                             | —                                                                               |
| `ec`    | `<string>`            | echo argument string back to the terminal           | `SYS_PUTS`                                   | N                             | —                                                                               |
| `rs`    | —                     | read and print special registers as hex             | `SYS_PUTHEX8`                                | N                             | —                                                                               |
| `ra`    | —                     | read and print address registers as hex             | `SYS_PUTHEX8`                                | N                             | —                                                                               |
| `s`     | `<hi2> <lo8> <value>` | store a byte to memory                              | `SYS_LOAD8`, `SYS_ASCII_2HEX`, `SYS_STORE8`  | Y                             | —                                                                               |
| `l`     | `<hi2> <lo8>`         | load a byte from memory and print it                | `SYS_LOAD8`, `SYS_ASCII_2HEX`, `SYS_PUTHEX8` | N                             | —                                                                               |
