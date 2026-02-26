# Terminal Documentation

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
