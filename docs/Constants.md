# Constants

### MMIO Addresses

| Name            | Address |
| --------------- | ------- |
| IO_KBD_CLR      | 0x3FF   |
| IO_KBD_AVAIL    | 0x3FE   |
| IO_KBD_GETC     | 0x3FD   |
| IO_TERM_PUTC    | 0x3FC   |
| IO_TERM_CLR     | 0x3FB   |
| IO_ENTER_ACTIVE | 0x3FA   |
| IO_ENTER_CLR    | 0x3F9   |

### General Kernel Addresses

| Name         | Address |
| ------------ | ------- |
| SYS_TBL_STRT | 0x041   |

### Syscall IDs

| Name           | ID |
| -------------- | -- |
| SYS_GETC       | 0  |
| SYS_PUTC       | 1  |
| SYS_PUTHEX8    | 2  |
| SYS_PUTS       | 3  |
| SYS_READLINE   | 4  |
| SYS_CLS        | 5  |
| SYS_STORE8     | 6  |
| SYS_LOAD8      | 7  |
| SYS_CMP_STR    | 8  |
| SYS_SAVE_REGS  | 9  |
| SYS_ASCII_2HEX | 10 |

### Program Start Addresses

| Name               | Value |
| ------------------ | ----- |
| TERM_STRT_HI2      | 0b10  |
| TERM_STRT_LO8      | 0x050 |
| TERM_STRT_TBL_ADDR | 0x051 |

### Error Codes

| Name                 | Code |
| -------------------- | ---- |
| ERR_INVAL_CMD        | 0x01 |
| ERR_INVAL_HEXC       | 0x02 |
| SYS_ERR_UNAUTH_READ  | 0xA0 |
| SYS_ERR_UNAUTH_WRITE | 0xA1 |
| SYS_ERR_KRNL_PANIC   | 0xEE |
 
### Terminal Addresses

| Name          | Address |
| ------------- | ------- |
| T_PROMPT      | 0x100   |
| T_ERR_TMPLATE | 0x102   |
| T_CMD_C       | 0x105   |
| T_CMD_R       | 0x107   |
| T_CMD_PM      | 0x109   |
| T_CMD_PSH     | 0x10C   |
| T_CMD_POP     | 0x110   |
| T_CMD_S       | 0x114   |
| T_CMD_L       | 0x116   |
| T_CMD_RS      | 0x118   |
| T_CMD_RA      | 0x11B   |
| T_CMD_EC      | 0x11E   |
| T_BUF_START   | 0x150   |
| T_BUF_END     | 0x170   |
| T_ARGP_1      | 0x2A0   |
| T_ARGP_2      | 0x2A1   |
| T_ARGP_3      | 0x2A2   |
| T_ARGP_4      | 0x2A3   |
| T_ARGP_HI2    | 0x2AF   |

### General Addresses

| Name     | Address |
| -------- | ------- |
| FLAG     | 0x060   |
| INFO_ERR | 0x1FF   |
| SV_REG_0 | 0x200   |
| SV_REG_1 | 0x201   |
| SV_REG_2 | 0x202   |
| SV_REG_3 | 0x203   |
| SV_REG_4 | 0x204   |
| SV_REG_5 | 0x205   |
| SV_REG_6 | 0x206   |
| SV_REG_7 | 0x207   |
| HEX_TBL  | 0x210   |
