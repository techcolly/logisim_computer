# Instruction Set

### 00000–00111
- `00000` – ADD  
- `00001` – SUB  
- `00010` – SHL  
- `00011` – SHR  
- `00100` – AND  
- `00101` – OR  
- `00110` – XOR  
- `00111` – INTRET (unused) 

### 01000–01111
- `01000` – MOV  
- `01001` – LDI  
- `01010` – NOP  
- `01011` – RAR (Read Address Register)  
  - **Note:** hi2 bits are stored in `TWO_TMP` and must be read via `RSR`
- `01100` – ADC  
- `01101` – SBC  
- `01110` – RSR (Read Special Register)  
- `01111` – WSR (Write Special Register)  

### 10000–10111
- `10000` – HALT  
- `10001` – JOC (Jump on Condition)  
- `10010` – JROC (Relative Jump on Condition: `pc + constant`)  
- `10011` – CMP (A − B, discard result, keep NZCV flags)  
- `10100` – LD  
- `10101` – ST  
- `10110` – LDR (address = register + tmp)  
- `10111` – STR (address = register + tmp)  

### 11000–11111
- `11000` – ISP (Initialize Stack Pointer)  
- `11001` – PUSH  
- `11010` – POP  
- `11011` – CALL  
  - If bit 12 = 1 → call from address in register using RS/B  
- `11100` – RET  
- `11101` – CIM (Change Instruction Mode)  
- `11110` – SYSCALL  
- `11111` – SYSRET  

## General Form of IW
- `IW: OPCODE[23:19] RD/A[18:16] RS/B[15:13] UNUSED[12:8] IMM8[7:0]`
- Special Cases
     - `JOC: OPCODE[23:19] USE_REG_VAL[18] RS/A[17:15] (unused if USE_REG_VAL is 0) UNUSED[14] CON_CODE[13:10] IMM10[9:0] (unused if USE_REG_VAL is 1)`
     - `LD: OPCODE[23:19] RD/A[18:16] UNUSED[15:10] ADDR[9:0]`
     - `ST: OPCODE[23:19] UNUSED[18:16] RS/B[15:13] UNUSED[12:10] ADDR[9:0]`
     - `LDR, RAR: OPCODE[23:19] RD/A[18:16] ADDR_SOURCE [15:13] UNUSED[12:0]`
     - `STR: OPCODE[23:19] RS/A[18:16] ADDR_SOURCE [15:13] UNUSED[12:0]`
     - `PUSH: OPCODE[23:19] UNUSED[18:16] RS/B[15:13] UNUSED[12:0]`
     - `POP: OPCODE[23:19] RD/A[18:16] UNUSED[15:13] UNUSED[12:0]`
     - `CALL: OPCODE[23:19] UNUSED[18:16] UNUSED[15:13] UNUSED[12:10] ADDR[9:0]`
     - `ISP, RET: OPCODE[23:19] UNUSED[18:0]`