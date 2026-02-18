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
- IW: OPCODE[23:19] RD/A[18:16] RS/B[15:13] UNUSED[12:8] IMM8[7:0]