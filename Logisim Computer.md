00000 - ADD
00001 - SUB
00010 - SHL
00011 - SHR
00100 - AND
00101 - OR
00110 - XOR
00111 - INTRET

01000 - MOV
01001 - LDI
01010 - NOP
01011 - RAR (read address register)
	Note: hi2 bits will be in TWO_TMP and must be read via RSR
01100 - ADC
01101 - SBC
01110 - RSR (read special register)
01111 - WSR (write special register)

10000 - HALT
10001 - JOC (jump on condition) 
10010 - JROC (relative jump on condition: pc + constant)
10011 - CMP (take A-B, discard result, keep NZCV flags)
10100 - LD
10101 - ST
10110 - LDR (address is in a register + tmp)
10111 - STR (address is in a register + tmp)

11000 - ISP (initialize stack pointer)
11001 - PUSH
11010 - POP
11011 - CALL
	- If the 12th bit is 1 then we can call from an address in a register using RS/B
11100 - RET
11101 - CIM (change instruction mode)
11110 - SYSCALL
11111 - SYSRET

Bus Drivers

ALU_OUT - Bus 0 (000)
IMM/LDI_DATA - Bus 1 (001)
READ_B - Bus 2 (010)
READ_A - Bus 3 (011)
SR_READ - Bus 4 (100)
RAM_OUTPUT - Bus 5 (101)
RAR_LO8 - Bus 6 (110)

SPECIAL REGISTER CODES: 
000 - FLAGS
001 - SHIFT_AMOUNT
010 -  TWO_TMP
011 - TST_LED
100 - COPY_MODE/COPY_SRC ---> this needs to be added to rsr mux later
- 4 bits: 
	- Bit 0 - Copy On (1 for on, 0 for off)
	- Bits 1-3: Where to copy from
		- 000 - BOOT_ROM
- Instruction 0xFFFFFF to exit copy mode
101 - ERR_INFO
110 - PGRM_START_ADDR ---> TWO_TMP bits must be set properly
	Note: not a valid id for RSR

ADDRESS REGISTER CODES:
000 - PC
001 - SP
010 - CSP
011 - C/R addr
100 - PGRM_START
101 - SYSRET_ADDR
110 - INT_RET_ADDR


IW: OPCODE[23:19] RD/A[18:16] RS/B[15:13] UNUSED[12:8] IMM8[7:0]

Special Cases: 

#old JOC : OPCODE[23:19] USE_REG_VAL[18:16] (can be 000 or 001) RS/A[15:13] (unused if USE_REG_VAL is 000) CON_CODE[12:10] IMM10[9:0] (unused if USE_REG_VAL is 001); note that if reg value is used, you are limited to 8 bits (first two MSBs will become zero)

JOC: OPCODE[23:19] USE_REG_VAL[18] (can be 0 or 1) RS/A[17:15] (unused if USE_REG_VAL is 0) UNUSED[14] CON_CODE[13:10] IMM10[9:0] (unused if USE_REG_VAL is 1)

JOC/JROC Condition Codes:

Borrow = ~Carry, [C=1 means no borrow needed]

| CON_CODE | Definition-based JOC/JROC argument | CMP-based JOC/JROC argument | Jumps if (NZCV)                    | Jumps if (definition)                                                                                  | Jumps if (after CMP) |
| -------- | ---------------------------------- | --------------------------- | ---------------------------------- | ------------------------------------------------------------------------------------------------------ | -------------------- |
| 0000     | NEG                                |                             | N=1                                | Negative                                                                                               |                      |
| 0001     | POS                                |                             | N=0                                | Positive,Zero                                                                                          |                      |
| 0010     | ZE                                 | EQ                          | Z=1                                | Zero                                                                                                   | A=B                  |
| 0011     | NZE                                |                             | Z=0                                | Not Zero                                                                                               |                      |
| 0100     |                                    | UGE                         | C=1                                | ADD, ADC carry-out 1 --> unsigned overflow<br><br>SUB, SBC --> borrow-out 0<br><br>CMP --> Unsigned GE | A≥B (unsigned)       |
| 0101     |                                    | ULT                         | C=0                                | ADD, ADC carry-out 0 --> unsigned overflow<br><br>SUB, SBC --> borrow-out 1<br><br>CMP --> Unsigned LT | A<B (unsigned)       |
| 0110     | OV                                 |                             | V=1                                | Signed Overflow (e.g 0x7f + 0x01, if signed, = 128 which equals -128 in two's complement)              |                      |
| 0111     | NOV                                | N/A                         | V=0                                | No Unsigned Overflow                                                                                   |                      |
| 1000     |                                    | UGT                         | C=1 AND Z=0                        | CMP --> Unsigned GT                                                                                    | A>B (unsigned)       |
| 1001     |                                    | ULE                         | C=0 OR Z=1                         | CMP --> Unsigned LE                                                                                    | A≤B (unsigned)       |
| 1010     |                                    | SGE                         | Z=1<br><br>OR <br><br>N XOR V = 0  | CMP --> Signed GE                                                                                      | A≥B (signed)         |
| 1011     |                                    | SLT                         | Z=0<br><br>AND<br><br>N XOR V = 1  | CMP --> Signed LT                                                                                      | A<B (signed)         |
| 1100     |                                    | SGT                         | Z=0<br><br>AND <br><br>N XOR V = 0 | CMP --> Signed GT                                                                                      | A>B (signed)         |
| 1101     |                                    | SLE                         | Z=1 <br><br>OR<br><br>N XOR V = 1  | CMP --> Signed LE                                                                                      | A≤B (signed)         |
| 1110     |                                    | UN                          |                                    | Unconditional <br><br>(Ignore flags, always jump regardless of what they are)                          |                      |
| 1111     |                                    |                             |                                    | Reserved                                                                                               |                      |

LD: OPCODE[23:19] RD/A[18:16] UNUSED[15:10] ADDR[9:0]
ST: OPCODE[23:19] UNUSED[18:16] RS/B[15:13] UNUSED[12:10] ADDR[9:0]

LDR, RAR: OPCODE[23:19] RD/A[18:16] ADDR_SOURCE [15:13] UNUSED[12:0]
STR: OPCODE[23:19] RS/A[18:16] ADDR_SOURCE [15:13] UNUSED[12:0]

PUSH: OPCODE[23:19] UNUSED[18:16] RS/B[15:13] UNUSED[12:0]
POP: OPCODE[23:19] RD/A[18:16] UNUSED[15:13] UNUSED[12:0]

CALL: OPCODE[23:19] UNUSED[18:16] UNUSED[15:13] UNUSED[12:10] ADDR[9:0]
ISP, RET: OPCODE[23:19] UNUSED[18:0]
## [Remember: two_tmp holds the two most significant bits]

0x3C0-0x3FF : Memory Mapped I/O
	0x3FF - KBD_CLEAR (set 1 to clear) ---> KBD PLA output 0b11
	0x3FE - KBD_AVAILABLE (1 if characters) ---> KBD PLA output 0b10
	0x3FD - KBD_GET_CHAR ---> KBD PLA output 0b01
	0x3FC - TERM_PUT_CHAR ---> TERM PLA output 0b11
	0x3FB - TERM_CLR (set 1 to clear) ---> TERM PLA output 0b10
	0x3FA - ENTER_ACTIVE
	0x3F9 - ENTER_CLEAR
	
0x3BF-0x380:  Stack (used by kernel also)
0x37F-0x360:  Call Stack
0x100-0x2FF: Program Region ---> strings must be in 0x100-0x1FF
	ROM1 - Terminal
		0x100-0x170:  Program strings
				(0x100, 0x101) ---> ">\0"
				(0x102, 0x104) ---> "E:\0"
				Commands:
					(0x105, 0x106) ---> "c\0"
						Clears the screen
					(0x107, 0x108) ---> "r\0"
						Will print all registers in hexadecimal
					(0x109, 0x10b) ---> "pm\0"
						This will dump the entire program memory into the console and then print the register state in a newline
					(0x10c, 0x10f) ---> "psh\0"
						The command will take one argument (value) and that value will be pushed onto the stack
					(0x110, 0x113) ---> "pop\0"
						Pops the value off the stack and prints it
					(0x114, 0x115) ---> "s\0"
						Command will take three arguments (value, address lo8, address hi2) and put the value at the address if the user has permission to do so, will raise error otherwise
					(0x116,  0x117) ---> "l\0"
						Command will take two arguments (address lo8, address hi2) and it will print the value in that address if the user has permission to do so, will raise error otherwise
					(0x118, 0x11a) ---> "rs\0"
						Will dump all special registers
					(0x11b, 0x11d) ---> "ra\0"
						Will dump all address registers that the user has permission to access
					(0x11e, 0x120) ---> "ec\0"
						Will echo input back to user
		0x150-0x170:  Program buffer
		0x200-0x207:  To save registers in regs command, kernel will do it
		0x250-0x25F:  Hex Table
		0x2A0-0x2C0: Argument pointers
			0x2A0 ---> pointer to argument 1 (lo8)
			0x2A1 ---> pointer to argument 2 (lo8)
			0x2A2 ---> pointer to argument 3 (lo8)
			0x2A3 ---> pointer to argument 4 (lo8)
0x000-0x070: Kernel Area
	(0x020, 0x040) - K_BUFFER
	(0x041, 0x050) - addresses for service codes
	(0x051, 0x05F) - addresses for program starts
	(0x060, 0x069) - flag string

To call a function with arguments, the function will expect the values to be on the stack
- Push the values onto the stack in reverse order
	- So do push c, push b, push a for f (a, b, c)

Trying to jump into kernel code will trigger the panic

Error Codes:
- 0x01 - INVALID_COMMAND
- 0xA0 - BAD_REGISTER_ID


# TODO: make LDR and STR kernel mode required, timer interrupt, address read terminal command, terminal argument handler

