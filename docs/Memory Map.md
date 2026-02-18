### Memory Mapped I/O : 0x3C0–0x3FF

- `0x3FF` – IO_KBD_CLR : write 1 to clear
- `0x3FE` – IO_KBD_AVAIL
- `0x3FD` – IO_KBD_GETC
- `0x3FC` – IO_TERM_PUTC
- `0x3FB` – IO_TERM_CLR : write 1 to clear
- `0x3FA` – IO_ENTER_ACTIVE
- `0x3F9` – IO_ENTER_CLR

### Data & Call Stacks

- `0x3BF–0x380` – Stack (used by user + kernel)
- `0x37F–0x360` – Call Stack

### Program Region : 0x100–0x2FF

- Strings must be in `0x100–0x1FF`

#### ROM1 – Terminal

- `0x100–0x170` – Program strings  
  - `(0x100–0x101)` → `">\0"`  
  - `(0x102–0x104)` → `"E:\0"`  

  **Commands:**
  - `(0x105–0x106)` → `"c\0"`  
    - Clears screen  
  - `(0x107–0x108)` → `"r\0"`  
    - Print all registers (hex)  
  - `(0x109–0x10B)` → `"pm\0"`  
    - Dump program memory + register state  
  - `(0x10C–0x10F)` → `"psh\0"`  
    - Push argument onto stack  
  - `(0x110–0x113)` → `"pop\0"`  
    - Pop stack and print value  
  - `(0x114–0x115)` → `"s\0"`  
    - Store value at address (with permission check)  
  - `(0x116–0x117)` → `"l\0"`  
    - Load value from address (with permission check)  
  - `(0x118–0x11A)` → `"rs\0"`  
    - Dump special registers  
  - `(0x11B–0x11D)` → `"ra\0"`  
    - Dump address registers  
  - `(0x11E–0x120)` → `"ec\0"`  
    - Echo input  

- `0x150–0x170` – Program buffer  
- `0x200–0x207` – Register save area (The kernel saves registers via a syscall)  
- `0x210–0x21F` – Hex table  
- `0x2A0–0x2A3` – Argument pointers  
  - `0x2A0` → T_ARGP_1  
  - `0x2A1` → T_ARGP_2  
  - `0x2A2` → T_ARGP_3  
  - `0x2A3` → T_ARGP_4
  - `0x2AF` → T_ARGP_HI2  

### Kernel Area (0x000–0x070)

- `(0x041–0x04B)` – Service code addresses  
- `(0x051–0x05F)` – Program start addresses  
- `(0x060–0x069)` – Flag string  
