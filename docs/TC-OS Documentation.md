# TC-OS Documentation

---
TC-OS is a small monolithic kernel which provides essential services and basic memory protection. User programs may utilize kernel services by invoking a system call with a valid syscall ID. The `syscall` instruction tells the CPU to enable kernel mode and jump to the syscall handler address `0x006`, which is burned-in and cannot be directly modified by software. If the ID is valid, the syscall handler will add a fixed offset `0x041` to the ID. This new number will point to the appropriate entry in the syscall table that contains the memory address for the requested kernel function. If the ID is invalid, a kernel panic will be triggered.

There are 11 valid system calls, but the kernel will only perform a permission check for two of them. If a user program calls `SYS_STORE8` or `SYS_LOAD8`, the request will only be fulfilled if the address in question lies in the program memory region `0x100`-`0x2FF` (inclusive). A system call for the aforementioned two syscall IDs which requests to read or write memory outside of this region will trigger a kernel panic.

When the system starts, the kernel will initialize the instruction mode and stack pointer. It will then begin the process of copying kernel functions into IRAM. 