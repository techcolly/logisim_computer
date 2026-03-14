# 8-Bit Logisim CPU + Monolithic Kernel
![The full CPU.](images/computer.jpg)

### Overview
---
The entire CPU was made from scratch in one `.circ` file. The CPU is 8 bits, with a 24-bit fixed instruction width and 10-bit addresses. In addition to 8 main registers and an ALU, the CPU offers the following features: 
- Data Stack
- Call Stack
- 1KB asynchronous RAM
- ROM loading to a fixed address
- Memory-mapped I/O
- User/Kernel Mode & Privilege Seperation (including `syscall`/`sysret`)

On the software side, this project includes a small monolithic kernel and a terminal program. This project also includes a CTF-style challenge, where one may attempt to display the flag string (at `0x060`) in the terminal.

For more information see the [documents folder](/docs), as everything is **extensively** documented there.

### Usage
---
Usage is relatively straightforward.
- If you do not wish to modify the assembly code, then simply open `computer.circ`, load `kernel.hex` into the `ROM0_BOOT` ROM, and load `rom1_terminal.hex` into the `ROM1_TERMINAL` ROM. Afterwards, enable auto-tick and set the auto-tick frequency to the highest setting that doesn't lag. The computer is now running, and you may type commands into the terminal, or inspect anything else.
- If you do wish to modify the assembly code, you'll need to reassemble the code once you're done. To do that, download `customasm.exe` from [hlorenzi](http://github.com/hlorenzi)'s [customasm project](https://github.com/hlorenzi/customasm). You'll need to place `customasm.exe` in the main folder, and then run `build_lss.py` to create the two new hex files and the new `.lss` file. Once this is finished, follow the same steps as the first entry.
### Motivation
---
This project was officially complete in mid-March of 2026, and I built and finished this project before taking a class on operating systems, systems software, or even computer architecture. My main motivation for this was that every explanation about how a computer works always felt like magic. "The CPU does X", "The system will do Y". Well how exactly does that happen? I figured the only way to gain proper intuition for this, was to build the entire thing up from scratch on my own and see exactly where everything falls into place. 

So, starting in early December 2025, with zero prior knowledge about how any of this stuff works, I began working on this project. To guide myself, I came up with a layered abstraction model (similar to the OSI model) for how a computer works. I figured that if I built layer 1, then figured out how I'd get from layer 1 to 2, then from 2 to 3, and just kept building all the way up to the top, I'd be able to finish the project with a good intuition for what a computer does and how modern OSes work. It was definitely very difficult to create this project in that fashion, but now that it's finished this has certainly paid off. 
