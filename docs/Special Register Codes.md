# Special Register Codes

- `000` – FLAGS  
- `001` – SHIFT_AMOUNT  
- `010` – TWO_TMP  
- `011` – TST_LED  
- `100` – COPY_MODE / COPY_SRC  
  - Bit 0 → Copy On (1 = on, 0 = off)  
  - Bits 1–3 → Copy Source  
    - `000` – BOOT_ROM  
  - Instruction `0xFFFFFF` exits copy mode  
- `101` – ERR_INFO  
- `110` – PGRM_START_ADDR  
  - TWO_TMP bits must be set properly  
  - Not a valid ID for RSR  
