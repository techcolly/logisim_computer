#!/usr/bin/env python3
"""
Build .txt/.hex listings from one or more .asm files (or file stems),
clean the .txt files down to valid listing lines, then merge them into
a single combined .lss file.

Accepted input forms:
  python build_lss.py kernel rom1_terminal
  python build_lss.py kernel.asm rom1_terminal.asm
  python build_lss.py kernel rom1_terminal.asm

Important:
- .asm source files must be placed inside the ./assembly folder.
- The script will only look for input assembly files there.

Outputs for each input stem:
  <stem>.txt
  <stem>.hex

Merged output:
  disassembly.lss

.lss output format:
  <space><hex_addr_no_leading_zeros>: <instruction text> | <raw bytes>

Rules:
1) Uses the MIDDLE column ("addr") as the instruction address.
2) Uses the text AFTER ';' as the instruction/comment text.
3) Multi-word lines (macros / pseudo-ops) are NOT expanded.
4) Every line shows raw bytes.
   - single-word line: | 0x480002
   - multi-word line:  | 0x48000a 0xc80000 0x480001 0xf00000
5) Label-only lines like "kernel:" or ".main_loop:" are removed from the .lss.
6) If two input files define the same address, the later file on the command line wins.
"""

from __future__ import annotations

import os
import re
import sys
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Tuple


LINE_RE = re.compile(
    r"^\s*[^|]*\|\s*([0-9a-fA-F]+)\s*\|\s*([^;]*?)\s*;\s*(.*?)\s*$"
)

HEX_BYTE_RE = re.compile(r"\b[0-9a-fA-F]{2}\b")

ASSEMBLY_DIR = Path("assembly")


def normalize_input_arg(arg: str) -> str:
    base, ext = os.path.splitext(arg)
    if ext.lower() == ".asm":
        return base
    return arg


def normalize_hex_addr(addr_int: int) -> str:
    return format(addr_int, "x")


def normalize_spaces(text: str) -> str:
    return " ".join(text.strip().split())


def is_label_only(comment: str) -> bool:
    s = comment.strip()
    return (not s) or s.endswith(":")


def parse_bytes(data_field: str) -> List[int]:
    toks = HEX_BYTE_RE.findall(data_field)
    return [int(t, 16) for t in toks]


def chunk_words(bytes_list: List[int], word_size: int = 3) -> List[Tuple[int, int, int]]:
    usable = (len(bytes_list) // word_size) * word_size
    bytes_list = bytes_list[:usable]
    return [tuple(bytes_list[i:i + word_size]) for i in range(0, len(bytes_list), word_size)]  # type: ignore


def format_word(word: Tuple[int, int, int]) -> str:
    op, b1, b2 = word
    return f"0x{op:02x}{b1:02x}{b2:02x}"


def format_words(words: List[Tuple[int, int, int]]) -> str:
    return " ".join(format_word(word) for word in words)


def find_customasm_executable() -> str:
    exe = Path("customasm.exe")

    if not exe.exists():
        print("Error: customasm.exe not found in project folder.", file=sys.stderr)
        print("Download it from: https://github.com/hlorenzi/customasm", file=sys.stderr)
        print("Place customasm.exe in the same directory as this script.", file=sys.stderr)
        sys.exit(1)

    return str(exe)


def delete_txt_files(txt_files: List[Path]) -> None:
    for f in txt_files:
        try:
            if f.exists():
                f.unlink()
        except Exception as e:
            print(f"Warning: could not delete {f}: {e}", file=sys.stderr)


def clean_listing_file(txt_path: Path) -> int:
    try:
        kept_lines: List[str] = []

        with txt_path.open("r", encoding="utf-8", errors="replace") as infile:
            for raw in infile:
                line = raw.rstrip("\n")
                if LINE_RE.match(line):
                    kept_lines.append(line)

        with txt_path.open("w", encoding="utf-8", newline="\n") as outfile:
            for line in kept_lines:
                outfile.write(line + "\n")

        return 0

    except Exception as e:
        print(f"Error cleaning {txt_path}: {e}", file=sys.stderr)
        return 1


def build_listing_files(file_stem: str, customasm_exe: str) -> int:
    try:
        asm_path = ASSEMBLY_DIR / f"{file_stem}.asm"
        txt_path = Path(f"{file_stem}.txt")
        hex_path = Path(f"{file_stem}.hex")

        if not asm_path.exists():
            print(f"Error: assembly file not found: {asm_path}", file=sys.stderr)
            return 1

        with txt_path.open("w", encoding="utf-8", newline="\n") as outfile:
            subprocess.run([customasm_exe, str(asm_path), "-p"], stdout=outfile, check=True)

        subprocess.run(
            [
                customasm_exe,
                str(asm_path),
                "-f",
                'list,base:16,group:6,between:" "',
                "-o",
                str(hex_path),
            ],
            check=True,
        )

        return clean_listing_file(txt_path)

    except Exception as e:
        print(f"Error building {file_stem}: {e}", file=sys.stderr)
        return 1


def move_hex_files_to_hex_folder(file_stems: List[str]) -> int:
    try:
        hex_dir = Path("hex")
        hex_dir.mkdir(exist_ok=True)

        for stem in file_stems:
            src = Path(f"{stem}.hex")
            dst = hex_dir / src.name

            if src.exists():
                if dst.exists():
                    dst.unlink()
                shutil.move(str(src), str(dst))

        return 0

    except Exception as e:
        print(f"Error moving .hex files: {e}", file=sys.stderr)
        return 1


def convert_text_to_lss_lines(input_text: str) -> Dict[int, str]:
    out: Dict[int, str] = {}

    for raw in input_text.splitlines():
        m = LINE_RE.match(raw)
        if not m:
            continue

        addr_hex = m.group(1)
        data_field = m.group(2)
        comment = normalize_spaces(m.group(3))

        if is_label_only(comment):
            continue

        addr = int(addr_hex, 16)
        byte_list = parse_bytes(data_field)

        if not byte_list:
            continue

        words = chunk_words(byte_list, 3)
        if not words:
            continue

        out[addr] = f" {normalize_hex_addr(addr)}: {comment} | {format_words(words)}"

    return out


def merge_txt_files_to_lss(txt_files: List[Path], out_path: Path) -> int:
    try:
        merged: Dict[int, str] = {}

        for txt_file in txt_files:
            text = txt_file.read_text(encoding="utf-8", errors="replace")
            current = convert_text_to_lss_lines(text)

            for addr, line in current.items():
                merged[addr] = line

        sorted_lines = [merged[addr] for addr in sorted(merged.keys())]
        out_path.write_text(
            "\n".join(sorted_lines) + ("\n" if sorted_lines else ""),
            encoding="utf-8",
        )

        print(f"Wrote {len(sorted_lines)} lines to {out_path}")
        return 0

    except Exception as e:
        print(f"Error creating {out_path}: {e}", file=sys.stderr)
        return 1


def main() -> int:
    if len(sys.argv) < 2:
        print(
            "Usage: python build_lss.py <file1|file1.asm> <file2|file2.asm> ...",
            file=sys.stderr,
        )
        return 2

    if not ASSEMBLY_DIR.exists():
        print(f"Error: required folder not found: {ASSEMBLY_DIR}", file=sys.stderr)
        print("Put your .asm files inside the ./assembly folder.", file=sys.stderr)
        return 1

    customasm_exe = find_customasm_executable()
    file_stems = [normalize_input_arg(arg) for arg in sys.argv[1:]]

    for stem in file_stems:
        if build_listing_files(stem, customasm_exe) != 0:
            return 1

    txt_files = [Path(f"{stem}.txt") for stem in file_stems]

    if merge_txt_files_to_lss(txt_files, Path("disassembly.lss")) != 0:
        return 1

    delete_txt_files(txt_files)

    if move_hex_files_to_hex_folder(file_stems) != 0:
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())