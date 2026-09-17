#!/usr/bin/env python3
"""Write the demo input for one case to a file.

    python3 make_input.py <case> <out-file>

libpng-01 cases (harness: PNG payload first, then a 12-byte FuzzedDataProvider
control tail consumed from the end; size must be >= 32):
  libpng-badsig   40 zero bytes                -> png_sig_cmp fails, returns early
  libpng-short    signature + IHDR + tail      -> png_error("read error"): data ran out
  libpng-valid    full 1x1 PNG + tail          -> png_read_info ok, png_read_end errors
cups-01 cases (harness: raw bytes -> cupsUTF8ToCharset):
  cups-crash      one byte 0xC3               -> heap-buffer-overflow (ASan, SIGABRT)
  cups-clean      one byte 0x41               -> returns normally
"""
import struct
import sys
import zlib

SIG = b"\x89PNG\r\n\x1a\n"
TAIL = b"\x00" * 12
IHDR = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)


def chunk(t: bytes, d: bytes) -> bytes:
    return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)


CASES = {
    "libpng-badsig": lambda: b"\x00" * 40,
    "libpng-short": lambda: SIG + chunk(b"IHDR", IHDR) + TAIL,
    "libpng-valid": lambda: SIG + chunk(b"IHDR", IHDR)
    + chunk(b"IDAT", zlib.compress(b"\x00\xff\x00\x00")) + chunk(b"IEND", b"") + TAIL,
    "cups-crash": lambda: b"\xc3",
    "cups-clean": lambda: b"\x41",
}

if __name__ == "__main__":
    case, out = sys.argv[1], sys.argv[2]
    with open(out, "wb") as f:
        f.write(CASES[case]())
