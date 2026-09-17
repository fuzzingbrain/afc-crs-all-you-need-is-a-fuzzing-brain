# trace demo — "where did the input go, and why did it stop there"

A standalone prototype of the next `trace` tool. It runs one input through a
challenge's graded (ASan, libFuzzer) binary under gdb and answers the two
questions the current tool cannot:

1. **Where did it go?** The full dynamic call sequence (function:depth), from
   a non-stopping breakpoint on every function the project's own source
   defines. 461 breakpoints on libpng cost ~0.5 s per run.
2. **Why did it stop there?** One of three stop kinds, each with evidence:
   - a function returned early → its return value and where it returned to;
   - `longjmp` / exception / `abort` → the error message and the backtrace at
     the throw point, plus which frames were dropped;
   - a signal (ASan crash) → the backtrace at the fault.

No rebuild, no image change: the binaries carry DWARF line tables and the
host has the same gdb 13 (with Python) as the images. Everything here runs
natively; docker is used exactly once, to copy the graded binaries out.

```
./fetch_bin.sh libpng-01 cups-01   # once: bin/<challenge>/asan/harness + sharedlibs (gitignored)
./run.sh all                       # the five cases below
./run.sh libpng-short              # one case
python3 build_case_md.py           # regenerate CASE-libpng-short.md by running every command in it
```

## Files

| file | role |
|---|---|
| `tracer.py` | the gdb-side script (runs inside gdb's Python); emits JSON events between `@@TRACE_JSON@@` / `@@TRACE_END@@` |
| `make_input.py` | writes the demo inputs |
| `fetch_bin.sh` | one-time `docker cp` of a challenge's graded binary and shared libs into `bin/` |
| `run.sh` | runs gdb natively, separates program stderr from gdb/libFuzzer noise, prints the events |
| `build_case_md.py` | regenerates `CASE-libpng-valid.md`: five ways to run one input, each with its exact command and full output |
| `CASE-libpng-short.md` | **start here**: one input run five ways, each with its raw copy-pasteable command and full output; no helper scripts involved |
| `COMPARE.md` | side-by-side of what the model learns from the old tool vs the new one, with and without target |
| `out/<case>.raw.txt` | the complete raw gdb output of the last run, unfiltered |

## Three layers in the output

1. **Raw gdb output** (`out/*.raw.txt`): gdb's own chatter, libFuzzer's INFO
   lines, and the program's own stderr, all interleaved. Only the program's
   lines matter (`libpng error: ...`, the ASan report).
2. **JSON events**: what the tracer observed. Facts only, no judgement.
3. **The model-facing summary**: not built yet; `tools.py` will derive it from
   the events. The "interpretation" lines below are what it should say.

## Cases

### libpng-short — signature + IHDR, then nothing

```
seq: LLVMFuzzerTestOneInput png_sig_cmp ... png_read_info png_read_sig png_sig_cmp
     png_read_chunk_header png_handle_chunk png_handle_IHDR ... png_read_chunk_header
     png_read_data png_error png_longjmp longjmp
stop: png_error("read error")
      ← user_read_data (harness.cc:67) ← png_read_chunk_header (pngrutil.c:196)
      ← png_read_info (pngread.c:118) ← LLVMFuzzerTestOneInput (harness.cc:282)
      png_read_info: frame left without a normal return (longjmp)
```

Interpretation: IHDR parsed fine (`png_handle_IHDR` returned `handled_ok`);
reading the *second* chunk header ran out of bytes in the harness's read
callback. Add a chunk to go deeper. The old tool would only have said
"reached png_read_info: no".

### libpng-badsig — 40 zero bytes

```
call png_sig_cmp  sig bytes=00 00 00 00 ...  num_to_check=8
ret  png_sig_cmp  value=-137  to harness.cc:186
ret  LLVMFuzzerTestOneInput value=0
```

Interpretation: the signature check failed on the first byte; nothing in
libpng was entered.

### libpng-valid — a complete 1x1 PNG (IHDR + IDAT + IEND)

```
program: libpng warning: IDAT: bad parameters to zlib
         libpng error: PNG unsigned integer out of range
ret  png_read_info (normal)
call png_read_end → png_read_finish_IDAT → png_read_IDAT_data → png_zstream_error
     → png_read_chunk_header → png_get_uint_31 → png_error
stop: png_error("PNG unsigned integer out of range")
      ← png_get_uint_31 (pngrutil.c:46) ← png_read_chunk_header (pngrutil.c:197)
      ← png_read_end (pngread.c:790) ← LLVMFuzzerTestOneInput (harness.cc:299)
```

Interpretation: the harness calls `png_read_end` right after `png_read_info`
without reading rows; draining the IDAT fails, the stream pointer is left
misaligned, and the next chunk length reads as ≥ 2^31. A "valid" PNG does not
run to completion on this harness — a fact the model cannot get from reading.

### cups-crash — one byte `0xC3`

```
seq: LLVMFuzzerTestOneInput cupsUTF8ToCharset abort
signal SIGABRT
   bt: __asan_report_load1 ← cupsUTF8ToCharset (transcode.c:245)
       ← LLVMFuzzerTestOneInput (harness.cc:19)
ret_lost cupsUTF8ToCharset, ret_lost LLVMFuzzerTestOneInput
program: ERROR: AddressSanitizer: heap-buffer-overflow ... transcode.c:245:12
```

### cups-clean — one byte `0x41`

```
call cupsUTF8ToCharset
ret  cupsUTF8ToCharset value=1  to harness.cc:20
ret  LLVMFuzzerTestOneInput value=0
exit code 0
```

## How gdb does this, briefly

gdb attaches via ptrace and only reads the process when it is stopped. The
tracer stops it with software breakpoints (`int3` written at each function's
entry), records the frame, and resumes without ever returning control to a
prompt. Return values come from gdb `FinishBreakpoint`s placed on the target
functions' return addresses; a frame that leaves via `longjmp` fires
`out_of_scope` instead, which is how dropped frames are detected. Crashes need
no breakpoint at all: ASan calls `abort`, the SIGABRT reaches gdb first.

Alternatives that would avoid breakpoints (SanitizerCoverage, function
instrumentation, LD_PRELOAD, Intel PT, eBPF uprobes, DynamoRIO) all need
either a rebuild or something the image and container do not have; only the
harness module carries sancov, the project code does not.

## Status

`tracer.py` here is a symlink to `FuzzingBrain-Agent/fbagent/gdb_tracer.py`, the
script the agent's `trace` tool now ships to the bench bridge. The gaps the
prototype had are closed there:

- a call is counted once (breakpoints are never created inside a `stop()`
  callback; a hit is attributed to the breakpoint's own function, so an inlined
  callee's breakpoint is not booked to its caller);
- one `longjmp` is one stop event (the sanitizer interceptor and libc's four
  alias names share a project stack and are collapsed);
- functions are selected by "not under a system path", so cups' bare `transcode.c`
  DWARF names work as well as libpng's `/src/...`;
- hot functions are capped (`FB_HIT_CAP`, default 50 hits) and a wall-clock
  guard (`FB_TIMEOUT`) prints what was collected;
- no project-specific error function is hard-coded: at a longjmp / abort /
  throw the arguments of every project frame on the stack are captured, which
  is where the message lives whatever the function is called.

Still out of scope: Java challenges (9 of 77, jazzer), and struct-typed
arguments (`png_ptr=0x...`) are shown as addresses, not expanded.
