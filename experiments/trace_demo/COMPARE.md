> Note: written against the prototype's event format (a `call` event per stopper, one per alias). The agent's tracer now emits one `stop` event per longjmp/abort with the arguments of every project frame on the stack; the questions and the table below are unchanged. `CASE-libpng-short.md` is regenerated from the current tracer.

# Three-way comparison: same input, old trace / new trace without target / new trace with target

Input: `out/libpng-valid.bin`, a complete 1x1 PNG plus a 12-byte control tail.
What the model wants to know: did my input reach `png_read_IDAT_data`? And what happened after that?

Raw output is in `out/compare.raw.txt` (the old-script and no-target sections) and `out/libpng-valid.raw.txt` (with target).

---

## 1. Old trace (the bench's existing 8-line gdb script, 1 breakpoint)

gdb script:

```
break png_read_IDAT_data
commands
  printf "@@REACHED png_read_IDAT_data@@\n"
  info args
  bt 4
  continue
end
run /tmp/in.bin
printf "@@ENDED@@\n"
bt 8
```

What the model actually receives (the output of `tools._parse_trace`, verbatim):

```
reached png_read_IDAT_data: YES   args: png_ptr = 0x61a000000080; output = <optimized out>; avail_out = <optimized out>
crashed: no — ran to completion without a fault
(LeakSanitizer is off under gdb; score memory-leak faults through ./submit.)
```

What the model learns from this: it got there, and it did not crash.
What the model does not learn: what happened after it got there. The program actually errored right after png_read_IDAT_data and longjmp'd out;
the line `libpng error: PNG unsigned integer out of range` is in the raw output, but the parser never looks at it.
"ran to completion without a fault" is misleading: the program was carried out by the error path, it did not run to completion.

---

## 2. New trace, no target (`FB_TARGETS=` empty)

What the events contain (noise other than seq stripped):

```
call png_error  args: error_message="PNG unsigned integer out of range"
   bt: png_error (pngerror.c:54)
       png_get_uint_31 (pngrutil.c:46)
       png_read_chunk_header (pngrutil.c:197)
       png_read_end (pngread.c:790)
       LLVMFuzzerTestOneInput (harness.cc:299)
call longjmp   bt: png_longjmp ← png_default_error ← png_error ← png_get_uint_31 ← ...
call exit
exit code 0, 92 hits, 0.59 s
counts: 55 distinct functions; png_read_data 7, png_get_io_ptr 7, png_read_chunk_header 6, ...
seq: LLVMFuzzerTestOneInput png_sig_cmp png_create_read_struct_2 ... png_read_info png_read_sig
     ... png_handle_IHDR ... png_read_end png_read_finish_IDAT png_read_IDAT_data
     png_zstream_error png_chunk_benign_error png_chunk_warning png_read_chunk_header
     png_read_data png_get_io_ptr png_read_chunk_header png_error png_longjmp longjmp ...
```

What the model learns from this:
- it reached png_read_IDAT_data (it is in the sequence);
- after that it went png_zstream_error → png_chunk_warning (a warning that zlib initialisation failed);
- then png_get_uint_31 errored while png_read_chunk_header was reading the next chunk header;
- the error jumped back to the harness via longjmp, and the process exited normally.

What the model does not learn: what png_read_IDAT_data itself returned, and whether png_read_info returned normally or was jumped out of.

---

## 3. New trace, with targets (`FB_TARGETS=LLVMFuzzerTestOneInput,png_sig_cmp,png_read_info,png_handle_IHDR,png_read_IDAT_data,png_read_end`)

On top of everything in part 2, these lines are added:

```
call png_sig_cmp        sig bytes=89 50 4e 47 0d 0a 1a 0a ...  num_to_check=8
ret  png_sig_cmp        value=0        to harness.cc:186
call png_read_info      png_ptr=0x61a000000080 info_ptr=0x613000000040
ret  png_handle_IHDR    value=handled_ok
ret  png_read_info      (normal)       to harness.cc:282
call png_read_end       png_ptr=0x61a000000080 info_ptr=0x613000000200
call png_read_IDAT_data png_ptr=0x61a000000080 output=<optimized out> avail_out=<optimized out>
ret  png_read_IDAT_data (void)         to pngrutil.c:4509
ret_lost png_read_end   frame left without a normal return (longjmp)
ret  LLVMFuzzerTestOneInput value=0
```

What the model additionally learns:
- the signature check passed (returned 0);
- png_read_info returned normally and IHDR was handled_ok, so header parsing was fine;
- png_read_IDAT_data returned normally, so the problem is not inside it but after it returns;
- the frame dropped by longjmp is png_read_end's, not png_read_info's.

In other words, "where did it stop" goes from function-level precision to "which stop returned normally and which one was jumped out of".

---

## One table

| Question | Old trace | New, no target | New, with target |
|---|---|---|---|
| Did it reach X | yes | yes (check the sequence) | yes |
| X's entry arguments | yes | no | yes |
| Which functions it passed through before X | none | all | all |
| Where it went after X | none | all | all |
| Why it stopped: error message | none (in the raw output, not parsed) | yes | yes |
| Why it stopped: call stack at the error | none | yes | yes |
| Which frames longjmp dropped | none | none | yes |
| Return value at each stop | none | none | yes |
| Stack at crash | yes | yes | yes |
| Breakpoints | 1 | 476 | 476 + 6 finish |
| Time | 0.3 s | 0.59 s | 0.57 s |

Conclusion: the two core questions (where did it go, why did it stop) do not depend on target; target only adds one more layer, "the return value at each stop".
So target should become an optional parameter.
