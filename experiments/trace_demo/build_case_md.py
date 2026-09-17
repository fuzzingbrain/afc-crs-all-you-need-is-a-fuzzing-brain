#!/usr/bin/env python3
"""Build CASE-libpng-short.md by actually running every command it shows.

Every command in the file is raw and self-contained: no run.sh, no
make_input.py, nothing hidden. The only files referenced are the graded
binary (bin/libpng-01/asan/harness) and tracer.py, which is printed in full
at the end.

    python3 build_case_md.py
"""
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
OUT = HERE / "CASE-libpng-short.md"

GEN_INPUT = r'''python3 - <<'EOF'
import struct, zlib
sig  = b"\x89PNG\r\n\x1a\n"                                   # 8-byte PNG signature
ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)            # 1x1, 8-bit, RGB
data = b"IHDR" + ihdr
chunk = struct.pack(">I", len(ihdr)) + data + struct.pack(">I", zlib.crc32(data) & 0xffffffff)
tail = b"\x00" * 12                                            # the harness reads 12 bytes of control parameters from the tail
open("out/libpng-short.bin", "wb").write(sig + chunk + tail)
EOF
od -An -tx1 out/libpng-short.bin'''

RUN_BARE = r'''ASAN_OPTIONS=detect_leaks=0 ./bin/libpng-01/asan/harness out/libpng-short.bin; echo "exit code: $?"'''

GDB_BARE = r'''ASAN_OPTIONS=detect_leaks=0 gdb -q -batch -ex "run out/libpng-short.bin" --args ./bin/libpng-01/asan/harness'''

GDB_OLD = r'''cat > /tmp/fb_trace.gdb <<'EOF'
set pagination off
set confirm off
set breakpoint pending on
break png_read_IDAT_data
commands
  printf "@@REACHED png_read_IDAT_data@@\n"
  info args
  bt 4
  continue
end
run out/libpng-short.bin
printf "@@ENDED@@\n"
bt 8
EOF
ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 gdb -q -batch -x /tmp/fb_trace.gdb --args ./bin/libpng-01/asan/harness'''

GDB_NEW_NOTGT = r'''ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 FB_INPUT=out/libpng-short.bin FB_FILES=/src/ FB_TARGETS= gdb -q -batch -x tracer.py --args ./bin/libpng-01/asan/harness'''

GDB_NEW_TGT = r'''ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 FB_INPUT=out/libpng-short.bin FB_FILES=/src/ FB_TARGETS=png_sig_cmp,png_read_info,png_handle_IHDR,png_read_IDAT_data gdb -q -batch -x tracer.py --args ./bin/libpng-01/asan/harness'''

SECTIONS = [
    ("1. Generate the input",
     GEN_INPUT,
     "Signature + one IHDR chunk + a 12-byte control tail, 45 bytes in total. No IDAT, no IEND."),

    ("2. Run the harness directly, no gdb",
     RUN_BARE,
     "This is everything `./submit` sees: libpng prints one `read error` line, exit code 0, no sanitizer report. "
     "The model is only told \"clean\". `ASAN_OPTIONS=detect_leaks=0` turns off the leak scan at exit, matching how the bench grades."),

    ("3. gdb with no script, just run",
     GDB_BARE,
     "gdb does nothing, because nobody told it where to stop. The program output is the same as in section 2, plus a few gdb lines about threads. "
     "`-batch` exits when done instead of dropping into the prompt; `-ex` runs one command; `--args` is followed by the program being debugged."),

    ("4. gdb + the bench's existing trace script (1 breakpoint)",
     GDB_OLD,
     "This is the script trace_blob in grader.py generates today, word for word, with png_read_IDAT_data as the target. "
     "`-x file` runs the gdb commands in that file after startup. "
     "Result: the breakpoint never hit (the input never reached png_read_IDAT_data), so there is only @@ENDED@@ and no @@REACHED@@. "
     "tools._parse_trace turns this into one line for the model: reached png_read_IDAT_data: no. Not a word about where it actually went or why it did not get there. "
     "The trailing `No stack.` is `bt 8` erroring because the process has already exited; harmless."),

    ("5. gdb + tracer.py, no target",
     GDB_NEW_NOTGT,
     "`-x tracer.py`: the .py suffix makes gdb run it with its built-in Python. The three FB_ variables are the parameters tracer.py reads: "
     "FB_INPUT is the input file, FB_FILES puts a breakpoint on every function under those source paths, FB_TARGETS is empty. "
     "Before @@TRACE_JSON@@ is the same program output as section 3; after it is the JSON the tracer adds. "
     "Even with no target you get: the full call sequence seq, per-function hit counts, the arguments and call stack at the png_error stop point, and the longjmp."),

    ("6. gdb + tracer.py, with 4 targets",
     GDB_NEW_TGT,
     "On top of section 5 this adds the entry arguments (args on the call events) and return values (ret events) of those 4 functions, "
     "plus the frame that longjmp dropped (ret_lost). png_read_IDAT_data is in the targets but never appears: it was never reached."),
]

HOWTO = """
---

## 7. 怎么读第 5、6 节的 JSON

| 事件 | 含义 |
|---|---|
| `setup` | 项目里有多少函数、设了多少断点、target 是谁 |
| `call` | 进入了一个 target 函数；`args` 是入口参数 |
| `ret` | 一个 target 函数正常返回；`value` 是返回值，`to` 是返回到调用者的哪一行 |
| `ret_lost` | 一个 target 函数的帧没有正常返回就消失了（longjmp / 异常 / abort） |
| `stop` | 程序放弃的那一刻：longjmp / abort / 异常 / exit 被调用；`stack` 是当时的调用栈，项目内每一帧都带参数，错误信息就在其中某一帧的参数里 |
| `signal` | 进程收到信号（崩溃时才有），带调用栈 |
| `exit` | 结局（exited / signal / timeout）、退出码、总命中数、总耗时 |
| `seq` | 完整调用序列，`函数名:栈深度`，按时间顺序 |
| `counts` | 每个函数被调用的次数，以及被热循环上限截断的函数 |

本例的结论，全部来自第 6 节的 JSON：

```
png_sig_cmp        返回 0            签名对
png_read_info      进入
png_handle_IHDR    返回 handled_ok   IHDR 解析成功
stop: longjmp，当时的栈（项目帧，带参数）：
  png_longjmp (pngerror.c:670)
  png_default_error (pngerror.c:660)   error_message="read error"
  png_error (pngerror.c:60)            error_message="read error"
  user_read_data (harness.cc:67)       harness 的读回调：要读的字节比剩下的多
  png_read_chunk_header (pngrutil.c:196)  正在读第 2 个块的头
  png_read_info (pngread.c:118)
png_read_info      ret_lost           被 longjmp 丢掉
png_read_IDAT_data 没出现             没到
退出码 0
```

也就是：IHDR 之后 libpng 在等第二个块，输入到此为止。在 IHDR 后面接一个块就能再往前走。

`exit` 和 `_exit` 的 stop 事件是 libFuzzer 正常收尾时调的，栈里没有项目帧，agent 侧生成摘要时会忽略。

agent 侧（`fbagent/tools.py` 的 `_summarize_trace`）把这些事件翻译成给模型的几十行文字；
`python3 -m pytest FuzzingBrain-Agent/tests/test_trace.py` 用本目录的输出作为固定样本检查那段文字。
"""


def run(cmd: str) -> str:
    # 2>&1 inside the shell so stdout/stderr interleave exactly as in a terminal
    r = subprocess.run(["bash", "-c", "{ " + cmd + "\n} 2>&1"], cwd=HERE,
                       capture_output=True, text=True, timeout=600)
    return r.stdout.rstrip("\n")


def main() -> None:
    parts = [
        "# Case: libpng-short, one input run five ways, each with the command and its full output\n",
        "Challenge libpng-01. The binary is the harness the bench grades with (an ASan libFuzzer binary), copied out of the image and run directly on this host.\n",
        "All commands run from this directory; copy them one at a time:\n",
        "```bash\ncd /home/ze/afc-crs-all-you-need-is-a-fuzzing-brain/experiments/trace_demo\n```\n",
        "## 0. Prerequisite, once only: copy the binary out of the image\n",
        "```bash\nid=$(docker create osanzas/fbbench-challenge-libpng-01:latest)\n"
        "docker cp $id:/opt/fbbench/oracle/binaries/vuln bin/libpng-01\n"
        "docker rm $id\nls bin/libpng-01/asan bin/libpng-01/sharedlibs\n```\n",
        "This yields `bin/libpng-01/asan/harness` (the binary) and `bin/libpng-01/sharedlibs/libz.so.1`. "
        "The host already has libz, so no LD_LIBRARY_PATH is needed below.\n",
        "Every section's output is what that command produced, with no lines removed. Addresses and the Seed change from run to run; everything else should match. This file is generated by `python3 build_case_md.py`.\n",
    ]
    for title, cmd, note in SECTIONS:
        out = run(cmd)
        parts.append(f"\n---\n\n## {title}\n\n{note}\n\n```bash\n{cmd}\n```\n\nOutput:\n\n```\n{out}\n```\n")
    parts.append(HOWTO)
    parts.append("\n---\n\n## 8. tracer.py in full\n\n```python\n" + (HERE / "tracer.py").read_text() + "```\n")
    OUT.write_text("\n".join(parts))
    print("wrote", OUT)


if __name__ == "__main__":
    main()
