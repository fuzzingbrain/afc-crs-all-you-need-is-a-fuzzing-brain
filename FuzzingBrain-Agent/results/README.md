# Runs

One record per challenge the agent has actually solved, kept so a claim in the
README can be checked rather than taken.

## avro-03 — solved

| | |
|---|---|
| Fault | out-of-memory, `malloc(4294967297)` from a 7-byte input |
| Location | `src/lang/c/src/encoding_binary.c:179`, `read_string` |
| Candidates | 1 |
| Wall clock | 135s |
| Network | blocked |
| Tools | read, glob, grep, bash |

```
00 02 80 80 80 80 20
│  │  └─ zigzag(0x100000000) — the key's string length, 4 GiB
│  └──── zigzag(1) — the map holds one entry
└─────── schema selector, consumed by the harness
```

The harness fixes the schema to `{"type":"map","values":"string"}`, so the path
is `avro_value_read` → `read_map_value` → `read_string`, and `read_string` does:

```c
*len = str_len + 1;
*s = (char *) avro_malloc(*len);
```

`str_len` is a zigzag varint taken straight from the input and never checked
against the bytes actually remaining. The agent reported the same pattern is
reachable through the map's value string and through `read_bytes`
(`encoding_binary.c:129`).

Worth noting for reading the number: this was the first candidate it built. The
agent read the harness, followed it into the source, named the fault and the
line, and then wrote the input — the 135 seconds are mostly reading, not search.
