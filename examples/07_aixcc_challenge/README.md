# AIxCC challenge — curl `cu-delta-02`

A delta scan of a real AIxCC Final Competition challenge, against the public
challenge repositories. Nothing here is local to one machine:

```bash
./FuzzingBrain.sh examples/07_aixcc_challenge/cu-delta-02.json
```

## Why this is the reference example

Every reference in this file is pinned, which is the whole point. An OSS-Fuzz
project that clones its dependencies at `master` builds differently on different
days — the `libpng` demo target used elsewhere in `examples/` copies its
`build.sh` out of `pnggroup/libpng@master`, so upstream tooling now compiles a
harness the scanned commit does not contain, and the build fails. A challenge
cannot drift like that: `.aixcc/challenge.yaml` names the exact `base_ref`,
`delta_ref` and `fuzz_tooling_ref`, and this config repeats them as commit SHAs.

It also exercises the parts of the system a plain repository never reaches: the
challenge ships `.aixcc/` containing the vulnerability's location, a reference
PoV blob and the reference patch, so the run has something real to strip. The
posture banner is where you confirm it did:

```
.aixcc         removed (1 path)
.git           kept (remove_git off)
workspace      confined to curl_<task_id>/repo
```

If that line reads `not present`, sanitisation did not run and the findings from
that run mean nothing.

## The target

| | |
|---|---|
| Challenge | `cu-delta-02` — curl-006, "medium difficulty crash" |
| Defect | CWE-476, NULL pointer dereference |
| Location | `lib/totallyfineprotocl.c:228-232` |
| Harness | `curl_fuzzer_ws` |
| Trigger | the server writing a specific response mid-connection |

The delta adds 613 lines across 17 files, including a whole invented protocol
and a test server for it. This is not a bug blind fuzzing stumbles over: the
reference PoV is 155 bytes of structured WebSocket input.

Knowing the answer is what makes the example useful — you can tell whether a run
worked. The system never sees any of it; `.aixcc` is deleted before the build,
and the agents' file tools refuse any path containing `.aixcc` or `.git`.

## Scope

One harness and one sanitizer, so one worker:

```json
"sanitizers": ["address"],
"fuzzers": ["curl_fuzzer_ws"]
```

`curl_fuzzer_ws` is the harness the challenge's own `vuln.yaml` names for this
PoV. The challenge defines seventeen; a competition run dispatches a worker per
`{fuzzer, sanitizer}` pair, and dropping `"fuzzers"` from the config does that
here. Start with one — it is the pair that reaches curl-006, and it keeps the
first run cheap enough to read end to end.

## Naming the harness source

```json
"fuzzer_sources": {
  "curl_fuzzer_ws": [
    ".../curl_fuzzer/curl_fuzzer.cc",
    ".../curl_fuzzer/curl_fuzzer.h"
  ]
}
```

Paths resolve against the workspace, so a path under `fuzz-tooling/` or `repo/`
works. This is worth setting explicitly whenever a harness is more than one
file, and curl is the case that shows why.

curl builds all seventeen of its named harnesses from a single
`curl_fuzzer.cc`, which reads its input as a TLV stream — and every TLV type
number is a `#define` in `curl_fuzzer.h`. Given only the `.cc`, an agent has to
infer that table. It infers the obvious thing: that the server-response slots
run consecutively from `TLV_TYPE_RESPONSE0 = 2`. They do not — slot 0 is 2 and
the rest jump to 17, 18, 19, with 3, 4 and 5 meaning USERNAME, PASSWORD and
POSTFIELDS. An agent working from that guess writes an input that is otherwise
completely correct, down to the trigger string and its CRLF, and puts it in a
POST body. Nothing crashes, and the run looks like a failure of reasoning
rather than a missing header.

## Cost and time

`budget_limit` is USD of LLM spend and a hard stop, not a hint. The build
dominates a first run: the Docker image takes about four minutes and the
seventeen fuzzers about five, both cached afterwards.

## Other challenges

The same shape works for any AIxCC challenge — copy the config and replace the
four refs with the ones in that challenge's `.aixcc/challenge.yaml`, and the
harness with the one its `vuln.yaml` names.
