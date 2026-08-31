# Working in this repository

## Commits

Never add `Co-Authored-By: Claude ...` or `Claude-Session: ...` trailers to
commit messages. Write the message and stop.

## Runs

Do not start FuzzingBrain runs, benchmark sweeps, or the full test suite unless
asked. When a run is authorised, set concurrency to 1 (`"concurrency": 1` in the
task file sets every knob at once) and use `--budget 20` unless told otherwise.

This host has 62 GB, no swap, and is shared with other work. It was livelocked
into a power-cycle on 2026-08-31. Anything launched in the background gets a
`timeout`; anything spawning containers goes through `docker_resource_args()`.

## Branches

Several Claude sessions share `/home/ze/afc-crs-all-you-need-is-a-fuzzing-brain`.
Do not run `git checkout` there — a switch moves HEAD out from under another
session. `/home/ze/fbv2` is a separate clone that stays on `main`; work there and
push straight to main.
