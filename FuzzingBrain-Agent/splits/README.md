# Challenge splits

The bench's 77 challenges, split in two so tuning and scoring do not happen on
the same bugs.

- **`dev.txt`** (41) — tune here: prompts, budgets, tools. Look at these runs as
  much as you like.
- **`test.txt`** (36) — held out. Run it only to measure, at the end, and do not
  tune against what you see. A score on test means something because the agent
  was not shaped to those specific bugs; a score on dev does not.

The split is **stratified by difficulty** (the frozen 1–5 coefficient in the
bench's `difficulty.json`): within each difficulty level the bugs alternate
between dev and test by name, so both halves carry the same mix of easy and hard
challenges.

## Running a split

```bash
cd <bench>
./fb-bench run $(grep -v '^#' /path/to/splits/dev.txt | paste -sd,) --agent fbagent-native --jobs 4
```

`grep -v '^#'` drops the comment header; `paste -sd,` joins the names into the
comma list `fb-bench run` takes.
