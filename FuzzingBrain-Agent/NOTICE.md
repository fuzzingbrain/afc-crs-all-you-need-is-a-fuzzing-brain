# Attribution

fb-agent is a fork of **mini-swe-agent**, by Kilian A. Lieret and Carlos E.
Jimenez (SWE-agent).

- Upstream: https://github.com/SWE-agent/mini-swe-agent
- Docs: https://mini-swe-agent.com/latest/
- Forked from: v2.4.6, commit `04d809ceab9df28f9adaed044884180159172930` (see
  `UPSTREAM_COMMIT`)

mini-swe-agent is MIT licensed and its licence is reproduced in full in
`LICENSE.md`, which is the licence this fork is distributed under. The original
copyright notice is retained there unchanged.

Almost all of the code here is theirs. The agent loop, the environments, the
model layer, the config system and the test suite are upstream's work; our
changes sit on top and are visible as the commits after the initial import.

The Python import path is still `minisweagent`, deliberately: it keeps the
lineage obvious in every file, and renaming 712 import sites would turn every
future merge from upstream into a conflict for no functional gain. Only the
name the agent goes by -- the package, the banner, the trajectory format, the
console script -- is fb-agent.
