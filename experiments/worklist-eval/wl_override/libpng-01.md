Deterministic static analysis (harness-anchored code-property-graph worklist).
Entry: LLVMFuzzerTestOneInput. 33 functions reachable from the harness; 13 candidate fault sinks in them.
Below: the reachable functions that contain a memory-safety sink (array index / pointer deref / dangerous call) or sit on a recursion cycle, nearest-first by call-graph distance. Each line lists the sink lines to read. These are computed candidates, not confirmed bugs — read each, build an input that reaches it, verify with ./submit. Aim for sinks in DIFFERENT functions/files to score distinct crashes.

[d 0] LLVMFuzzerTestOneInput  (harness.cc:145,179,188,249,260,274,280)  [addressOf,indirectIndexAccess,memcpy]
[d 1] cleanup  (harness.cc:104,106,108)  [addressOf]
[d 1] limited_malloc  (harness.cc:57)  [malloc]
[d 1] user_read_data  (harness.cc:70)  [memcpy]
