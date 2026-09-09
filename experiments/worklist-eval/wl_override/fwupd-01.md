Deterministic static analysis (harness-anchored code-property-graph worklist).
Entry: LLVMFuzzerTestOneInput. 1 functions reachable from the harness; 0 candidate fault sinks in them.

No reachable memory-safety sink was resolved from this harness by static name-based reachability (the entry dispatches through indirect/callback tables the pass does not cross). Fall back to reading the harness and the code it drives.
