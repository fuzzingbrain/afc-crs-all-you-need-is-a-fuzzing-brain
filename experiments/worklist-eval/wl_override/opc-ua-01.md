Deterministic static analysis (harness-anchored code-property-graph worklist).
Entry: LLVMFuzzerTestOneInput. 8 functions reachable from the harness; 36 candidate fault sinks in them.
Below: reachable functions that contain a memory-safety sink (array index / pointer deref / dangerous call) or sit on a recursion cycle, nearest-first by call-graph distance. Read each, build an input that reaches it, verify with ./submit. Aim for sinks in DIFFERENT functions/files to score distinct crashes.

[d 0] LLVMFuzzerTestOneInput  (harness.cc:26,28,31)  [addressOf,memset]
[d 1] UA_NetworkMessage_decodeJson  (ua_pubsub_networkmessage_json.c:532,535,543,547)  [addressOf,indirection,memset]
[d 2] NetworkMessage_decodeJsonInternal  (ua_pubsub_networkmessage_json.c:451,460,463,475,478,479,505,506,507,508,512,516)  [addressOf,indirectIndexAccess,memset]
[d 2] tokenize  (ua.c:907,909,912,913,921,928,945)  [indirectIndexAccess,indirection]
