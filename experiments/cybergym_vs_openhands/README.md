# CyberGym vs OpenHands (RQ5) — apple-to-apple harness

Runs FBv2 and OpenHands head-to-head on CyberGym/ARVO historical vulns under
identical information, model (o3), budget ($50), environment, and oracle. See
`../../paper/fbv2_new_paper/docs/RQ5_CYBERGYM_VS_OPENHANDS_ZH.md` for the protocol.

- `broker.py` — host-side candidate-testing service = FBv2 `create_pov` equivalent
  for OpenHands. POST raw bytes to `/test`; runs them in the sanitized vul image's
  harness; returns {crashed, crash_fn, crash_loc, sanitizer}. Fixed image+harness,
  answers removed, so no docker/answer leakage to the agent.
- `setup_cg_task.py <arvo_id> <port>` — build sanitized image, extract source,
  write TASK.md + test_pov.sh into the OpenHands workspace.
- `oh_run_<id>.sh` — OpenHands 0.58 headless run (needs
  `--add-host host.docker.internal:host-gateway` + `SANDBOX_LOCAL_RUNTIME_URL`).
- `grade.py <arvo_id> <pov>` — the shared oracle: crash the -vul image, NOT the
  -fix image, and the #0 application frame must match the official crash function.
- `results/` — per-task manifests + the winning PoV blobs.
