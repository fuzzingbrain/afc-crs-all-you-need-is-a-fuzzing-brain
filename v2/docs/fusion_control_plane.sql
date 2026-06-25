-- SPDX-License-Identifier: Apache-2.0
--
-- FuzzingBrain v2 control-plane schema.
--
-- The single source of truth for all program state. Modeled (as logic, not
-- copied code) on the first-party O2 fuzzdb control plane: structured columns
-- for queryable / constrained fields, JSONB `extra` for long-tail metadata.
--
-- Work unit invariant: 1 logic_group = 1 harness = 1 pipeline unit.
-- Stages hand off ONLY by mutating these rows; they never call each other.

-- ── breadth: target carving ────────────────────────────────────────────────

CREATE TABLE project (
    id           TEXT PRIMARY KEY,           -- e.g. "libyaml"
    language     TEXT NOT NULL,              -- c | cpp | java | ...
    repo_url     TEXT,
    oss_fuzz     BOOLEAN NOT NULL DEFAULT FALSE,
    track        TEXT NOT NULL DEFAULT 'oss-fuzz',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    extra        JSONB NOT NULL DEFAULT '{}'
);

-- A Logic Group is one attack-surface unit. It is the pipeline work unit and
-- carries its own pipeline state on these columns.
CREATE TABLE logic_group (
    id               TEXT PRIMARY KEY,
    project_id       TEXT NOT NULL REFERENCES project(id),
    name             TEXT NOT NULL,
    entry_functions  JSONB NOT NULL DEFAULT '[]',   -- public entry points
    core_functions   JSONB NOT NULL DEFAULT '[]',   -- security-relevant core
    risk_score       REAL NOT NULL DEFAULT 0,
    overlap_check    JSONB,                          -- novelty/dedup evidence (gate)
    -- pipeline state (the orchestrator reads/writes these)
    pipeline_stage   TEXT NOT NULL DEFAULT 'explore',
    pipeline_status  TEXT NOT NULL DEFAULT 'pending', -- pending|running|done|parked
    pipeline_attempts INTEGER NOT NULL DEFAULT 0,
    pipeline_note    TEXT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    extra            JSONB NOT NULL DEFAULT '{}'
);

CREATE TABLE harness (
    id            TEXT PRIMARY KEY,
    logic_group_id TEXT NOT NULL UNIQUE REFERENCES logic_group(id), -- 1 LG = 1 harness
    source_path   TEXT,
    corpus_source TEXT,                          -- where starting seeds came from
    corpus_coverage REAL,                        -- coverage of the starting corpus (gate)
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    extra         JSONB NOT NULL DEFAULT '{}'
);

CREATE TABLE harness_build (
    id          BIGSERIAL PRIMARY KEY,
    harness_id  TEXT NOT NULL REFERENCES harness(id),
    sanitizer   TEXT NOT NULL DEFAULT 'address', -- address|memory|undefined
    engine      TEXT NOT NULL DEFAULT 'libfuzzer',
    status      TEXT NOT NULL DEFAULT 'pending', -- pending|ok|failed
    smoke_ok    BOOLEAN NOT NULL DEFAULT FALSE,
    log_path    TEXT,
    built_at    TIMESTAMPTZ,
    extra       JSONB NOT NULL DEFAULT '{}'
);

-- ── depth: fuzzing + SP brain ───────────────────────────────────────────────

CREATE TABLE fuzz_run (
    id          BIGSERIAL PRIMARY KEY,
    harness_id  TEXT NOT NULL REFERENCES harness(id),
    kind        TEXT NOT NULL DEFAULT 'discovery', -- discovery (prep) | resident (run)
    started_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    ended_at    TIMESTAMPTZ,
    coverage    JSONB,                            -- covered edges/functions snapshot
    extra       JSONB NOT NULL DEFAULT '{}'
);

-- A Suspicious Point: a structured vulnerability hypothesis. The shared
-- currency between the fuzzer and the SP brain.
CREATE TABLE suspicious_point (
    id                TEXT PRIMARY KEY,
    logic_group_id    TEXT NOT NULL REFERENCES logic_group(id),
    function_name     TEXT,
    location          TEXT,        -- control-flow description, not line numbers
    vuln_type         TEXT,        -- CWE id
    trigger_condition TEXT,        -- input constraints to reach/trigger
    score             REAL NOT NULL DEFAULT 0,
    status            TEXT NOT NULL DEFAULT 'pending_verify', -- lifecycle
    verdict           TEXT,        -- tp | fp | unknown
    pov_attempts      INTEGER NOT NULL DEFAULT 0,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    extra             JSONB NOT NULL DEFAULT '{}'
);

-- Append-only audit log of everything that happens to an SP.
CREATE TABLE sp_event (
    id        BIGSERIAL PRIMARY KEY,
    sp_id     TEXT NOT NULL REFERENCES suspicious_point(id),
    kind      TEXT NOT NULL,        -- generated|verified|seeded|candidate|crashed|dropped
    payload   JSONB NOT NULL DEFAULT '{}',
    at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ── unified downstream: crashes → findings ──────────────────────────────────

CREATE TABLE crash (
    id            TEXT PRIMARY KEY,
    harness_id    TEXT NOT NULL REFERENCES harness(id),
    sp_id         TEXT REFERENCES suspicious_point(id),  -- NULL = random fuzzing
    input_path    TEXT NOT NULL,
    sanitizer     TEXT,
    crash_type    TEXT,             -- parsed sanitizer signal
    cluster_id    TEXT,             -- dedup cluster representative
    status        TEXT NOT NULL DEFAULT 'new', -- new|triaged|verifying|finding|dropped
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    extra         JSONB NOT NULL DEFAULT '{}'
);

CREATE TABLE finding (
    id            TEXT PRIMARY KEY,
    crash_id      TEXT NOT NULL REFERENCES crash(id),
    logic_group_id TEXT NOT NULL REFERENCES logic_group(id),
    vuln_type     TEXT,
    repro_path    TEXT,             -- verified reproduction package
    report_path   TEXT,
    recorded_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    extra         JSONB NOT NULL DEFAULT '{}'
);
