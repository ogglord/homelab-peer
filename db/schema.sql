-- The peer hub's whole schema. It is applied once to an empty database
-- (internal/store: PRAGMA user_version 0 -> 1); a change to it is a new
-- numbered step in internal/store, never an edit of this file once
-- deployed.
--
-- Every TEXT column is an enum (CHECK ... IN) or length-bounded. No column
-- holds a secret value: the hub hands none over.

-- One row per peer host. instance is the opaque id of the host's current
-- listener and instance_started_at (unix ms) its start time: the newest
-- instance wins (PeerHello). acked_seq is the highest peer_messages.seq the
-- host has acknowledged.
CREATE TABLE peer_hosts (
    name                TEXT PRIMARY KEY CHECK (length(name) BETWEEN 1 AND 64),
    instance            TEXT NOT NULL CHECK (length(instance) <= 128),
    instance_started_at INTEGER NOT NULL,
    last_seen_at        INTEGER NOT NULL,
    acked_seq           INTEGER NOT NULL DEFAULT 0
);

-- Status and result messages awaiting replay to their target. seq is the
-- replay cursor (AUTOINCREMENT: never reused after a prune). sender plus id
-- is the idempotency key. A status carries a phase; a result answers a
-- request and has no phase.
CREATE TABLE peer_messages (
    seq        INTEGER PRIMARY KEY AUTOINCREMENT,
    id         TEXT NOT NULL CHECK (length(id) BETWEEN 1 AND 64),
    kind       TEXT NOT NULL CHECK (kind IN ('status', 'result')),
    request_id TEXT CHECK (length(request_id) <= 64),
    sender     TEXT NOT NULL CHECK (length(sender) BETWEEN 1 AND 64),
    target     TEXT NOT NULL CHECK (length(target) BETWEEN 1 AND 64),
    phase      TEXT CHECK (phase IN ('info', 'started', 'progress', 'blocked', 'done', 'failed')),
    body       TEXT CHECK (length(body) <= 16384),
    created_at INTEGER NOT NULL,
    delivered  BOOLEAN NOT NULL DEFAULT FALSE,
    read       BOOLEAN NOT NULL DEFAULT FALSE,
    UNIQUE (sender, id),
    CHECK ((kind = 'status') = (phase IS NOT NULL)),
    CHECK (kind <> 'result' OR request_id IS NOT NULL)
);
CREATE INDEX peer_messages_target_seq ON peer_messages (target, seq);
CREATE INDEX peer_messages_target_read ON peer_messages (target, read);
CREATE INDEX peer_messages_request ON peer_messages (request_id) WHERE request_id IS NOT NULL;

-- The outcome of every accepted message id, kept 7 days: a retry with the
-- same sender and id replays it, one whose kind or target differs is a
-- conflict.
CREATE TABLE peer_message_outcomes (
    sender     TEXT NOT NULL CHECK (length(sender) BETWEEN 1 AND 64),
    id         TEXT NOT NULL CHECK (length(id) BETWEEN 1 AND 64),
    kind       TEXT NOT NULL CHECK (kind IN ('request', 'status')),
    target     TEXT NOT NULL CHECK (length(target) BETWEEN 1 AND 64),
    request_id TEXT CHECK (length(request_id) <= 64),
    outcome    TEXT NOT NULL CHECK (outcome IN ('stored')),
    created_at INTEGER NOT NULL,
    PRIMARY KEY (sender, id)
);
CREATE INDEX peer_outcomes_created ON peer_message_outcomes (created_at);

-- Requests. state is the lifecycle (internal/peer/request.go has the
-- transition table); expires_at is when the hub ends a non-terminal request
-- nothing moved, NULL once terminal. step, park_reason and summary are what
-- the run reported; run_token_hash is the SHA-256 of the per-run token,
-- never the token. park_kind is the kind of the current or last park,
-- fingerprint the hex value a decision must name (the step hash, or the
-- SHA-256 of limit:<round>). spent_usd is the run's cumulative cost and
-- used_seconds its run time, against the allowance an approved limit park
-- raises. prompt_id is the approval prompt's id on the Hemma hub.
CREATE TABLE peer_requests (
    id                TEXT PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 64),
    sender            TEXT NOT NULL CHECK (length(sender) BETWEEN 1 AND 64),
    target            TEXT NOT NULL CHECK (length(target) BETWEEN 1 AND 64),
    text              TEXT NOT NULL CHECK (length(text) BETWEEN 1 AND 16384),
    state             TEXT NOT NULL CHECK (state IN ('waiting', 'delivered', 'running', 'parked', 'approved', 'done', 'failed', 'denied', 'expired')),
    attempt           INTEGER NOT NULL DEFAULT 0,
    instance          TEXT CHECK (length(instance) <= 128),
    run_token_hash    TEXT CHECK (length(run_token_hash) <= 64),
    delivered_at      INTEGER,
    claimed_at        INTEGER,
    expires_at        INTEGER,
    approval_cycles   INTEGER NOT NULL DEFAULT 0 CHECK (approval_cycles >= 0),
    tool              TEXT CHECK (length(tool) <= 128),
    step              TEXT CHECK (length(step) <= 8192),
    step_hash         TEXT CHECK (length(step_hash) <= 64),
    notified_at       INTEGER,
    parent_id         TEXT CHECK (length(parent_id) <= 64) REFERENCES peer_requests (id) ON DELETE RESTRICT,
    reason            TEXT CHECK (reason IN ('listener_lost', 'timeout', 'run_failed', 'no_output', 'invalid_output', 'gate_unverified')),
    summary           TEXT CHECK (length(summary) <= 4096),
    created_at        INTEGER NOT NULL,
    updated_at        INTEGER NOT NULL,
    park_kind         TEXT CHECK (park_kind IN ('step', 'limit')),
    fingerprint       TEXT CHECK (length(fingerprint) <= 64),
    park_reason       TEXT CHECK (length(park_reason) <= 300),
    spent_usd         REAL NOT NULL DEFAULT 0 CHECK (spent_usd >= 0),
    used_seconds      INTEGER NOT NULL DEFAULT 0 CHECK (used_seconds >= 0),
    allowance_usd     REAL NOT NULL DEFAULT 10 CHECK (allowance_usd >= 0),
    allowance_seconds INTEGER NOT NULL DEFAULT 7200 CHECK (allowance_seconds >= 0),
    prompt_id         TEXT CHECK (length(prompt_id) <= 128),
    CHECK ((expires_at IS NULL) = (state IN ('done', 'failed', 'denied', 'expired'))),
    CHECK ((reason IS NOT NULL) = (state = 'failed')),
    CHECK (state <> 'running' OR (instance IS NOT NULL AND run_token_hash IS NOT NULL AND claimed_at IS NOT NULL))
);
CREATE INDEX peer_requests_target_state ON peer_requests (target, state, expires_at);
CREATE INDEX peer_requests_expires ON peer_requests (expires_at) WHERE expires_at IS NOT NULL;
CREATE INDEX peer_requests_token ON peer_requests (run_token_hash) WHERE run_token_hash IS NOT NULL;
CREATE INDEX peer_requests_parent ON peer_requests (parent_id) WHERE parent_id IS NOT NULL;

-- Small keyed state: the enrolled approver phone (peer_approver), the Hemma
-- decisions cursor and the recently applied decisions.
CREATE TABLE meta (
    key   TEXT PRIMARY KEY CHECK (length(key) BETWEEN 1 AND 64),
    value TEXT NOT NULL CHECK (length(value) <= 65536)
);
