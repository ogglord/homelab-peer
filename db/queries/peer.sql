-- Compare-and-replace of the host's listener instance. Instance ids are
-- opaque; "newer" means a start time (unix ms) at or after the stored one, so
-- the current instance can re-hello and a superseded instance is refused.
-- Returns 0 rows when refused.
-- name: PeerHello :execrows
INSERT INTO peer_hosts (name, instance, instance_started_at, last_seen_at) VALUES (?, ?, ?, ?)
ON CONFLICT (name) DO UPDATE SET
    instance = excluded.instance, instance_started_at = excluded.instance_started_at,
    last_seen_at = excluded.last_seen_at
WHERE excluded.instance_started_at >= peer_hosts.instance_started_at;

-- name: GetPeerHost :one
SELECT * FROM peer_hosts WHERE name = ?;

-- The acknowledged sequence only moves forward.
-- name: AdvancePeerAckedSeq :exec
UPDATE peer_hosts SET acked_seq = MAX(acked_seq, CAST(sqlc.arg(seq) AS INTEGER)) WHERE name = sqlc.arg(name);

-- name: InsertPeerMessage :one
INSERT INTO peer_messages (id, kind, request_id, sender, target, phase, body, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
RETURNING seq;

-- Status and results for a host after its cursor, in sequence order.
-- name: ReplayPeerMessages :many
SELECT * FROM peer_messages
WHERE target = sqlc.arg(target) AND seq > sqlc.arg(after) AND kind IN ('status', 'result')
ORDER BY seq LIMIT sqlc.arg(limit);

-- name: GetPeerMessageOutcome :one
SELECT * FROM peer_message_outcomes WHERE sender = ? AND id = ?;

-- name: InsertPeerMessageOutcome :exec
INSERT INTO peer_message_outcomes (sender, id, kind, target, request_id, outcome, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?);

-- Messages past retention that belong to no request row: standalone status,
-- and every message of a request already pruned. A message of a request that still
-- exists goes with that request.
-- name: PrunePeerMessages :execrows
DELETE FROM peer_messages
WHERE peer_messages.created_at < sqlc.arg(cutoff)
  AND (peer_messages.request_id IS NULL OR peer_messages.request_id NOT IN (SELECT r.id FROM peer_requests r));

-- name: PrunePeerOutcomes :execrows
DELETE FROM peer_message_outcomes WHERE created_at < ?;

-- name: GetPeerMessage :one
SELECT * FROM peer_messages WHERE sender = ? AND id = ?;

-- Unread status and results addressed to a host, oldest first.
-- name: ListPeerInbox :many
SELECT * FROM peer_messages WHERE target = ? AND NOT read ORDER BY seq LIMIT ?;

-- name: MarkPeerMessageRead :exec
UPDATE peer_messages SET read = TRUE WHERE seq = ?;

-- Everything a host acknowledged has been delivered.
-- name: MarkPeerMessagesDelivered :exec
UPDATE peer_messages SET delivered = TRUE
WHERE target = sqlc.arg(target) AND seq <= sqlc.arg(seq) AND NOT delivered;

-- name: ListPeerHosts :many
SELECT * FROM peer_hosts ORDER BY name;

-- name: ListRecentPeerMessages :many
SELECT * FROM peer_messages ORDER BY seq DESC LIMIT ?;

-- name: ListRecentPeerOutcomes :many
SELECT * FROM peer_message_outcomes ORDER BY created_at DESC, sender, id LIMIT ?;

-- Requests. Every UPDATE below is one compare-and-set naming its from-states;
-- the transition table is in internal/peer/request.go. FinishPeerRequest is
-- the only statement that writes a terminal state.

-- A request as sent (waiting).
-- name: InsertPeerRequest :exec
INSERT INTO peer_requests (id, sender, target, text, state, expires_at, parent_id, created_at, updated_at)
VALUES (sqlc.arg(id), sqlc.arg(sender), sqlc.arg(target), sqlc.arg(text), sqlc.arg(state),
        sqlc.arg(expires_at), sqlc.narg(parent_id), sqlc.arg(created_at), sqlc.arg(updated_at));

-- name: GetPeerRequest :one
SELECT * FROM peer_requests WHERE id = ?;

-- name: GetPeerRequestByToken :one
SELECT * FROM peer_requests WHERE run_token_hash = ?;

-- Requests a host's listener should be pushed, in arrival order.
-- name: ListPushablePeerRequests :many
SELECT * FROM peer_requests
WHERE target = ? AND state IN ('waiting', 'approved')
ORDER BY created_at, id;

-- waiting|approved -> delivered, after a push. Keeps expires_at: waiting and
-- delivered share one 24 h window, so a request bouncing between them never
-- outlives it.
-- name: MarkPeerRequestDelivered :execrows
UPDATE peer_requests SET state = 'delivered', delivered_at = sqlc.arg(now), updated_at = sqlc.arg(now)
WHERE id = sqlc.arg(id) AND attempt = sqlc.arg(attempt) AND state IN ('waiting', 'approved');

-- delivered -> waiting (or approved, for an approved re-run, which is the
-- only way a queued request has a round), for one host or all, when the
-- push was not claimed: the host said hello again, was busy, its run ended,
-- or the claim timed out. Keeps expires_at.
-- name: RequeuePeerRequests :many
UPDATE peer_requests
SET state = CASE WHEN approval_cycles = 0 THEN 'waiting' ELSE 'approved' END, updated_at = sqlc.arg(now)
WHERE state = 'delivered' AND delivered_at <= sqlc.arg(delivered_before)
  AND (target = sqlc.narg(target) OR sqlc.narg(target) IS NULL)
RETURNING target;

-- waiting|delivered|approved -> running at the pushed attempt, unless the
-- host already has a running request (one run per host).
-- name: ClaimPeerRequest :execrows
UPDATE peer_requests
SET state = 'running', attempt = attempt + 1, instance = sqlc.arg(instance), run_token_hash = sqlc.arg(token_hash),
    claimed_at = sqlc.arg(now), expires_at = sqlc.arg(expires_at), updated_at = sqlc.arg(now)
WHERE peer_requests.id = sqlc.arg(id) AND peer_requests.target = sqlc.arg(target)
  AND peer_requests.attempt = sqlc.arg(attempt) AND peer_requests.state IN ('waiting', 'delivered', 'approved')
  AND NOT EXISTS (SELECT 1 FROM peer_requests r WHERE r.target = sqlc.arg(target) AND r.state = 'running');

-- running -> parked at the run's attempt, instance and token: a new round,
-- not prompted yet. The run's cost is cumulative (kept at its maximum); its
-- run time adds up.
-- name: ParkPeerRequest :execrows
UPDATE peer_requests
SET state = 'parked', approval_cycles = approval_cycles + 1, park_kind = sqlc.arg(park_kind),
    tool = sqlc.narg(tool), step = sqlc.narg(step), step_hash = sqlc.narg(step_hash),
    fingerprint = sqlc.narg(fingerprint), park_reason = sqlc.narg(park_reason),
    spent_usd = MAX(spent_usd, CAST(sqlc.arg(spent_usd) AS REAL)), used_seconds = used_seconds + sqlc.arg(used_seconds),
    expires_at = sqlc.arg(expires_at), updated_at = sqlc.arg(now), notified_at = NULL, prompt_id = NULL
WHERE id = sqlc.arg(id) AND state = 'running' AND attempt = sqlc.arg(attempt) AND instance = sqlc.arg(instance)
  AND run_token_hash = sqlc.arg(token_hash);

-- A run's result reports its cost and run time like a park does.
-- name: AddPeerRequestUsage :exec
UPDATE peer_requests
SET spent_usd = MAX(spent_usd, CAST(sqlc.arg(spent_usd) AS REAL)), used_seconds = used_seconds + sqlc.arg(used_seconds)
WHERE id = sqlc.arg(id);

-- The only writer of terminal states. from_states (a JSON array; sqlc.slice
-- mis-numbers the parameters after it) and every non-null guard must hold:
-- the attempt and instance of a run, a due expiry, a claim older than a
-- lease cutoff.
-- name: FinishPeerRequest :execrows
UPDATE peer_requests
SET state = sqlc.arg(to_state), reason = sqlc.narg(reason), summary = sqlc.narg(summary),
    expires_at = NULL, updated_at = sqlc.arg(now)
WHERE id = sqlc.arg(id) AND state IN (SELECT value FROM json_each(sqlc.arg(from_states)))
  AND (attempt = sqlc.narg(attempt) OR sqlc.narg(attempt) IS NULL)
  AND (instance = sqlc.narg(instance) OR sqlc.narg(instance) IS NULL)
  AND (expires_at <= sqlc.narg(due_by) OR sqlc.narg(due_by) IS NULL)
  AND (claimed_at < sqlc.narg(claimed_before) OR sqlc.narg(claimed_before) IS NULL);

-- name: ListPeerRequestsInState :many
SELECT * FROM peer_requests WHERE target = ? AND state = ? ORDER BY created_at, id;

-- Non-terminal requests whose expiry is due.
-- name: ListDuePeerRequests :many
SELECT * FROM peer_requests WHERE expires_at IS NOT NULL AND expires_at <= ? ORDER BY expires_at, id;

-- name: ListPeerHostsRunning :many
SELECT DISTINCT target FROM peer_requests WHERE state = 'running' ORDER BY target;

-- name: ListRecentPeerRequests :many
SELECT * FROM peer_requests ORDER BY created_at DESC, id LIMIT ?;

-- Terminal requests past retention that no request still names as parent
-- (parent_id restricts). Run until it deletes nothing to clear a chain.
-- name: PrunePeerRequests :execrows
DELETE FROM peer_requests
WHERE peer_requests.state IN ('done', 'failed', 'denied', 'expired') AND peer_requests.updated_at < sqlc.arg(cutoff)
  AND peer_requests.id NOT IN (SELECT c.parent_id FROM peer_requests c WHERE c.parent_id IS NOT NULL);

-- parked -> approved is a decision's compare-and-set on the round and
-- fingerprint it was signed for; an approved limit park raises the
-- allowance in the same statement. parked -> denied goes through
-- FinishPeerRequest like every terminal state.
-- name: ApprovePeerRequest :execrows
UPDATE peer_requests
SET state = 'approved', expires_at = sqlc.arg(expires_at), updated_at = sqlc.arg(now),
    allowance_usd = allowance_usd + sqlc.arg(add_usd), allowance_seconds = allowance_seconds + sqlc.arg(add_seconds)
WHERE id = sqlc.arg(id) AND state = 'parked' AND approval_cycles = sqlc.arg(round) AND fingerprint = sqlc.arg(fingerprint);

-- Every parked request: an approver change moves each to a new round.
-- name: ListParkedPeerRequests :many
SELECT * FROM peer_requests WHERE state = 'parked' ORDER BY updated_at, id;

-- parked at round -> parked at the next round, not prompted yet, with that
-- round's fingerprint.
-- name: ReroundPeerRequest :execrows
UPDATE peer_requests
SET approval_cycles = approval_cycles + 1, fingerprint = sqlc.arg(fingerprint), notified_at = NULL, prompt_id = NULL,
    updated_at = sqlc.arg(now)
WHERE id = sqlc.arg(id) AND state = 'parked' AND approval_cycles = sqlc.arg(round);

-- Parked requests whose approval prompt was never delivered.
-- name: ListUnnotifiedParkedPeerRequests :many
SELECT * FROM peer_requests WHERE state = 'parked' AND notified_at IS NULL ORDER BY updated_at, id;

-- name: SetPeerRequestNotified :execrows
UPDATE peer_requests SET notified_at = sqlc.arg(now), prompt_id = sqlc.narg(prompt_id)
WHERE id = sqlc.arg(id) AND state = 'parked' AND approval_cycles = sqlc.arg(round) AND notified_at IS NULL;

-- Requests in one state, newest first (operator view).
-- name: ListPeerRequestsByState :many
SELECT * FROM peer_requests WHERE state = ? ORDER BY created_at DESC, id LIMIT ?;

-- name: GetMeta :one
SELECT value FROM meta WHERE key = ?;

-- name: SetMeta :exec
INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value;

-- name: DeleteMeta :exec
DELETE FROM meta WHERE key = ?;
