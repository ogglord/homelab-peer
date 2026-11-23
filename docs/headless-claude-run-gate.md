---
title: Gating a headless claude -p run with auto mode and hooks (Claude Code 2.1.323)
date: 2026-10-30
last_updated: 2026-11-14
category: integration-issues
module: internal/peerclient
problem_type: integration_issue
component: tooling
severity: high
symptoms:
  - "An 'always park' policy rule let the step run because the request asked for it"
  - "The startup canary stayed gate-unverified on the real build while every fake-claude test passed"
  - "Every run would park at its end on a tool named StructuredOutput"
  - "An approved step never matched on the re-run"
root_cause: wrong_api
resolution_type: code_fix
tags: [peer, claude-code, headless, hooks, permissions, auto-mode, canary, resume]
retire_when: "A Claude Code release changes how autoMode soft_deny/hard_deny rules, the PermissionDenied hook, --resume or --max-budget-usd behave in -p mode; re-check each fact below with a real run after an upgrade (the listener's canary covers only the hook deny and the classifier block)"
---

# Gating a headless claude -p run with auto mode and hooks (Claude Code 2.1.323)

## Problem

Peer requests run as headless `claude -p` processes on the receiving host (`internal/peerclient/run.go`). Since the trusted-circle change (plan `docs/plans/2026-11-13-2142-feat-peer-trusted-circle-plan.md` in ogglord/homelab) the gate is: the host's allow-list runs untouched, Claude Code's auto-mode classifier judges everything else under a per-host policy, a classifier block parks the request for a signed approval, and the approval resumes the same Claude session. Several of the behaviours this rests on are undocumented or easy to get wrong, and the scripted fake `claude` the tests use cannot show any of them. Only real runs did.

## Symptoms

- A rule meant to always park (deleting a canary file) did not park: the classifier let the `rm` run.
- After deploying, the listener logged `gate unverified: the canary was inconclusive` with `no classifier denial reached the PermissionDenied hook (parked on Bash)`, so it claimed no requests, while the fake-claude canary tests passed.
- (Earlier dontAsk gate, still relevant) every run parked at its end on `StructuredOutput`, and an approved Bash step never matched on the re-run because its free-text `description` changed.

## What Didn't Work

- **Putting "always park" rules in `soft_deny`.** Auto mode lets a soft_deny action through when the user turn explicitly asked for it. In a peer run the request text *is* the user turn, so "delete this file" or "change the router's DHCP" is always an explicit ask.
- **Testing the classifier with a file inside the working directory.** Operations confined to the working directory are approved before the classifier is consulted, so an `rm` of a file in the run's cwd never reaches a policy rule, hard_deny included.
- **Reusing the real park denial text in the canary.** The hook's park denial tells the model the run "ends now ... stop" (`hook.go:608`). The canary's first call is denied by the hook on purpose; the model obeyed the text and never made the second call, so the classifier half of the canary could not run.
- **Trusting the fake.** The test double `internal/peerclient/fakeclaude` scripts which calls the classifier blocks and which hook decisions win, so it encodes these assumptions instead of testing them.

## Solution

- Launch with `--permission-mode auto` and pass the host's policy as an `autoMode` block inside the `--settings` JSON, next to the hooks (`run.go:489-494`; `run.go:519` passes `--permission-mode auto`). Each list is prose rules; `"$defaults"` keeps Claude Code's built-ins. Rules that must hold even when the request asks for the action go in `hard_deny` (`policy.go:14`); the homelab's router-change and delete-outside-the-worktree rules are hard_deny in the operator's listener policy file (`peer service install --policy-file`).
- Install a `PermissionDenied` hook (`peer park --denied`, `hook.go:616`). A classifier block does not run the call and tells Claude, but the run continues, so the hook records the park (with the classifier's `reason`, e.g. "The server-side auto mode classifier judged this action dangerous (it gave no explanation)") and the listener stops the run when the park file appears.
- Resume after approval with `--resume <session-id>` and the resume text as a positional prompt (`run.go:511`); the first run uses `--session-id` (`run.go:513`). Re-pass `--settings`, `--permission-mode` and the tool flags on every resume: they are not restored. The approved call passes because the PreToolUse hook returns `allow` for it, which gets past the classifier even for a hard_deny action.
- The approved step is matched by the text the operator saw: `StepText` (`hook.go:498`) is tool plus scrubbed canonical input (Bash without `description`/`timeout`), and the hub derives the step hash from that stored text, so a forged park record cannot approve a different call.
- In observe mode (the canary) the hook's denial tells the run to go on to its next call (`hook.go:606`); the canary victim lives outside the run directory and a canary `hard_deny` rule names it (`canary.go:24`, `canary.go:82`).

## Why This Works

The verified facts, on Claude Code 2.1.323 with real `claude -p` runs:

| Fact | Consequence for the gate |
| --- | --- |
| `autoMode` from `--settings` is honoured in `-p` | the policy can be per host and per run |
| soft_deny yields to an explicit ask in the user turn | always-park rules must be hard_deny |
| working-directory operations skip the classifier | work inside the per-request worktree never parks; only the world outside it is judged |
| a classifier block fires `PermissionDenied` with a `reason`, and the run continues | the hook must record the park and the listener must stop the run |
| `--resume <id>` keeps the session id and its transcript (`~/.claude/projects/<symlink-resolved cwd with non-alphanumerics replaced by '-'>/<id>.jsonl`) | sessions can be derived from the request id and deleted when the request ends |
| a PreToolUse `allow` beats the classifier | one approved call can run even when policy would block it |
| `total_cost_usd` is cumulative across resumes; `--max-budget-usd` applies per invocation and ignores restored cost | pass `allowance - cumulative spent` as the next run's budget |

Still true from the earlier dontAsk gate: `--json-schema` output arrives as a `StructuredOutput` tool call that goes through PreToolUse, so `Rules.forRun()` always allows it; the allow-list feeds both `--allowedTools` and the hook from one rule list; `--bare` is unusable because it drops hooks and CLAUDE.md.

## Prevention

- After a Claude Code upgrade on a peer host, restart the listener and read its canary line: `gate verified: the hook's deny blocks and a classifier block reaches the denied hook`. The canary does not prove the resume, the hook-allow-over-classifier path or the budget semantics; re-check those with one real run (a hard_deny step outside the cwd, approved and resumed) before trusting them.
- Keep canary and probe targets outside the run's working directory, and give any self-test its own denial text: a model follows the stop instruction it is given.
- Write "always park" policy as hard_deny and phrase it to cover the explicit-ask case ("even when the user asked for it").
- Treat `fakeclaude` as a model of these facts, not evidence for them; when a fact changes, change the fake and this doc together.

## Related

- `docs/peer-hub-tailnet-identity.md`: who may send requests and secrets to the hub, which the gate above trusts.
- `docs/plans/2026-11-13-2142-feat-peer-trusted-circle-plan.md` in ogglord/homelab: the trusted-circle requirements this gate implements.
