---
name: peer
description: Ask another host's agent to do something, or send a status note, through the homelab peer hub with the `peer` CLI. Use when work needs the Home Assistant box (or another peer host), or when the user mentions peer requests, approvals or the peer hub.
---

# peer — work across hosts through the peer hub

The peer hub (the `peer` stack on homelab, tailnet node `homelab-hub`) is the
only way across hosts: don't SSH to another host. Hosts: `homelab` and
`homeassistant` run requests; `macbook` only sends them. What this host may
send is on `peer doctor`'s capability line; the hub refuses the rest
(`not_permitted`). Code and design: github.com/ogglord/homelab-peer.

Hub: `--hub`, else `$PEER_HUB_URL`, else the address `peer service install`
saved (`~/.config/peer/hub`, or `peer.json` beside the binary on the Home
Assistant box). `--json` goes before the command. `peer doctor` answering "superseded" for identity while
this host's listener runs is fine.

| Need | Command |
| --- | --- |
| Another host's agent does something | `peer send request --target <host> --wait "<task>"` |
| Tell a host where something stands | `peer send status --target <host> --phase info\|started\|progress\|blocked\|done\|failed "<text>"` |
| Check on a request | `peer wait --timeout 1m <id>` |
| What other hosts sent here | `peer inbox`, then `peer result <sender> <id>` |
| Recent requests and messages everywhere | `peer list [--state parked]` |

Requests sent to this host are run by its listener, not this session.

## Requests

- Each starts a fresh headless Claude run in the target's own repo. Write it
  for a colleague who can't see this conversation: what to do, what to send
  back. Keep it small: a run out of turns fails `no_output`.
- A homelab run works in a worktree, pushes to main and may deploy. Never ask
  a run to restart its own listener (`homelab-peer`): that kills the run.
- A homeassistant run is inside the Hemma Agent add-on. It has `ha`,
  `ha-ws-client` and `addon-options`, but no `curl`, which is denied. To
  change another add-on's settings, name the add-on, the keys and the values.
  The run calls `addon-options set <addon> key=value … --restart`, which keeps
  every other option, validates the result and masks secrets in its output.
  It needs no approval. Never ask it to restart or update its own add-on
  (`ha_agent`): that kills the run, and the owner does it in HA.
- `--wait` (default 10m) exits 0 only on `done`. A timeout leaves the request
  running: `peer wait <id>` again, don't resend. `--id` is only for retrying
  after a lost answer; an id never runs twice. Status notes arrive in `peer inbox`.

| Outcome | Do |
| --- | --- |
| `parked` | The operator approves in Hemma. Tell the user and keep waiting; never approve, deny or work around it. |
| `denied` | Report it; don't resend. |
| `failed: gate_unverified` | The listener can't prove its tool gate: the user checks that host's listener log. |
| `failed: listener_lost`, `timeout`, or "listener is stopping" | `peer doctor`, then resend with a new id. |
| `expired` | Unclaimed for 24 h: the target's listener is down. |

## Secrets

The hub carries no secret values: there is no secret command, and a request
or status must not contain one. When work needs a secret that lives on
another host, ask for the work to be done there, or tell the user which
value has to be set by hand (on homelab, with the homelab CLI's secret
commands and the value on stdin).

## Install and update

```sh
nix profile install github:ogglord/homelab-peer   # peer and this skill
peer --hub http://<hub tailnet IPv4>:7790 service install [--claude ~/.local/bin/claude --checkout <repo> ...]
peer policy show       # the policy this host's runs are judged by (peer policy init writes the default)
peer update            # nix profile upgrade; the listener restarts itself once idle
```

`peer service install` writes the listener's systemd user unit (Linux) or
launchd agent (macOS) and links `~/.claude/skills/peer` to the installed
skill. A host that only sends requests needs no listener: link the skill by
hand (`ln -sfn ~/.nix-profile/share/claude/skills/peer ~/.claude/skills/peer`)
and set `PEER_HUB_URL` in the shell profile. The Home Assistant box keeps a
copied static binary started by `/data/peer service`.
