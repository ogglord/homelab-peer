---
title: Peer hub identity comes from the tailnet, and its rules live outside the repo
date: 2026-10-30
last_updated: 2026-11-16
module: internal/tsnode, internal/peer
tags: [peer, tsnet, tailscale, acl, capability]
---

# Peer hub identity comes from the tailnet, and its rules live outside the repo

Moved from ogglord/homelab (docs/solutions/architecture-patterns) with the
hub, when the hub left homelab-daemon for this stack (#82). Secret handover,
and with it the grants' secret globs, was removed then.

## Context

The hub joins the tailnet as its own tsnet node, `homelab-hub` with
`tag:homelab-hub`, and serves only agent operations on plain HTTP port 7790
of that node. It has no login of its own. Who a caller is, and what it may
do, comes from the tailnet. Half of that contract is the Tailscale ACL, which
this repo does not track, so several traps are invisible from the code.

## Guidance

**Identity and rights.** For every request, `internal/tsnode` runs WhoIs on
the connection's remote address and reads the application capability
`ogglord.com/cap/peer` (`internal/peer/identity.go`, `CapName`). Each grant
entry is `{"host", "kinds"}`, and entries from several grants are unioned. The
body's `sender` field and forwarded-address headers play no part. A node with
no capability is refused, and a tag is not required: homelab stays a
user-owned node. Older grants may still carry the removed `"secret"` kind and
`"secrets"` globs; the hub ignores both. The grants, in the tailnet policy
file:

```jsonc
{ "src": ["tag:ha-agent"], "dst": ["tag:homelab-hub"], "ip": ["tcp:7790"],
  "app": { "ogglord.com/cap/peer": [ { "host": "homeassistant", "kinds": ["result", "status"] } ] } }
{ "src": ["homelab"], "dst": ["tag:homelab-hub"], "ip": ["tcp:7790"],   // "homelab": a hosts alias for the host's tailnet IPv4
  "app": { "ogglord.com/cap/peer": [ { "host": "homelab", "kinds": ["request", "result", "status"] } ] } }
```

**The tsnet OAuth resolver defaults to ephemeral, unapproved nodes.** At
tailscale.com v1.98.10, `feature/oauthkey` treats a bare `tskey-client-…` as
`ephemeral=true&preauthorized=false`. An ephemeral hub disappears from the
tailnet whenever the hub stops. The hub therefore appends
`?ephemeral=false&preauthorized=true` to the client secret
(`internal/tsnode`). The OAuth client needs only the Auth Keys write scope on
`tag:homelab-hub`. The client ID is never used.

**Clients pin the hub by tailnet IPv4.** homelab runs tailscaled with
`--accept-dns=false`, and the Home Assistant add-on has no MagicDNS, so names
do not resolve. The address (`http://<hub tailnet IPv4>:7790`) is set where
each listener is installed: `peer service install --hub`, which also saves it
in `~/.config/peer/hub` for every later `peer`, and the add-on's
`/data/peer.json` (`"hub"`). `PEER_HUB_URL` overrides both.

The node's keys live in `/var/lib/peer-hub/tsnet` inside the stack, which the
stack's backup folder covers. If that directory is lost, the hub re-enrols as a new node with a
new address: re-pin every client and delete the stale device in the admin
console. A Tailscale Service could give the hub a stable address, but it was
rejected: in HTTP mode a Service hands the hub loopback connections and no
caller identity.

## Why This Matters

A wrong grant or a stale pinned address fails quietly, as a refusal or a
listener that keeps reconnecting, and nothing in the repo shows which side is
wrong. An ephemeral hub looks healthy until the first restart.
