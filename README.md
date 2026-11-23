# homelab-peer

Agent messaging between hosts for a [homelab-ngx](https://github.com/homelab-ngx/homelab-ngx)
homelab: a hub that runs as a stack, and the `peer` CLI every host uses to
talk to it. One host's Claude Code agent asks another host's agent to do
something. The other host runs it as a headless Claude Code run, and steps
that need a human wait for a signed approval from the operator's phone.

- **Hub** (`peer-hub`, `cmd/peer-hub`): joins the tailnet as its own node
  `homelab-hub` (tag `tag:homelab-hub`) and serves the agent operations on
  port 7790 of that node. Callers are identified by WhoIs and a tailnet
  capability (`docs/peer-hub-tailnet-identity.md`). Requests park for a
  signed approval from the enrolled phone through Hemma, a Home Assistant
  add-on that pushes to the phone. Its state is one SQLite file
  (`/var/lib/peer-hub/peer.db`, schema `db/schema.sql`); requests and
  messages are kept 90 days, message outcomes 7.
- **Page** (`internal/web`): `https://peer.<domain>`, behind Pocket ID.
- **CLI** (`peer`, `cmd/peer`): send requests and status, wait, inbox, and
  the listener that runs the requests pushed to its host as headless Claude
  Code runs (`docs/headless-claude-run-gate.md`).

The hub carries no secret values between hosts.

## Get started

1. Tailscale: an OAuth client with the Auth Keys write scope on
   `tag:homelab-hub`, and grants in the tailnet policy that give each host's
   node the peer capability (`docs/peer-hub-tailnet-identity.md`).
2. Pocket ID: a group for the operator (such as `peer-admins`) and an OIDC
   client with the callback URL `https://peer.<domain>/auth/callback`,
   allowed to that group.
3. Add the stack: `homelab stacks add github:ogglord/homelab-peer`. Fill in
   its variables (below) in the dashboard or with
   `homelab stacks var set peer <NAME> [--secret] --value-stdin`, approve it
   and start it.
4. Install the CLI and a listener on each host (below), and enrol the phone
   on the page.

## Install the CLI

```sh
nix profile install github:ogglord/homelab-peer
peer --hub http://<hub tailnet IPv4>:7790 service install \
  --claude ~/.local/bin/claude --checkout ~/repos/<repo> \
  --deny 'WebFetch(domain:<domain>)' --deny 'WebFetch(domain:*.<domain>)'
```

`service install` writes a systemd user unit (`homelab-peer.service`, Linux)
or a launchd agent (`com.ogglord.homelab-peer`, macOS) that runs the
listener from the profile's `peer`. It saves the hub's address in
`~/.config/peer/hub`, so every later `peer` finds it without `--hub`, and
links `~/.claude/skills/peer` to the skill shipped in the package. Without
`--claude` the listener only receives status and results. Without
`--checkout` runs work in the unit's working directory instead of a git
worktree. Its PATH is the PATH the command ran with (`--path` overrides), so
run it from a login shell. `--dry-run` prints the file instead. On Linux the
user needs lingering for the listener to start at boot.

### The run policy

Runs outside the allow list are judged by Claude Code's auto-mode
classifier under the host's policy:
`{"environment": [...], "allow": [...], "hard_deny": [...]}`, each a list of
prose rules with `"$defaults"` for Claude Code's built-ins. A hard_deny rule
holds even when the request asks.

Without `--policy-file`, `service install` uses `~/.config/peer/policy.json`
and writes the default there when the file is missing. The default lets a
run read the host's state, restart one service or stack the request names,
build and test in its worktree and push its commits. It never lets a run
delete data outside its worktree, change how the host is reached or who may
log in, reboot the host, touch secrets, or install packages.

```sh
peer policy default          # print the default
peer policy init [--force]   # write it to ~/.config/peer/policy.json
peer policy show             # print the host's policy, after checking it parses
```

Edit the file to describe the host (the `environment` list) and what its
runs may do, then restart the listener.

A `--deny` list replaces the built-in one (curl, wget and the homelab CLI).
The listener always adds its own floor: the approver routes, requests from
child runs, and the hard_deny rule against enrolling approver keys. Deny
WebFetch to the host's own domain, as above, so a run cannot reach the
dashboard.

A host that only sends requests needs no listener: install the profile,
`ln -sfn ~/.nix-profile/share/claude/skills/peer ~/.claude/skills/peer`
and put the hub's address in `~/.config/peer/hub` (or `PEER_HUB_URL`).

On the Home Assistant box, a static binary goes to `/data/peer`
(`nix build .#packages.x86_64-linux.peer`, or `aarch64-linux` for an ARM
box), with `/data/peer.json` beside it and `/data/peer service` as the
add-on's init command.

## Update

```sh
peer update          # nix profile upgrade homelab-peer
peer update --now    # and restart the listener at once, even mid-run
```

The listener watches the profile's `peer` and restarts itself on the new
binary once no run is in progress, so an update never kills a run.

## The page

`https://peer.<domain>` shows the hub's state, the requests waiting for
approval with their blocked step, the approver phone, the hosts with their
`peer` versions, and the last 50 messages and outcomes. Caddy's route has no
sign-in, so the hub signs the operator in through Pocket ID and admits only
members of `OIDC_ADMIN_GROUP`. Every POST must come from the page itself
(`Sec-Fetch-Site: same-origin`, else a matching `Origin`), so another
stack's page under the same domain cannot post to it. A session lasts 12
hours; its signing key is in `peer.db`, so a restart keeps it.

The page is served under `/` and `/auth/*`. Without sign-in the listener
serves only `GET`/`POST /api/peer/approvers` (the phone's enrolment) and
`GET /healthz`.

## Approver enrolment

One phone holds the key whose signatures decide approvals. On the page,
**Enrol a phone** shows a one-time code (10 minutes) as a QR code. Scan it
with the iPhone camera on the home network and it opens the Hemma app, which
posts its key to `https://peer.<domain>/api/peer/approvers`. The page closes
the code once the phone has enrolled. **Remove** revokes the phone. Hemma
pushes a notice to the phones when a new one enrols.

The same works as root on the host, without the page:

```sh
systemd-run -M peer --pipe -q -- /run/current-system/sw/bin/peer-hub approver code
```

prints the code and its `hemma://homelab?…` link; show the link as a QR
code (e.g. `qrencode -t ansiutf8`). `peer-hub approver show` and
`peer-hub approver revoke` work the same way, and `peer-hub status` shows
the tailnet node and the hosts. Only root in the stack can open the hub's
operator socket, and only the signed-in operator can mint a code on the
page, so no agent on a peer host can enrol a key.

## The stack

- `flake.nix`: `nixosModules.default` (the stack, `stack.nix`; the homelab
  daemon builds it on its base module with the nixpkgs the manifest
  recommends), `packages.<system>.{default,peer,peer-hub}`, a dev shell.
- `homelab-stack.json`: the route `peer` (the page and enrolment), egress to
  Hemma on `HEMMA_ADDRESS` (8788/tcp), and UDP 41641 to the Home Assistant
  box and the host for direct tailnet paths (DERP works without them). The
  hub reaches Pocket ID through Caddy on the host's port 443, which every
  stack may.
- The repo holds no values. The host binds them read-only at
  `/run/secrets/<NAME>`, and `peer-hub` takes them through
  `LoadCredential=`; restart it after changing one. The page's address comes
  from the host's `HOMELAB_DOMAIN`.

<!-- manifest:start -->
<!-- Made from homelab-stack.json. Change the manifest, not these lines. -->

## Grants

You approve each of these before the stack starts.

- Route: `peer.<your domain>` to port 8080 in the stack.
- Network: out to the addresses you give in `HEMMA_ADDRESS` on port 8788/tcp.
- Network: out to the addresses you give in `HEMMA_ADDRESS` on port 41641/udp.
- Network: out to the host on port 41641/udp.

## Variables

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `PEER_HUB_TAILSCALE_CLIENT_SECRET` | secret | yes |  | Tailscale OAuth client secret (tskey-client-…) with the Auth Keys write scope on tag:homelab-hub; the hub mints its node's auth key with it. |
| `HEMMA_ADDRESS` | address | yes |  | IPv4 address of the Home Assistant box that runs the Hemma add-on (port 8788). The hub reaches Hemma there, and the box's Tailscale directly on UDP 41641. |
| `HEMMA_TOKEN` | secret | yes |  | Bearer token of the Hemma hub on the Home Assistant box, which the hub uses to prompt the approver phone and read its decisions. |
| `HEMMA_CERT_SHA256` | env | yes |  | SHA-256 (hex) of the Hemma add-on's self-signed certificate (DER), which the hub pins. Not secret. |
| `OIDC_ISSUER` | env | yes |  | Pocket ID's address, the issuer the peer page signs in with, such as https://auth.example.com. |
| `OIDC_CLIENT_ID` | env | yes |  | Client ID of the peer page's OIDC client in Pocket ID (callback URL https://peer.<domain>/auth/callback). |
| `OIDC_CLIENT_SECRET` | secret | yes |  | Client secret of the peer page's OIDC client in Pocket ID. |
| `OIDC_ADMIN_GROUP` | env | yes |  | The Pocket ID group whose members may sign in to the peer page, enrol the approver phone and remove it. |

## Backup

The stack recommends these folders. None is backed up until you add it to a backup.

- Hub database and network identity: `/var/lib/peer-hub` in the stack.

## Health

An update is kept when all of this holds, and rolled back when it does not.

- `peer-hub.service` is active.
- Port 8080 answers at `/healthz`.

Manifest version 9, built with nixpkgs `nixos-unstable`. Runs on [homelab-ngx](https://github.com/homelab-ngx/homelab-ngx).

<!-- manifest:end -->

## Develop

```sh
make test     # go test -race -count=1 ./... in the dev shell (~10 s once built)
make check    # gofmt, sqlc diff, vet, test
make gen      # sqlc after changing db/schema.sql or db/queries
```

After changing `go.mod`/`go.sum`, update `vendorHash` in `nix/package.nix`
(the build prints the new one).
