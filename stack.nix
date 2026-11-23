{
  lib,
  peerHub,
  ...
}:
let
  # The host binds the stack's secrets (homelab-stack.json) read-only at
  # /run/secrets, one root-owned file per name. The hub runs as peer-hub, so
  # systemd copies the ones it needs into its credentials directory (%d).
  credential = name: "%d/${name}";
  # The listener Caddy's route (peer.<domain>) reaches: the operator's page
  # (signed in through Pocket ID) and the phone's enrolment. The host opens
  # it (manifest version 8 and later).
  enrolPort = 8080;
  # The hub node's WireGuard port.
  wgPort = 41642;
in
{
  # The homelab daemon's base module makes this a container, sets the
  # hostname, time zone and stateVersion, and hands in the address.
  # Direct WireGuard paths from tailnet peers; DERP works without it.
  networking.firewall.allowedUDPPorts = [ wgPort ];

  # ── The hub ─────────────────────────────────────────────────────────────
  # A fixed uid inside the stack, so the tailnet node's state
  # (/var/lib/peer-hub/tsnet) keeps its owner when it is moved in.
  users.users.peer-hub = {
    isSystemUser = true;
    uid = 790;
    group = "peer-hub";
  };
  users.groups.peer-hub.gid = 790;

  # `peer-hub approver code|show|revoke` and `peer-hub status`, as root:
  #   systemd-run -M peer --pipe -q -- /run/current-system/sw/bin/peer-hub approver code
  environment.systemPackages = [ peerHub ];

  systemd.services.peer-hub = {
    description = "Homelab peer hub";
    wantedBy = [ "multi-user.target" ];
    wants = [ "network-online.target" ];
    after = [ "network-online.target" ];
    serviceConfig = {
      ExecStart = lib.escapeShellArgs [
        (lib.getExe peerHub)
        "serve"
        "--client-secret-file"
        (credential "tailscale-client-secret")
        "--hostname"
        "homelab-hub"
        "--tag"
        "tag:homelab-hub"
        "--port"
        "7790"
        "--wg-port"
        (toString wgPort)
        "--enrol-listen"
        ":${toString enrolPort}"
        "--domain-file"
        (credential "homelab-domain")
        "--oidc-issuer-file"
        (credential "oidc-issuer")
        "--oidc-client-id-file"
        (credential "oidc-client-id")
        "--oidc-client-secret-file"
        (credential "oidc-client-secret")
        "--oidc-admin-group-file"
        (credential "oidc-admin-group")
        "--hemma-address-file"
        (credential "hemma-address")
        "--hemma-token-file"
        (credential "hemma-token")
        "--hemma-cert-sha256-file"
        (credential "hemma-cert-sha256")
      ];
      # Read once at start: restart peer-hub after changing any value.
      LoadCredential = [
        "tailscale-client-secret:/run/secrets/PEER_HUB_TAILSCALE_CLIENT_SECRET"
        "hemma-token:/run/secrets/HEMMA_TOKEN"
        "hemma-address:/run/secrets/HEMMA_ADDRESS"
        "hemma-cert-sha256:/run/secrets/HEMMA_CERT_SHA256"
        "homelab-domain:/run/secrets/HOMELAB_DOMAIN"
        "oidc-issuer:/run/secrets/OIDC_ISSUER"
        "oidc-client-id:/run/secrets/OIDC_CLIENT_ID"
        "oidc-client-secret:/run/secrets/OIDC_CLIENT_SECRET"
        "oidc-admin-group:/run/secrets/OIDC_ADMIN_GROUP"
      ];
      User = "peer-hub";
      Group = "peer-hub";
      # /var/lib/peer-hub: peer.db and the node's state (tsnet/).
      StateDirectory = "peer-hub";
      StateDirectoryMode = "0700";
      # /run/peer-hub/admin.sock: the operator's socket, root and peer-hub only.
      RuntimeDirectory = "peer-hub";
      RuntimeDirectoryMode = "0700";
      Restart = "always";
      RestartSec = 5;
      NoNewPrivileges = true;
      ProtectSystem = "strict";
      ProtectHome = true;
      PrivateTmp = true;
      UMask = "0077";
    };
  };
}
