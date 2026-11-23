# The two binaries of this repo. Both are pure Go (SQLite is modernc's), so
# they build with CGO off: `peer` is one static binary that also runs on the
# Home Assistant box, copied there by hand.
{ pkgs, version }:
let
  src = pkgs.lib.fileset.toSource {
    root = ../.;
    fileset = pkgs.lib.fileset.unions [
      ../go.mod
      ../go.sum
      ../cmd
      ../internal
      ../db
    ];
  };
  # Go 1.26: tailscale.com v1.98's go-json-experiment does not build under
  # 1.27's encoding/json/v2.
  buildGoModule = pkgs.buildGoModule.override { go = pkgs.go_1_26; };
  build =
    attrs:
    buildGoModule (
      {
        inherit version src;
        vendorHash = "sha256-c4CPHyyfIb+eNmf8ScaxYoNO0v1zWvp3eg/reOqmD6g=";
        env.CGO_ENABLED = "0";
        ldflags = [
          "-s"
          "-w"
          "-X main.version=${version}"
        ];
        # The suites run in the dev shell (make test): they start fake
        # claude processes and loopback servers.
        doCheck = false;
      }
      // attrs
    );
in
{
  peer = build {
    pname = "peer";
    subPackages = [ "cmd/peer" ];
    # The skill ships with the binary, so `peer service install` links the
    # one that matches the installed CLI.
    postInstall = ''
      mkdir -p $out/share/claude/skills
      cp -r ${../skills/peer} $out/share/claude/skills/peer
    '';
    meta = {
      description = "Homelab peer client: send requests and status, inbox, listener";
      mainProgram = "peer";
    };
  };

  peer-hub = build {
    pname = "peer-hub";
    subPackages = [ "cmd/peer-hub" ];
    meta = {
      description = "Homelab peer hub: the agent messaging hub on its own tailnet node";
      mainProgram = "peer-hub";
    };
  };
}
