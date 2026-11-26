{
  description = "The homelab peer hub as a homelab stack, and the peer CLI";

  inputs = {
    # For the packages and dev shells: the homelab daemon builds the stack
    # with the nixpkgs chosen for it and makes this input follow that.
    nixpkgs.url = "github:NixOS/nixpkgs/d4f25a3e562008648d45bcf2d70bcc7422cad84e";
  };

  outputs =
    { self, nixpkgs, ... }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
      ];
      forAll = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
      version = self.shortRev or self.dirtyShortRev or "dev";
      packagesFor = pkgs: import ./nix/package.nix { inherit pkgs version; };
    in
    {
      # `nix profile install github:ogglord/homelab-peer` installs `peer` and
      # its skill (share/claude/skills/peer); `peer-hub` is the stack's.
      packages = forAll (
        pkgs:
        let
          p = packagesFor pkgs;
        in
        {
          inherit (p) peer peer-hub;
          default = p.peer;
        }
      );

      # What the homelab daemon builds, on its base module and the nixpkgs
      # homelab-stack.json recommends (manifest version 10).
      nixosModules.default =
        { pkgs, ... }:
        {
          imports = [ ./stack.nix ];
          _module.args.peerHub = (packagesFor pkgs).peer-hub;
        };

      devShells = forAll (pkgs: {
        default = pkgs.mkShell {
          packages = with pkgs; [
            go_1_26 # as nix/package.nix
            gopls
            sqlc
            gcc # -race needs cgo
          ];
        };
      });
    };
}
