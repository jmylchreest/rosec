{
  description = "rosec source packaging and NixOS regression tests";
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/31ecbaca1bdefa45dffc409f0250bd8039ea0010";
  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forSystems = nixpkgs.lib.genAttrs systems;
      builds = forSystems (system: import ./contrib/nix/package.nix {
        pkgs = import nixpkgs { inherit system; };
      });
    in {
      packages = forSystems (system: {
        default = builds.${system}.rosec;
        inherit (builds.${system}) providers;
      });
      checks = forSystems (system:
        let
          pkgs = import nixpkgs { inherit system; };
          build = builds.${system};
          upstreamTest = import "${nixpkgs}/nixos/tests/rosec.nix" {
            inherit pkgs;
            inherit (pkgs) lib;
          };
        in {
          package = build.rosec;
          providers = build.smoke;
        } // pkgs.lib.optionalAttrs (system == "x86_64-linux") {
          # Reuse the contributor's real D-Bus/PAM login test with our checkout.
          nixos = pkgs.testers.runNixOSTest {
            imports = [ upstreamTest ];
            nodes.machine.services.rosec.package = pkgs.lib.mkForce build.rosec;
            testScript = pkgs.lib.mkForce ({ nodes, ... }:
              upstreamTest.testScript { inherit nodes; } + ''
                with subtest("Source-built providers retain required verification"):
                    report = machine.succeed("su - alice -c 'rosec provider validate'")
                    assert "embedded package hashes" in report
                    for kind in ["bitwarden-pm", "bitwarden-sm", "gnome-keyring", "keepassxc-file", "protonpass"]:
                        assert kind + " (" in report, report
                    machine.succeed("journalctl --no-pager | grep -F 'WASM plugin authenticated by embedded package hashes'")
              '');
          };
        });
    };
}
