{
  description = "DNS-SD/mDNS reflector and power tools";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs }:
  let
    supportedSystems = [ "x86_64-linux" "aarch64-linux" ];
    forAllSystems = nixpkgs.lib.genAttrs supportedSystems;
    pkgsFor = system: nixpkgs.legacyPackages.${system};
  in
  {
    packages = forAllSystems (system: {
      dnssd-powertools = (pkgsFor system).callPackage ./package.nix {};
      default = self.packages.${system}.dnssd-powertools;
    });

    nixosModules.default = import ./module.nix;

    checks = forAllSystems (system: {
      # Unit tests (cargo test)
      unit = (pkgsFor system).callPackage ./package.nix {};

      # NixOS VM integration test
      integration = (pkgsFor system).testers.nixosTest (import ./test-module.nix {
        dnssd-powertools = self.packages.${system}.dnssd-powertools;
        dnssdModule = self.nixosModules.default;
      });
    });

    devShells = forAllSystems (system:
    let pkgs = pkgsFor system;
    in {
      default = pkgs.mkShell {
        buildInputs = with pkgs; [
          cargo
          rustc
          rustfmt
          clippy
        ];
      };
    });
  };
}
