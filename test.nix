# Standalone entry point: nix-build test.nix
let
  pkgs = import <nixpkgs> {};
  mdnssdpd = pkgs.callPackage ./package.nix {};
  dnssdModule = import ./module.nix;
in
pkgs.testers.nixosTest (import ./test-module.nix { inherit mdnssdpd dnssdModule; })
