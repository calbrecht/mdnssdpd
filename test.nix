# Standalone entry point: nix-build test.nix
let
  pkgs = import <nixpkgs> {};
  dnssd-powertools = pkgs.callPackage ./package.nix {};
  dnssdModule = import ./module.nix;
in
pkgs.testers.nixosTest (import ./test-module.nix { inherit dnssd-powertools dnssdModule; })
