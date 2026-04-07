{
  lib,
  rustPlatform,
}:

rustPlatform.buildRustPackage {
  pname = "dnssd-powertools";
  version = "0.1.0";

  src = lib.cleanSource ./.;

  cargoLock.lockFile = ./Cargo.lock;

  meta = {
    description = "DNS-SD/mDNS reflector and power tools";
    mainProgram = "dnssd-powertools";
  };
}
