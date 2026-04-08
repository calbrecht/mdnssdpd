{
  lib,
  rustPlatform,
}:

rustPlatform.buildRustPackage {
  pname = "mdnssdpd";
  version = "0.1.0";

  src = lib.cleanSource ./.;

  cargoLock.lockFile = ./Cargo.lock;

  meta = {
    description = "DNS-SD/mDNS reflector and power tools";
    mainProgram = "mdnssdpd";
  };
}
