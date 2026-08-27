# CLAUDE.md — Context for AI Assistants

## What This Project Is

mdnssdpd is an mDNS (Multicast DNS / DNS-SD) reflector, filter, and diagnostic tool in Rust. It receives mDNS packets on network interfaces, runs them through configurable filter/transform pipelines ("routes"), and outputs them as JSON logs or reflects them as multicast to other interfaces.

Primary use case: reflecting mDNS service discovery across VLANs with optional message transformation (e.g., stripping link-local IPv6 addresses before forwarding).

## Build & Test

This is a NixOS-based project. The developer uses NixOS.

```bash
# Build
nix build
# or: nix-shell --run "cargo build"

# Unit tests
nix-shell --run "cargo test"

# NixOS VM integration tests (3 VMs, 2 VLANs, 8 subtests, ~30s)
nix-build test.nix

# All checks via flake
nix flake check

# Run
nix-shell --run "cargo run -- --config examples/sniff-only.toml"
```

**Do NOT attempt to install Rust via rustup** — use `nix-shell` or `nix develop` which provides Rust 1.94+.

## Architecture Overview

```
main.rs (orchestrator)
  → config.rs (TOML deserialization)
  → receiver.rs (multicast recv, sends PacketEvent into crossbeam channel)
  → route.rs (pipeline: parse → filter → transform → output)
      → filter/ (FilterEngine: TOML rules + chain files + jq via jaq-core)
      → transform/ (Transform trait: remove_records, set_ttl, remove_services)
      → output/ (Output trait: log to stdout, reflect to multicast)
  → sender.rs (multicast send socket)
  → dns_util.rs (hickory-proto parsing, JSON serialization types)
```

**Key design decisions:**
- Filters operate on `serde_json::Value` (JSON path traversal, jq expressions). This is intentional — users write filter rules against the JSON they see in log output.
- Transforms operate on `hickory_proto::op::Message` (wire-level mutation). This ensures re-serialized packets are valid DNS.
- No async runtime. `std::thread` + `crossbeam-channel`. mDNS is low-throughput.
- Loop prevention: packets from local IP addresses are dropped when reflect outputs exist. (Known to be too aggressive — see limitations.)
- Sockets bind per-interface: receivers use `SO_BINDTODEVICE` (Linux) to only receive from configured interfaces. Senders bind to the interface IP on port 5353.

## Important Implementation Details

### mDNS Cache-Flush Bit
In mDNS, the top bit (0x8000) of the DNS class field means "cache-flush" on records and "prefer unicast" on questions. hickory-proto does not mask this automatically, so raw `dns_class()` returns `UNKNOWN(0x8001)` instead of `IN`. The code masks it: `(raw_class & 0x7FFF).into()`. This is regression-tested both in unit tests and VM integration tests.

### Filter Composition
- Within a TOML file: rules can be OR'd (`mode = "any"`) or AND'd (`mode = "all"`). Each rule's conditions are AND'd.
- Between chain files: AND (packet must pass every file).
- jq expressions: AND'd with TOML rules.
- `action = "hide"` inverts at the file level.
- `negate = true` inverts a single rule.
- This yields CNF (conjunctive normal form) — any boolean expression is representable.

### Transform Ordering
Transforms execute in TOML array order. A transform returning `Ok(false)` drops the packet. If no transforms are configured, original wire bytes are forwarded (zero-copy). After all transforms, if the packet has no questions, answers, authorities, or additionals left, it is silently dropped (not reflected or logged).

### RecordMatcher rdata Matching
`RecordMatcher` uses `format!("{}", record.data())` (Display trait) for rdata regex matching, NOT `format!("{:?}", ...)` (Debug). This is critical — Debug wraps values in type constructors (e.g., `AAAA(AAAA(fe80::1))`) which breaks regex patterns like `^fe80`. Display gives the human-readable form (e.g., `fe80::1`).

### mDNS Source Port
Reflected packets MUST be sent from port 5353 (RFC 6762 Section 15.1). Many mDNS implementations silently ignore responses from other source ports. The sender binds to the interface IP on port 5353.

### SO_BINDTODEVICE
Receiver and sender sockets use `SO_BINDTODEVICE` on Linux to restrict traffic to the configured interface. This requires `CAP_NET_RAW` (provided by the systemd service). For IPv4 multicast reception, the socket must still bind to `0.0.0.0` (not the interface IP) — binding to a specific IP causes the kernel to not deliver multicast packets.

### TTL=0 Semantics
In mDNS, TTL=0 means "goodbye" (tells caches to flush the record). The `set_ttl` transform never overwrites TTL=0.

## File Inventory (~2500 lines Rust)

| File | Purpose |
|---|---|
| `src/main.rs` | CLI (clap), config loading, channel setup, dispatch loop |
| `src/config.rs` | TOML config types: RouteConfig, TransformConfig, OutputConfig |
| `src/dns_util.rs` | DNS parsing + JSON types + mDNS bit masking + unit tests |
| `src/receiver.rs` | Socket creation, SO_BINDTODEVICE, multicast join, blocking recv loop |
| `src/sender.rs` | Multicast send socket (IPv4, port 5353, SO_BINDTODEVICE) |
| `src/route.rs` | Route pipeline: dispatch, parse, filter, transform, empty-drop, output |
| `src/filter/mod.rs` | FilterEngine, chain loading, compiled rules, jq integration |
| `src/filter/ops.rs` | 14 filter operators + inline expression parser |
| `src/filter/path.rs` | Dot-notation path parser + JSON value resolver |
| `src/transform/mod.rs` | Transform trait, chain, RecordMatcher (Display-based rdata matching) |
| `src/transform/remove_records.rs` | RemoveRecords + RemoveServices + tests |
| `src/transform/set_ttl.rs` | SetTtl (preserves goodbye) + tests |
| `src/output/mod.rs` | Output trait + builder |
| `src/output/log.rs` | JSON log to stdout |
| `src/output/reflect.rs` | Multicast reflect via MdnsSender |

## Nix Files

| File | Purpose |
|---|---|
| `flake.nix` | Flake: packages, checks (unit + integration), nixosModules, devShell |
| `package.nix` | Rust package derivation (rustPlatform.buildRustPackage) |
| `module.nix` | NixOS module with fully typed submodules for routes/filters/transforms/outputs |
| `test.nix` | Standalone VM test entry point (`nix-build test.nix`) |
| `test-module.nix` | VM test definition (3 VMs, 2 VLANs, 11 subtests), uses the NixOS module |
| `shell.nix` | Legacy nix-shell with cargo/rustc/rustfmt/clippy |

## NixOS Module Architecture

The module (`module.nix`) provides `services.mdnssdpd` with fully typed submodules:

```
services.mdnssdpd
  ├── enable: bool
  ├── package: package
  ├── ipv6: bool
  ├── settings: null | string (raw TOML, bypasses routes)
  └── routes: attrsOf routeModule
       ├── input: [string]
       ├── filter: null | filterModule
       │    ├── mode: "any" | "all"
       │    ├── action: "show" | "hide"
       │    ├── chain: [path]
       │    ├── jq: [string]
       │    └── rules: [ruleModule]
       │         ├── name: null | string
       │         ├── negate: bool
       │         └── conditions: [conditionModule]
       │              ├── path: string
       │              ├── op: enum (eq|ne|contains|regex|glob|...)
       │              └── value: string | int | bool | float | [string]
       ├── transforms: [transformModule]
       │    ├── type: "remove_records" | "set_ttl" | "remove_services"
       │    ├── removeRecords: null | { section, recordType, matchName, matchRdata }
       │    ├── setTtl: null | { section, value, recordType }
       │    └── removeServices: null | { matchName }
       └── outputs: [outputModule]
            ├── type: "reflect" | "log"
            ├── reflect: null | { interfaces }
            └── log: null | {}
```

The module generates TOML via `pkgs.formats.toml {}`. Route attribute names become route names. Assertions validate that tagged-union fields have matching sub-options (e.g., `type = "reflect"` requires `reflect` to be set).

The VM tests use this structured config — **not** raw TOML strings — which validates that the Nix→TOML→Rust pipeline works end-to-end.

## What's Not Yet Implemented

- IPv6 multicast send (`MdnsSender::new_v6`)
- `rewrite_ip` transform (CIDR-based address rewriting)
- `strip_txt_keys` transform
- jq-based transform (mutate message via jaq expression)
- Graceful shutdown / signal handling
- Log verbosity levels
- Rate limiting per route
- `--dry-run` mode
