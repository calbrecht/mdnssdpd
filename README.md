# mdnssdpd

A configurable mDNS (Multicast DNS / DNS-SD) reflector, filter, and diagnostic tool written in Rust. It listens for mDNS traffic on network interfaces, filters and transforms DNS messages declaratively, and can reflect them across VLANs or log them as structured JSON.

## Use Cases

- **Cross-VLAN mDNS reflection**: Make services discoverable across network segments (e.g., Tidal Connect streamer in one VLAN, control app in another)
- **Enterprise mDNS filtering**: Allow printer announcements across VLANs while suppressing workstation advertisements
- **mDNS diagnostics**: Capture and inspect all mDNS traffic with full metadata as structured NDJSON
- **Message transformation**: Strip link-local IPv6 addresses, clamp TTLs, remove unwanted records before reflecting

## Quick Start

### Nix (recommended)

```bash
# Run directly
nix run github:your/repo -- --config config.toml

# Development shell
nix develop

# Run all checks (unit tests + NixOS VM integration tests)
nix flake check
```

### Cargo

```bash
cargo build --release
./target/release/mdnssdpd --config config.toml
```

### List Interfaces

```bash
mdnssdpd --list
```

## Architecture

Everything is built around **routes** — declarative pipelines that define how mDNS packets flow:

```
Receive (interface) → Filter → Transform → Output (reflect / log)
```

Multiple routes run concurrently. Each packet from a receiver is dispatched to all routes whose input interfaces match.

```
NIC eth0 ──recv──┐
NIC eth1 ──recv──┤  Receiver Threads
                 │
          ┌──────▼──────┐
          │  Fan-Out     │  crossbeam-channel
          └──┬─────┬────┘
             │     │
         Route A  Route B
           │        │
     1. Parse (hickory-proto)
     2. Filter (on JSON representation)
     3. Transform (on DNS Message, in-place)
     4. Re-serialize to wire format
     5. Output (reflect multicast / log JSON)
```

### Threading Model

- **Receiver threads** (one per interface per IP version): blocking `recv_from`, send `PacketEvent` into a bounded crossbeam channel
- **Main thread**: reads from channel, dispatches to all routes sequentially
- No async runtime — `std::thread` + channels. mDNS is low-throughput; simplicity wins.

### Loop Prevention

When any route has a `reflect` output, the tool collects all local IP addresses at startup. Packets originating from local addresses are dropped before dispatch. This prevents infinite reflection loops when an interface is both input and output across routes.

## Configuration

All configuration is via a single TOML file passed with `--config`.

### Minimal: Sniff/Log Only

```toml
[[route]]
name = "sniff-all"
input = ["wlp0s20f3"]
output = [{ type = "log" }]
```

### Cross-VLAN Reflection with Transforms

```toml
# Forward queries from control VLAN to stream VLAN
[[route]]
name = "control-to-stream"
input = ["eth0"]
output = [
  { type = "reflect", interfaces = ["eth1"] },
  { type = "log" },
]

[route.filter]
[[route.filter.rule]]
[[route.filter.rule.condition]]
path = "message.message_type"
op = "eq"
value = "query"

# Forward responses back, stripping link-local IPv6
[[route]]
name = "stream-to-control"
input = ["eth1"]
output = [
  { type = "reflect", interfaces = ["eth0"] },
  { type = "log" },
]

[route.filter]
[[route.filter.rule]]
[[route.filter.rule.condition]]
path = "message.message_type"
op = "eq"
value = "response"

[[route.transform]]
type = "remove_records"
section = "answers"
record_type = "AAAA"
match_rdata = "fe80"

[[route.transform]]
type = "set_ttl"
section = "all"
value = 60
```

### Enterprise: Selective Service Reflection

```toml
# Only reflect printer services, suppress everything else
[[route]]
name = "printers-only"
input = ["office"]
output = [{ type = "reflect", interfaces = ["guest"] }]

[route.filter]
mode = "all"
jq = ['.message.answers | any(.name | test("_ipp|_printer|_pdl-datastream"))']

[[route.filter.rule]]
negate = true
[[route.filter.rule.condition]]
path = "message.answers[*].name"
op = "regex"
value = "_(airplay|raop|homekit)"
```

## Filter System

Filters decide whether a packet enters a route's pipeline. They operate on the JSON representation of the parsed DNS message.

### Three Ways to Filter

**1. TOML Rules** — declarative path-based conditions:

```toml
[route.filter]
mode = "any"  # "any" = OR between rules, "all" = AND

[[route.filter.rule]]
name = "responses-only"
[[route.filter.rule.condition]]
path = "message.message_type"
op = "eq"
value = "response"

[[route.filter.rule]]
name = "has-ptr"
[[route.filter.rule.condition]]
path = "message.answers[*].record_type"
op = "eq"
value = "PTR"
```

**2. jq Expressions** — full jq power via [jaq-core](https://github.com/01mf02/jaq):

```toml
[route.filter]
jq = [
  'select(.message | .answers[]?,.questions[]? | .name | test("_smb"))',
]
```

**3. Chain Files** — reference external TOML filter files (ANDed together):

```toml
[route.filter]
chain = [
  "./10-only-responses.toml",
  "./20-tidal-services.toml",
]
```

All three can be combined. Chain files AND rules AND jq must all pass.

### Path Expressions

Dot-notation with `[*]` array wildcard. A condition matches if **any** array element satisfies it.

| Path | Resolves to |
|---|---|
| `interface` | Top-level string |
| `message.message_type` | `"query"` or `"response"` |
| `message.opcode` | e.g. `"QUERY"` |
| `message.authoritative` | boolean |
| `message.questions[*].name` | Name from every question |
| `message.answers[*].record_type` | Type from every answer |
| `message.answers[*].rdata_detail.port` | Nested into SRV detail |

### Operators

| Operator | Types | Description |
|---|---|---|
| `eq` / `ne` | string, number, bool | Equality |
| `contains` / `icontains` | string | Substring (case-sensitive / insensitive) |
| `starts_with` / `ends_with` | string | Prefix / suffix |
| `regex` | string | Rust regex |
| `glob` | string | Shell glob (`*._tcp.local.`) |
| `gt` / `gte` / `lt` / `lte` | number | Numeric comparison |
| `in` | string, number | Value in list |
| `exists` | any | Field present and non-null |

### Filter Chain Files

Standalone TOML filter files can be chained. Each file is an independent filter step; a packet must pass all of them (AND semantics). Files can recursively reference other files via `chain`. Circular references are detected and rejected.

```toml
# 10-only-responses.toml
[[rule]]
[[rule.condition]]
path = "message.message_type"
op = "eq"
value = "response"
```

```toml
# filter-chain.toml — bundles other filters
chain = [
  "./10-only-responses.toml",
  "./20-tidal-services.toml",
]
```

## Transforms

Transforms modify DNS messages in-place **after** filtering, **before** output. They operate on the `hickory-proto` `Message` struct directly (not on JSON) to produce wire-correct re-serialized packets.

Transforms are chained in TOML array order. If no transforms are configured, original wire bytes are forwarded as-is (zero-copy for pure reflection).

### `remove_records`

Remove records matching criteria from specified sections.

```toml
[[route.transform]]
type = "remove_records"
section = "answers"       # "answers" | "authorities" | "additionals" | "all"
record_type = "AAAA"      # optional: filter by DNS record type
match_name = ".*local"    # optional: regex on record name
match_rdata = "^fe80"     # optional: regex on rdata string
```

### `set_ttl`

Set TTL on matching records. Respects mDNS goodbye announcements (TTL=0 is never overwritten).

```toml
[[route.transform]]
type = "set_ttl"
section = "all"
value = 60
record_type = "A"         # optional: only matching types
```

### `remove_services`

Remove services by name pattern from **all** sections including questions.

```toml
[[route.transform]]
type = "remove_services"
match_name = "_(airplay|raop)"
```

## Output Sinks

Each route can have multiple outputs. All outputs receive the (possibly transformed) message.

### `log`

Write structured NDJSON to stdout. Each line is a complete JSON object with timestamp, interface, source, packet size, and the full parsed DNS message.

```toml
output = [{ type = "log" }]
# or: { type = "log", format = "json" }
```

### `reflect`

Send the (possibly transformed) packet as mDNS multicast on the specified interfaces.

```toml
output = [{ type = "reflect", interfaces = ["eth0", "eth1"] }]
```

## JSON Log Format

Every logged packet produces one JSON line on stdout (NDJSON). Pipe to `jq` for pretty-printing or further filtering.

```jsonc
{
  "timestamp": "2026-04-07T15:38:47.124942Z",
  "interface": "wlp0s20f3:v4",
  "source": "10.93.4.1:5353",
  "packet_size": 114,
  "message": {
    "id": 0,
    "message_type": "response",
    "opcode": "QUERY",
    "authoritative": true,
    "truncated": false,
    "recursion_desired": false,
    "recursion_available": false,
    "response_code": "No Error",
    "question_count": 0,
    "answer_count": 3,
    "authority_count": 0,
    "additional_count": 0,
    "questions": [],
    "answers": [
      {
        "name": "_smb._tcp.local.",
        "record_type": "PTR",
        "class": "IN",
        "ttl": 4500,
        "rdata": "merktnix._smb._tcp.local."
      },
      {
        "name": "merktnix._smb._tcp.local.",
        "record_type": "SRV",
        "class": "IN",
        "ttl": 120,
        "cache_flush": true,
        "rdata": "merktnix.lan.:445 -> 0",
        "rdata_detail": {
          "port": 445,
          "priority": 0,
          "target": "merktnix.lan.",
          "weight": 0
        }
      }
    ],
    "authorities": [],
    "additionals": []
  }
}
```

### mDNS-Specific Fields

- **`cache_flush`**: Present and `true` on records where the mDNS cache-flush bit (top bit of class field) is set. The `class` field always shows the actual class (`"IN"`) with the bit masked off.
- **`prefer_unicast`**: Present and `true` on questions where the QU bit is set (unicast-response requested).
- **`rdata_detail`**: Structured breakdown for SRV (priority, weight, port, target), TXT (entries array), and MX (preference, exchange) records.

## Project Structure

```
src/
  main.rs                     CLI, config loading, channel fan-out, dispatch loop
  config.rs                   TOML config types (RouteConfig, TransformConfig, OutputConfig)
  dns_util.rs                 DNS parsing (hickory-proto) and JSON serialization types
  receiver.rs                 mDNS multicast socket setup, blocking recv loop
  sender.rs                   mDNS multicast send socket
  route.rs                    Route pipeline: parse → filter → transform → output
  filter/
    mod.rs                    FilterEngine: compiles TOML rules + chain files + jq into evaluator
    ops.rs                    Filter operators (eq, regex, glob, contains, in, gt/lt, ...)
    path.rs                   JSON path expression parser and resolver (dot.notation[*].support)
  transform/
    mod.rs                    Transform trait, TransformChain, RecordMatcher, section helpers
    remove_records.rs         RemoveRecords and RemoveServices transforms
    set_ttl.rs                SetTtl transform (respects mDNS goodbye TTL=0)
  output/
    mod.rs                    Output trait and builder
    log.rs                    JSON log output (stdout)
    reflect.rs                Multicast reflect output

package.nix                   Nix package definition
flake.nix                     Nix flake (package, checks, devShell)
test.nix                      Standalone NixOS VM test entry point
test-module.nix               NixOS VM test definition (importable, used by flake)
shell.nix                     Legacy nix-shell for development
examples/
  sniff-only.toml             Minimal sniff/log config
  tidal-reflect.toml          Cross-VLAN Tidal Connect reflection with transforms
```

## Dependencies

| Crate | Purpose |
|---|---|
| `hickory-proto` | DNS message parsing and serialization (wire format) |
| `jaq-core` + `jaq-std` + `jaq-json` | jq expression engine for filters |
| `clap` | CLI argument parsing |
| `serde` + `serde_json` + `toml` | Serialization and config parsing |
| `socket2` | Low-level multicast socket control |
| `crossbeam-channel` | Bounded channel for receiver→route fan-out |
| `network-interface` | Interface enumeration and address lookup |
| `regex` | Regular expression matching in filters and transforms |
| `chrono` | Timestamps |
| `anyhow` | Error handling |
| `ipnet` | (Reserved for future `rewrite_ip` transform) |

## Testing

### Unit Tests (177 tests, 74% coverage)

```bash
cargo test
```

Covers: config TOML deserialization and defaults, all 14 filter operators with edge cases, JSON path resolution with nested wildcards, filter engine composition (chain files, AND/OR modes, hide action, invert, jq truthiness), jq compile errors, transform record removal (link-local IPv6 stripping from all sections, per-section removal, regex-only matching), service removal (full strip, partial strip, cross-section), TTL setting (per-section, record type filter, goodbye preservation), RecordMatcher with Display-based rdata, cache-flush class masking (wire roundtrip regression), question QU-bit masking, route pipeline integration (interface matching, filter rejection, transform application, empty packet drop, multi-output dispatch), log output JSON formatting, dispatch loop with loop prevention.

### NixOS VM Integration Tests (11 subtests)

```bash
nix-build test.nix
# or via flake:
nix flake check
```

Spins up 3 QEMU VMs with 2 VLANs, IPv6 enabled:
- **client1** (VLAN 1): avahi browser
- **client2** (VLAN 2): avahi service announcer (TestStreamer `_tidal._tcp`)
- **reflector** (VLAN 1 + 2): runs mdnssdpd

Tests verify:
1. systemd service is active
2. Both interfaces and routes are logged
3. Generated TOML config is valid and contains expected routes/transforms
4. IPv6 link-local addresses are present
5. client2 sees its own service locally
6. Reflector captures and logs mDNS queries
7. Link-local IPv6 AAAA records are stripped from responses
8. IPv6 is active and avahi publishes over IPv6
9. All log entries are valid JSON, `class` is never `"UNKNOWN"` (cache-flush regression)
10. Empty packets after transforms (e.g., stripped `_googlecast` queries) are not logged or reflected
11. Service restarts cleanly

## Known Limitations / Future Work

- **Log output shows post-transform state**: The `log` output on a route logs packets *after* transforms have been applied. There is currently no way to log the original packet before transformation, and no metadata in the JSON indicating which route processed the packet or how many transforms were applied. This can make debugging confusing — you see what was reflected, not what came in. A future improvement would add fields like `"route": "stream-to-control"` and `"transforms_applied": 2` to the log output.
- **Loop prevention is too aggressive**: Currently all packets from any local IP address are dropped before reaching any route. This means other services on the same host (e.g., Home Assistant, avahi) are invisible to mdnssdpd — their mDNS traffic is silently discarded. Loop prevention should only drop packets that mdnssdpd itself sent (i.e., reflected packets), not all locally-originated mDNS traffic. A better approach would be to track sent packets (e.g., by tagging or hashing recent outgoing packets) rather than blanket-dropping by source IP.
- **IPv6 reflect sender**: Currently only IPv4 multicast send is implemented (`MdnsSender::new_v4`). IPv6 reflect (`ff02::fb`) is not yet wired up.
- **`rewrite_ip` transform**: CIDR-based IP address rewriting (dependency `ipnet` is included but transform not yet implemented).
- **`strip_txt_keys` transform**: Remove specific TXT record keys by regex.
- **jq transform**: Use jaq expressions to mutate message structure (not just filter).
- **Graceful shutdown**: No signal handling yet; the process must be killed.
- **Verbosity levels**: All logging is currently at a single debug level. Structured log levels (error/warn/info/debug) are planned.
- **Rate limiting**: No per-route rate limiting to prevent amplification storms.
- **Dry-run mode**: `--dry-run` to show what would be reflected without sending.

## NixOS Module

The flake exposes a NixOS module at `nixosModules.default` with fully typed, structured configuration.

### Basic Usage

```nix
{
  inputs.mdnssdpd.url = "github:your/repo";

  outputs = { self, nixpkgs, mdnssdpd, ... }: {
    nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
      modules = [
        mdnssdpd.nixosModules.default
        {
          services.mdnssdpd = {
            enable = true;
            package = mdnssdpd.packages.x86_64-linux.default;

            routes.sniff-all = {
              input = [ "eth0" ];
              outputs = [{ type = "log"; }];
            };
          };
        }
      ];
    };
  };
}
```

### Cross-VLAN Reflection

```nix
services.mdnssdpd = {
  enable = true;

  routes = {
    control-to-stream = {
      input = [ "eth0" ];
      filter.rules = [{
        conditions = [{
          path = "message.message_type";
          op = "eq";
          value = "query";
        }];
      }];
      outputs = [
        { type = "reflect"; reflect.interfaces = [ "eth1" ]; }
        { type = "log"; }
      ];
    };

    stream-to-control = {
      input = [ "eth1" ];
      filter.rules = [{
        conditions = [{
          path = "message.message_type";
          op = "eq";
          value = "response";
        }];
      }];
      transforms = [
        {
          type = "remove_records";
          removeRecords = {
            section = "all";
            recordType = "AAAA";
            matchRdata = "^fe80";
          };
        }
        {
          type = "set_ttl";
          setTtl = { section = "all"; value = 60; };
        }
      ];
      outputs = [
        { type = "reflect"; reflect.interfaces = [ "eth0" ]; }
        { type = "log"; }
      ];
    };
  };
};
```

### Enterprise Printer-Only Reflection

```nix
services.mdnssdpd.routes.printers-only = {
  input = [ "office" ];
  filter = {
    jq = [ ''.message.answers | any(.name | test("_ipp|_printer"))'' ];
    rules = [{
      negate = true;
      conditions = [{
        path = "message.answers[*].name";
        op = "regex";
        value = "_(airplay|raop|homekit)";
      }];
    }];
  };
  outputs = [
    { type = "reflect"; reflect.interfaces = [ "guest" ]; }
  ];
};
```

### Module Options Reference

| Option | Type | Default | Description |
|---|---|---|---|
| `enable` | bool | `false` | Enable the service |
| `package` | package | `pkgs.mdnssdpd` | Package to use |
| `ipv6` | bool | `false` | Join IPv6 multicast group |
| `settings` | null or string | `null` | Raw TOML config (bypasses `routes`) |
| `routes.<name>.input` | list of string | — | Input interfaces |
| `routes.<name>.filter.mode` | `"any"` or `"all"` | `"any"` | How rules combine |
| `routes.<name>.filter.action` | `"show"` or `"hide"` | `"show"` | Filter action |
| `routes.<name>.filter.chain` | list of path | `[]` | External filter chain files |
| `routes.<name>.filter.jq` | list of string | `[]` | jq filter expressions |
| `routes.<name>.filter.rules` | list of rule | `[]` | Filter rules |
| `routes.<name>.filter.rules.*.negate` | bool | `false` | Invert rule |
| `routes.<name>.filter.rules.*.conditions` | list of condition | `[]` | Rule conditions (ANDed) |
| `routes.<name>.filter.rules.*.conditions.*.path` | string | — | JSON path expression |
| `routes.<name>.filter.rules.*.conditions.*.op` | enum | — | Operator |
| `routes.<name>.filter.rules.*.conditions.*.value` | string/int/bool/list | — | Comparison value |
| `routes.<name>.transforms` | list of transform | `[]` | Transform chain (ordered) |
| `routes.<name>.outputs` | list of output | — | Output sinks |

### systemd Service

The module creates a hardened systemd service:
- `DynamicUser = true` — no static user needed
- `CAP_NET_RAW` + `CAP_NET_BIND_SERVICE` — multicast without root
- Full sandboxing: `ProtectSystem=strict`, `PrivateTmp`, `NoNewPrivileges`, `MemoryDenyWriteExecute`, etc.
- `Restart = on-failure` with 5s backoff

## License

TBD
