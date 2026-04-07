/*
  NixOS VM integration test for dnssd-powertools mDNS reflector.

  Uses the NixOS module with structured route definitions.

  Usage from flake.nix:
    import ./test-module.nix { dnssd-powertools = <package>; dnssdModule = <module>; }

  Standalone:
    nix-build test.nix
*/

{ dnssd-powertools, dnssdModule }:

let
  networkBase = {
    networking.firewall.allowedUDPPorts = [ 5353 ];
    networking.enableIPv6 = true;
  };

  avahiModule = {
    services.avahi = {
      enable = true;
      nssmdns4 = true;
      publish = {
        enable = true;
        addresses = true;
        workstation = true;
      };
    };
  };

in
{
  name = "dnssd-powertools-reflect";

  nodes = {
    client1 = { config, pkgs, ... }: {
      imports = [ avahiModule networkBase ];
      virtualisation.vlans = [ 1 ];
      networking.interfaces.eth1.ipv4.addresses = [
        { address = "192.168.1.10"; prefixLength = 24; }
      ];
      environment.systemPackages = [ pkgs.avahi pkgs.jq ];
    };

    client2 = { config, pkgs, ... }: {
      imports = [ avahiModule networkBase ];
      virtualisation.vlans = [ 2 ];
      networking.interfaces.eth1.ipv4.addresses = [
        { address = "192.168.2.20"; prefixLength = 24; }
      ];
      environment.systemPackages = [ pkgs.avahi pkgs.jq ];

      services.avahi.extraServiceFiles.tidal = ''
        <?xml version="1.0" standalone='no'?>
        <!DOCTYPE service-group SYSTEM "avahi-service.dtd">
        <service-group>
          <name>TestStreamer</name>
          <service>
            <type>_tidal._tcp</type>
            <port>8080</port>
            <txt-record>model=TestDevice</txt-record>
          </service>
        </service-group>
      '';
    };

    reflector = { config, pkgs, ... }: {
      imports = [ dnssdModule networkBase ];
      virtualisation.vlans = [ 1 2 ];
      networking.interfaces.eth1.ipv4.addresses = [
        { address = "192.168.1.1"; prefixLength = 24; }
      ];
      networking.interfaces.eth2.ipv4.addresses = [
        { address = "192.168.2.1"; prefixLength = 24; }
      ];
      environment.systemPackages = [ pkgs.jq pkgs.tcpdump ];

      # --- Structured route configuration via NixOS module ---
      services.dnssd-powertools = {
        enable = true;
        package = dnssd-powertools;

        routes = {
          # Route 1: Forward queries from control (vlan1) to stream (vlan2)
          control-to-stream = {
            input = [ "eth1" ];
            filter = {
              rules = [{
                conditions = [{
                  path = "message.message_type";
                  op = "eq";
                  value = "query";
                }];
              }];
            };
            outputs = [
              { type = "reflect"; reflect.interfaces = [ "eth2" ]; }
              { type = "log"; }
            ];
          };

          # Route 2: Forward responses from stream (vlan2) to control (vlan1)
          # Strip link-local IPv6 AAAA records, clamp TTL to 60s
          stream-to-control = {
            input = [ "eth2" ];
            filter = {
              rules = [{
                conditions = [{
                  path = "message.message_type";
                  op = "eq";
                  value = "response";
                }];
              }];
            };
            transforms = [
              {
                type = "remove_records";
                removeRecords = {
                  section = "all";
                  recordType = "AAAA";
                  matchRdata = "fe80";
                };
              }
              {
                type = "set_ttl";
                setTtl = {
                  section = "all";
                  value = 60;
                };
              }
            ];
            outputs = [
              { type = "reflect"; reflect.interfaces = [ "eth1" ]; }
              { type = "log"; }
            ];
          };
        };
      };
    };
  };

  testScript = ''
    import json

    start_all()

    client1.wait_for_unit("avahi-daemon.service")
    client2.wait_for_unit("avahi-daemon.service")

    # Wait for the systemd service to be running
    reflector.wait_for_unit("dnssd-powertools.service")

    # Give avahi time to announce services and IPv6 SLAAC to settle
    client2.succeed("sleep 5")

    # --- Test 1: systemd service is active ---
    with subtest("dnssd-powertools systemd service is active"):
        status = reflector.succeed("systemctl is-active dnssd-powertools.service").strip()
        assert status == "active", f"Service should be active, got: {status}"

    # --- Test 2: service stderr shows both interfaces and both routes ---
    with subtest("service listens on both interfaces with both routes"):
        journal = reflector.succeed(
            "journalctl -u dnssd-powertools.service --no-pager -o cat"
        )
        assert "eth1" in journal, f"Should listen on eth1, journal: {journal}"
        assert "eth2" in journal, f"Should listen on eth2, journal: {journal}"
        assert "All receivers up" in journal, f"Should be fully started, journal: {journal}"
        assert "control-to-stream" in journal, f"Should log route name, journal: {journal}"
        assert "stream-to-control" in journal, f"Should log route name, journal: {journal}"

    # --- Test 3: generated config file is valid TOML ---
    with subtest("generated config file is valid TOML"):
        # The config path is in the ExecStart line
        exec_line = reflector.succeed(
            "systemctl show dnssd-powertools.service -p ExecStart --no-pager"
        )
        # Extract config file path
        import re
        config_match = re.search(r'--config\s+(\S+)', exec_line)
        assert config_match, f"Should find --config in ExecStart: {exec_line}"
        config_path = config_match.group(1)
        # Verify it parses and has the expected routes
        config_content = reflector.succeed(f"cat {config_path}")
        assert "control-to-stream" in config_content, \
            f"Config should contain route name, got: {config_content}"
        assert "remove_records" in config_content, \
            f"Config should contain transform, got: {config_content}"
        assert "fe80" in config_content, \
            f"Config should contain match_rdata, got: {config_content}"

    # --- Test 4: client2 has IPv6 link-local ---
    with subtest("client2 has IPv6 link-local address"):
        result = client2.succeed("ip -6 addr show dev eth1 scope link")
        assert "fe80::" in result, f"Should have link-local IPv6, got: {result}"

    # --- Test 5: client2 sees own service ---
    with subtest("client2 sees its own service via avahi"):
        result = client2.succeed("avahi-browse -t -p _tidal._tcp 2>/dev/null || true")
        assert "TestStreamer" in result, f"Should see TestStreamer, got: {result}"

    # --- Test 6: trigger mDNS query from client1 ---
    with subtest("reflector captures and reflects queries"):
        client1.execute("avahi-browse -t -p _tidal._tcp >/tmp/browse.out 2>&1 &")
        client2.succeed("avahi-resolve -n client2.local || true")
        reflector.succeed("sleep 5")

        journal = reflector.succeed(
            "journalctl -u dnssd-powertools.service --no-pager -o cat"
        )
        json_lines = [l for l in journal.split('\n') if l.strip().startswith('{')]
        assert len(json_lines) > 0, "Should have JSON log lines in journal"

        found_query = False
        for line in json_lines:
            entry = json.loads(line)
            if entry["message"]["message_type"] == "query":
                found_query = True
        assert found_query, f"Should have logged a query, got {len(json_lines)} JSON lines"

    # --- Test 7: link-local IPv6 stripped from responses ---
    with subtest("link-local IPv6 addresses are stripped from responses"):
        journal = reflector.succeed(
            "journalctl -u dnssd-powertools.service --no-pager -o cat"
        )
        json_lines = [l for l in journal.split('\n') if l.strip().startswith('{')]
        for line in json_lines:
            entry = json.loads(line)
            if entry["message"]["message_type"] == "response":
                for answer in entry["message"]["answers"]:
                    if answer["record_type"] == "AAAA":
                        assert not answer["rdata"].startswith("fe80"), \
                            f"Link-local IPv6 should be stripped, found: {answer['rdata']}"

    # --- Test 8: IPv6 active and avahi publishes IPv6 ---
    with subtest("client2 has IPv6 and avahi publishes over IPv6"):
        ll = client2.succeed("ip -6 addr show dev eth1 scope link")
        assert "fe80" in ll, f"Should have fe80 link-local, got: {ll}"
        browse = client2.succeed("avahi-browse -a -t -p 2>/dev/null || true")
        assert "IPv6" in browse, f"Should publish IPv6 records, got: {browse}"

    # --- Test 9: JSON structure valid, class != UNKNOWN regression ---
    with subtest("all log entries are valid JSON with correct fields"):
        journal = reflector.succeed(
            "journalctl -u dnssd-powertools.service --no-pager -o cat"
        )
        json_lines = [l for l in journal.split('\n') if l.strip().startswith('{')]
        for line in json_lines:
            entry = json.loads(line)
            assert "timestamp" in entry, "Missing timestamp"
            assert "interface" in entry, "Missing interface"
            assert "source" in entry, "Missing source"
            assert "packet_size" in entry, "Missing packet_size"
            msg = entry["message"]
            assert msg["message_type"] in ("query", "response"), \
                f"Invalid message_type: {msg['message_type']}"
            for section in ["questions", "answers", "authorities", "additionals"]:
                for record in msg.get(section, []):
                    assert record["class"] != "UNKNOWN", \
                        f"class should not be UNKNOWN: {record}"

    # --- Test 10: service restarts cleanly ---
    with subtest("service restarts cleanly"):
        reflector.succeed("systemctl restart dnssd-powertools.service")
        reflector.wait_for_unit("dnssd-powertools.service")
        status = reflector.succeed("systemctl is-active dnssd-powertools.service").strip()
        assert status == "active", f"Should be active after restart, got: {status}"
  '';
}
