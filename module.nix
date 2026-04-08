{ config, lib, pkgs, ... }:

let
  cfg = config.services.mdnssdpd;

  # --- Submodule types ---

  conditionModule = lib.types.submodule {
    options = {
      path = lib.mkOption {
        type = lib.types.str;
        description = "JSON path expression (e.g. `message.answers[*].record_type`).";
        example = "message.message_type";
      };
      op = lib.mkOption {
        type = lib.types.enum [
          "eq" "ne"
          "contains" "icontains"
          "starts_with" "ends_with"
          "regex" "glob"
          "gt" "gte" "lt" "lte"
          "in" "exists"
        ];
        description = "Comparison operator.";
      };
      value = lib.mkOption {
        type = with lib.types; oneOf [ str int bool float (listOf str) ];
        description = ''
          Value to compare against. Type depends on operator:
          - string for eq/ne/contains/regex/glob/starts_with/ends_with
          - number for gt/gte/lt/lte
          - bool for exists
          - list of strings for `in`
        '';
      };
    };
  };

  ruleModule = lib.types.submodule {
    options = {
      name = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        description = "Optional rule name for debugging.";
      };
      negate = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = "Invert rule match result.";
      };
      conditions = lib.mkOption {
        type = lib.types.listOf conditionModule;
        default = [];
        description = "Conditions within this rule (ANDed together).";
      };
    };
  };

  filterModule = lib.types.submodule {
    options = {
      mode = lib.mkOption {
        type = lib.types.enum [ "any" "all" ];
        default = "any";
        description = "`any` = OR between rules, `all` = AND between rules.";
      };
      action = lib.mkOption {
        type = lib.types.enum [ "show" "hide" ];
        default = "show";
        description = "`show` = only print matches, `hide` = suppress matches.";
      };
      chain = lib.mkOption {
        type = lib.types.listOf lib.types.path;
        default = [];
        description = "External TOML filter files to chain (ANDed together).";
      };
      jq = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [];
        description = "jq expressions (via jaq-core). All must be truthy.";
        example = [ ''.message.answers | any(.name | test("_ipp"))'' ];
      };
      rules = lib.mkOption {
        type = lib.types.listOf ruleModule;
        default = [];
        description = "Filter rules. Combined according to `mode`.";
      };
    };
  };

  sectionType = lib.types.enum [ "answers" "authorities" "additionals" "all" ];

  removeRecordsModule = lib.types.submodule {
    options = {
      section = lib.mkOption {
        type = sectionType;
        default = "all";
        description = "Which record section to operate on.";
      };
      recordType = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        description = "Filter by DNS record type (e.g. `AAAA`, `PTR`).";
        example = "AAAA";
      };
      matchName = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        description = "Regex to match against record name.";
      };
      matchRdata = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        description = "Regex to match against rdata string representation.";
        example = "^fe80";
      };
    };
  };

  setTtlModule = lib.types.submodule {
    options = {
      section = lib.mkOption {
        type = sectionType;
        default = "all";
        description = "Which record section to operate on.";
      };
      value = lib.mkOption {
        type = lib.types.ints.unsigned;
        description = "TTL value to set. TTL=0 (mDNS goodbye) is never overwritten.";
      };
      recordType = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        description = "Only set TTL on records of this type.";
      };
    };
  };

  removeServicesModule = lib.types.submodule {
    options = {
      matchName = lib.mkOption {
        type = lib.types.str;
        description = "Regex to match service names. Removes from all sections including questions.";
        example = "_(airplay|raop)";
      };
    };
  };

  transformModule = lib.types.submodule {
    options = {
      type = lib.mkOption {
        type = lib.types.enum [ "remove_records" "set_ttl" "remove_services" ];
        description = "Transform type.";
      };
      removeRecords = lib.mkOption {
        type = lib.types.nullOr removeRecordsModule;
        default = null;
        description = "Config for `remove_records` transform.";
      };
      setTtl = lib.mkOption {
        type = lib.types.nullOr setTtlModule;
        default = null;
        description = "Config for `set_ttl` transform.";
      };
      removeServices = lib.mkOption {
        type = lib.types.nullOr removeServicesModule;
        default = null;
        description = "Config for `remove_services` transform.";
      };
    };
  };

  reflectOutputModule = lib.types.submodule {
    options = {
      interfaces = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        description = "Interfaces to reflect mDNS packets to.";
      };
    };
  };

  logOutputModule = lib.types.submodule {
    options = {
      format = lib.mkOption {
        type = lib.types.enum [ "json" ];
        default = "json";
        description = "Log output format.";
      };
    };
  };

  outputModule = lib.types.submodule {
    options = {
      type = lib.mkOption {
        type = lib.types.enum [ "reflect" "log" ];
        description = "Output sink type.";
      };
      reflect = lib.mkOption {
        type = lib.types.nullOr reflectOutputModule;
        default = null;
        description = "Config for `reflect` output.";
      };
      log = lib.mkOption {
        type = lib.types.nullOr logOutputModule;
        default = null;
        description = "Config for `log` output.";
      };
    };
  };

  routeModule = lib.types.submodule {
    options = {
      input = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        description = "Network interfaces to receive mDNS packets from.";
        example = [ "eth0" "eth1" ];
      };
      filter = lib.mkOption {
        type = lib.types.nullOr filterModule;
        default = null;
        description = "Filter configuration. If null, all packets pass.";
      };
      transforms = lib.mkOption {
        type = lib.types.listOf transformModule;
        default = [];
        description = "Transform chain, applied in order before output.";
      };
      outputs = lib.mkOption {
        type = lib.types.listOf outputModule;
        description = "Output sinks (reflect and/or log).";
      };
    };
  };

  # --- TOML generation ---

  filterNulls = lib.filterAttrs (_: v: v != null);

  conditionToTOML = c: {
    inherit (c) path op;
    # value needs special handling: lists stay lists, scalars stay scalars
    value = c.value;
  };

  ruleToTOML = r: filterNulls {
    inherit (r) name negate;
    condition = map conditionToTOML r.conditions;
  };

  filterToTOML = f: filterNulls {
    inherit (f) mode action jq;
    chain = map toString f.chain;
    rule = map ruleToTOML f.rules;
  };

  transformToTOML = t:
    let
      base = { inherit (t) type; };
    in
    if t.type == "remove_records" then
      assert t.removeRecords != null;
      base // filterNulls {
        section = t.removeRecords.section;
        record_type = t.removeRecords.recordType;
        match_name = t.removeRecords.matchName;
        match_rdata = t.removeRecords.matchRdata;
      }
    else if t.type == "set_ttl" then
      assert t.setTtl != null;
      base // filterNulls {
        section = t.setTtl.section;
        value = t.setTtl.value;
        record_type = t.setTtl.recordType;
      }
    else if t.type == "remove_services" then
      assert t.removeServices != null;
      base // {
        match_name = t.removeServices.matchName;
      }
    else
      throw "Unknown transform type: ${t.type}";

  outputToTOML = o:
    let
      base = { inherit (o) type; };
    in
    if o.type == "reflect" then
      assert o.reflect != null;
      base // { interfaces = o.reflect.interfaces; }
    else if o.type == "log" then
      if o.log != null
      then base // { format = o.log.format; }
      else base
    else
      throw "Unknown output type: ${o.type}";

  routeToTOML = name: r: filterNulls {
    inherit name;
    inherit (r) input;
    filter = if r.filter != null then filterToTOML r.filter else null;
    transform = map transformToTOML r.transforms;
    output = map outputToTOML r.outputs;
  };

  configTOML = {
    route = lib.mapAttrsToList routeToTOML cfg.routes;
  };

  tomlFormat = pkgs.formats.toml {};
  configFile = tomlFormat.generate "mdnssdpd.toml" configTOML;

in
{
  options.services.mdnssdpd = {
    enable = lib.mkEnableOption "mdnssdpd mDNS reflector";

    package = lib.mkPackageOption pkgs "mdnssdpd" {};

    ipv6 = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Also join IPv6 multicast group (ff02::fb).";
    };

    settings = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = ''
        Raw TOML configuration string. If set, this is used verbatim
        instead of generating config from the structured `routes` option.
      '';
    };

    routes = lib.mkOption {
      type = lib.types.attrsOf routeModule;
      default = {};
      description = ''
        Named route definitions. Each route is a pipeline:
        input interfaces → filter → transform → output.
        Attribute name becomes the route name in the config.
      '';
      example = lib.literalExpression ''
        {
          sniff-all = {
            input = [ "eth0" ];
            outputs = [{ type = "log"; }];
          };
        }
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.settings != null || cfg.routes != {};
        message = "services.mdnssdpd: either `settings` or `routes` must be configured.";
      }
    ] ++ lib.concatLists (lib.mapAttrsToList (name: route:
      # Validate transform configs have matching sub-options
      map (t: {
        assertion =
          (t.type == "remove_records" -> t.removeRecords != null) &&
          (t.type == "set_ttl" -> t.setTtl != null) &&
          (t.type == "remove_services" -> t.removeServices != null);
        message = "Route '${name}': transform type '${t.type}' requires matching config attribute.";
      }) route.transforms
      ++
      # Validate output configs have matching sub-options
      map (o: {
        assertion =
          (o.type == "reflect" -> o.reflect != null);
        message = "Route '${name}': output type 'reflect' requires 'reflect' config.";
      }) route.outputs
    ) cfg.routes);

    systemd.services.mdnssdpd = {
      description = "DNS-SD/mDNS Reflector and Power Tools";
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      wantedBy = [ "multi-user.target" ];

      serviceConfig = {
        ExecStart = let
          configPath =
            if cfg.settings != null
            then pkgs.writeText "mdnssdpd.toml" cfg.settings
            else configFile;
        in
          "${cfg.package}/bin/mdnssdpd"
          + " --config ${configPath}"
          + lib.optionalString cfg.ipv6 " --ipv6";

        Restart = "on-failure";
        RestartSec = 5;

        # Hardening
        DynamicUser = true;
        AmbientCapabilities = [ "CAP_NET_RAW" "CAP_NET_BIND_SERVICE" ];
        CapabilityBoundingSet = [ "CAP_NET_RAW" "CAP_NET_BIND_SERVICE" ];
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        NoNewPrivileges = true;
        RestrictSUIDSGID = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectControlGroups = true;
        RestrictNamespaces = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        RestrictRealtime = true;
      };
    };
  };
}
