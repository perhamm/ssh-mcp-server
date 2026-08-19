import { parseArgs } from "node:util";
import {
  SSHConfig,
  SshConnectionConfigMap,
  ParsedArgs,
  DynamicHostsConfig,
} from "../models/types.js";
import fs from "fs";
import path from "path";
import os from "os";
import { lookupSshConfig } from "../utils/ssh-config-parser.js";
import type { GuardProfileName } from "../guards/guard-rules.js";
import type { HostKeyChecking } from "../utils/known-hosts.js";
import {
  AuditLogSettings,
  DEFAULT_AUDIT_KEEP,
  DEFAULT_AUDIT_MAX_BYTES,
  defaultAuditLogPath,
} from "../utils/audit-log.js";
import {
  DEFAULT_TUNNEL_POLICY,
  TunnelPolicy,
} from "../services/tunnel-manager.js";

/**
 * Command line argument parser class
 */
export class CommandLineParser {
  private static readonly DEFAULT_TRANSPORT_MODE: SSHConfig["transportMode"] = "exec";
  private static readonly DEFAULT_SHELL_READY_TIMEOUT_MS = 10000;

  private static parseBoolean(value: unknown): boolean | undefined {
    if (value === undefined) {
      return undefined;
    }
    if (typeof value === "boolean") {
      return value;
    }
    if (typeof value === "string") {
      const normalized = value.trim().toLowerCase();
      if (normalized === "true") {
        return true;
      }
      if (normalized === "false") {
        return false;
      }
    }
    return Boolean(value);
  }

  private static parseTransportMode(
    value: unknown,
  ): SSHConfig["transportMode"] | undefined {
    if (value === undefined || value === null || value === "") {
      return undefined;
    }

    if (value === "exec" || value === "shell") {
      return value;
    }

    throw new Error(
      `transportMode must be either 'exec' or 'shell', got: ${String(value)}`,
    );
  }

  private static parseTimeout(
    value: unknown,
    fieldName: string,
  ): number | undefined {
    if (value === undefined || value === null || value === "") {
      return undefined;
    }

    const parsed =
      typeof value === "number" ? value : parseInt(String(value), 10);

    if (!Number.isFinite(parsed) || parsed <= 0) {
      throw new Error(`${fieldName} must be a positive number, got: ${String(value)}`);
    }

    return parsed;
  }

  private static parseMaxOutputBytes(value: unknown): number | undefined {
    if (value === undefined || value === null || value === "") {
      return undefined;
    }

    const parsed = typeof value === "number" ? value : Number(String(value));

    if (!Number.isSafeInteger(parsed) || parsed < 0) {
      throw new Error(
        `maxOutputBytes must be a non-negative integer, got: ${String(value)}`,
      );
    }

    return parsed;
  }

  /**
   * Parse command line arguments
   */
  public static parseArgs(): ParsedArgs {
    const { values, positionals } = parseArgs({
      args: process.argv.slice(2),
      options: {
        "config-file": { type: "string" },
        "ssh-config-file": { type: "string" },
        ssh: { type: "string", multiple: true },
        // Compatible with single connection legacy parameters
        host: { type: "string", short: "h" },
        port: { type: "string", short: "p" },
        username: { type: "string", short: "u" },
        password: { type: "string", short: "w" },
        privateKey: { type: "string", short: "k" },
        passphrase: { type: "string", short: "P" },
        agent: { type: "string", short: "a" },
        whitelist: { type: "string", short: "W" },
        blacklist: { type: "string", short: "B" },
        proxy: { type: "string" },
        socksProxy: { type: "string", short: "s" },
        "allowed-local-paths": { type: "string" },
        "allowed-remote-paths": { type: "string" },
        "transport-mode": { type: "string" },
        "shell-ready-timeout": { type: "string" },
        "command-template": { type: "string" },
        pty: { type: "boolean" },
        "try-keyboard": { type: "boolean" },
        "pre-connect": { type: "boolean" },
        "ssh-config-hosts": { type: "boolean" },
        "allowed-hosts": { type: "string" },
        "proxy-jump": { type: "string" },
        "guards-profile": { type: "string" },
        "guards-file": { type: "string" },
        "sudo-password-env": { type: "string" },
        "sudo-user": { type: "string" },
        "host-key-checking": { type: "string" },
        "known-hosts-file": { type: "string" },
        "host-key-algorithms": { type: "string" },
        "audit-log": { type: "string" },
        "audit-max-size": { type: "string" },
        "audit-keep": { type: "string" },
        "enable-upload": { type: "boolean" },
        "disable-tunnels": { type: "boolean" },
        "tunnel-bind-address": { type: "string" },
        "allowed-tunnel-ports": { type: "string" },
        "max-tunnels": { type: "string" },
      },
      allowPositionals: true,
    });

    const sharedDefaults: Partial<SSHConfig> = {
      guardProfile: this.parseGuardProfile(values["guards-profile"]),
      guardsFile: values["guards-file"]
        ? this.normalizeLocalPath(values["guards-file"])
        : undefined,
      sudoPasswordEnv: values["sudo-password-env"],
      sudoUser: values["sudo-user"],
      hostKeyChecking: this.parseHostKeyChecking(values["host-key-checking"]),
      hostKeyAlgorithms: this.parseList(values["host-key-algorithms"]),
      knownHostsFiles: this.parseList(values["known-hosts-file"])?.map(
        (file) => this.normalizeLocalPath(file),
      ),
    };
    const tunnelPolicy = this.parseTunnelPolicy(values);
    const auditLog = this.parseAuditSettings(values);
    const configMap: SshConnectionConfigMap = {};

    // Priority 1: Load from config file if specified
    if (values["config-file"]) {
      const configFilePath = path.resolve(values["config-file"]);
      if (!fs.existsSync(configFilePath)) {
        throw new Error(`Config file not found: ${configFilePath}`);
      }
      try {
        const configContent = fs.readFileSync(configFilePath, "utf-8");
        const fileConfig = JSON.parse(configContent);
        
        // Support both array format and object format
        if (Array.isArray(fileConfig)) {
          // Array format: [{name: "dev", host: "...", ...}, ...]
          for (const config of fileConfig) {
            if (!config.name || !config.host || !config.port || !config.username) {
              throw new Error("Each config in array must include name, host, port, username");
            }
            configMap[config.name] = this.normalizeConfig(config);
          }
        } else if (typeof fileConfig === "object" && fileConfig !== null) {
          // Object format: {"dev": {host: "...", ...}, "prod": {...}}
          for (const [name, config] of Object.entries(fileConfig)) {
            const normalizedConfig = this.normalizeConfig(config as any);
            normalizedConfig.name = name;
            configMap[name] = normalizedConfig;
          }
        } else {
          throw new Error("Config file must contain an array or object of SSH configurations");
        }
      } catch (err) {
        if (err instanceof SyntaxError) {
          throw new Error(`Invalid JSON in config file: ${(err as Error).message}`);
        }
        throw err;
      }
    }

    // Priority 2: Parse --ssh parameters (only if no config file was loaded)
    if (Object.keys(configMap).length === 0) {
      const sshParams: string[] = Array.isArray(values.ssh)
        ? values.ssh
        : values.ssh
        ? [values.ssh]
        : [];

      for (const sshStr of sshParams) {
        let conf: SSHConfig;
        
        // Try to parse as JSON first
        if (sshStr.trim().startsWith("{")) {
          try {
            const jsonConfig = JSON.parse(sshStr);
            conf = this.normalizeConfig(jsonConfig);
            if (!conf.name) {
              throw new Error("JSON config must include 'name' field");
            }
          } catch (err) {
            throw new Error(`Invalid JSON format in --ssh parameter: ${(err as Error).message}`);
          }
        } else {
          // Fallback to legacy comma-separated format for backward compatibility
          conf = this.parseLegacySshFormat(sshStr);
        }
        
        if (!conf.name || !conf.host || !conf.port || !conf.username) {
          throw new Error("Each --ssh must include name, host, port, username");
        }
        configMap[conf.name] = conf;
      }
    }

    const dynamicHostsEnabled = values["ssh-config-hosts"] === true;

    // Priority 3: Compatible with single connection legacy parameters
    if (
      Object.keys(configMap).length === 0 &&
      !(dynamicHostsEnabled && !values.host && positionals.length === 0)
    ) {
      const host = values.host || positionals[0];

      // 尝试从 SSH config 读取配置
      let sshConfigEntry = null;
      if (host) {
        try {
          sshConfigEntry = lookupSshConfig(host, values["ssh-config-file"]);
        } catch (err) {
          // 显式指定配置文件但读取失败时抛错
          throw err;
        }
      }

      const portStr = values.port || positionals[1] || sshConfigEntry?.port?.toString() || "22";
      const username = values.username || positionals[2] || sshConfigEntry?.user;
      const password = values.password || positionals[3];
      const privateKey = values.privateKey || sshConfigEntry?.identityFile;
      const passphrase = values.passphrase || process.env.SSH_MCP_PASSPHRASE;
      const resolvedAgent = values.agent !== undefined
        ? values.agent
        : !password && !privateKey
        ? process.env.SSH_AUTH_SOCK
        : undefined;
      const whitelist = values.whitelist;
      const blacklist = values.blacklist;
      const allowedLocalPaths = values["allowed-local-paths"];
      const allowedRemotePaths = values["allowed-remote-paths"];
      const commandTemplate = values["command-template"];
      const pty = values.pty;
      const tryKeyboard = values["try-keyboard"];

      // 实际连接地址：优先使用 SSH config 的 HostName
      const actualHost = sshConfigEntry?.hostName || host;

      if (!actualHost || !portStr || !username || (!password && !privateKey && !resolvedAgent)) {
        throw new Error(
          "Missing required parameters, need to provide host, port, username and password, private key or agent"
        );
      }

      const port = parseInt(portStr, 10);
      if (isNaN(port)) {
        throw new Error("Port must be a valid number");
      }

      configMap["default"] = this.normalizeConfig({
        name: "default",
        host: actualHost,
        port,
        username,
        password,
        privateKey,
        passphrase,
        agent: resolvedAgent,
        proxy: values.proxy,
        socksProxy: values.socksProxy,
        pty: pty !== undefined ? pty : undefined,
        tryKeyboard: tryKeyboard !== undefined ? tryKeyboard : undefined,
        transportMode: values["transport-mode"],
        shellReadyTimeoutMs: values["shell-ready-timeout"],
        commandTemplate,
        proxyJump: values["proxy-jump"] || sshConfigEntry?.proxyJump,
        knownHostsFiles: sshConfigEntry?.userKnownHostsFiles,
        sshConfigFile: values["ssh-config-file"],
        commandWhitelist: whitelist
          ? whitelist
              .split(",")
              .map((pattern) => pattern.trim())
              .filter(Boolean)
          : undefined,
        commandBlacklist: blacklist
          ? blacklist
              .split(",")
              .map((pattern) => pattern.trim())
              .filter(Boolean)
          : undefined,
        allowedLocalPaths: allowedLocalPaths
          ? allowedLocalPaths
              .split(",")
              .map((allowedPath) => allowedPath.trim())
              .filter(Boolean)
          : undefined,
        allowedRemotePaths: allowedRemotePaths
          ? allowedRemotePaths
              .split(",")
              .map((allowedPath) => allowedPath.trim())
              .filter(Boolean)
          : undefined,
      });
    }

    for (const config of Object.values(configMap)) {
      this.applyDefaults(config, sharedDefaults);
    }

    const dynamicHosts: DynamicHostsConfig = {
      enabled: dynamicHostsEnabled,
      sshConfigFile: values["ssh-config-file"],
      allowPatterns: this.parseList(values["allowed-hosts"]),
      template: {
        ...sharedDefaults,
        username: values.username,
        privateKey: values.privateKey
          ? this.normalizeLocalPath(values.privateKey)
          : undefined,
        passphrase: values.passphrase || process.env.SSH_MCP_PASSPHRASE,
        agent: values.agent !== undefined ? values.agent : process.env.SSH_AUTH_SOCK,
        proxy: values.proxy,
        socksProxy: values.socksProxy,
        proxyJump: values["proxy-jump"],
        pty: this.parseBoolean(values.pty),
        tryKeyboard: this.parseBoolean(values["try-keyboard"]),
        transportMode: this.parseTransportMode(values["transport-mode"]),
        shellReadyTimeoutMs: this.parseTimeout(
          values["shell-ready-timeout"],
          "shellReadyTimeoutMs",
        ),
        commandTemplate: this.parseCommandTemplate(values["command-template"]),
        commandWhitelist: this.parseList(values.whitelist),
        commandBlacklist: this.parseList(values.blacklist),
        allowedLocalPaths: this.parseList(values["allowed-local-paths"])?.map(
          (allowedPath) => this.normalizeLocalPath(allowedPath),
        ),
        allowedRemotePaths: this.parseList(values["allowed-remote-paths"])?.map(
          (allowedPath) => this.normalizeRemotePath(allowedPath),
        ),
      },
    };

    return {
      configs: configMap,
      preConnect: values["pre-connect"] === true,
      dynamicHosts,
      tunnelPolicy,
      auditLog,
      enableUpload: values["enable-upload"] === true,
    };
  }

  /**
   * Fill in the options that are configured once for the whole server and are
   * not worth repeating in every connection entry.
   */
  private static applyDefaults(
    config: SSHConfig,
    defaults: Partial<SSHConfig>,
  ): void {
    for (const [key, value] of Object.entries(defaults)) {
      if (value !== undefined && config[key as keyof SSHConfig] === undefined) {
        (config as unknown as Record<string, unknown>)[key] = value;
      }
    }
  }

  private static parseList(value: unknown): string[] | undefined {
    if (typeof value !== "string" || value.trim() === "") {
      return undefined;
    }

    const items = value
      .split(",")
      .map((item) => item.trim())
      .filter(Boolean);

    return items.length > 0 ? items : undefined;
  }

  private static parseHostKeyChecking(
    value: unknown,
  ): HostKeyChecking | undefined {
    if (value === undefined || value === null || value === "") {
      return undefined;
    }

    if (value === "strict" || value === "accept-new" || value === "off") {
      return value;
    }

    throw new Error(
      `hostKeyChecking must be one of 'strict', 'accept-new', 'off', got: ${String(value)}`,
    );
  }

  private static parseGuardProfile(value: unknown): GuardProfileName | undefined {
    if (value === undefined || value === null || value === "") {
      return undefined;
    }

    if (value === "off" || value === "safe" || value === "readonly") {
      return value;
    }

    throw new Error(
      `guardsProfile must be one of 'off', 'safe', 'readonly', got: ${String(value)}`,
    );
  }

  private static parseAuditSettings(values: {
    "audit-log"?: string;
    "audit-max-size"?: string;
    "audit-keep"?: string;
  }): AuditLogSettings {
    const configured = values["audit-log"];

    if (configured === "off" || configured === "none") {
      return {
        enabled: false,
        maxBytes: DEFAULT_AUDIT_MAX_BYTES,
        keep: DEFAULT_AUDIT_KEEP,
      };
    }

    const maxBytes = values["audit-max-size"];
    const parsedMaxBytes =
      maxBytes === undefined || maxBytes === ""
        ? DEFAULT_AUDIT_MAX_BYTES
        : Number(maxBytes);

    if (!Number.isSafeInteger(parsedMaxBytes) || parsedMaxBytes < 0) {
      throw new Error(
        `auditMaxSize must be a non-negative integer, got: ${String(maxBytes)}`,
      );
    }

    return {
      enabled: true,
      path: configured
        ? this.normalizeLocalPath(configured)
        : defaultAuditLogPath(),
      maxBytes: parsedMaxBytes,
      keep: this.parseTimeout(values["audit-keep"], "auditKeep") || DEFAULT_AUDIT_KEEP,
    };
  }

  private static parseTunnelPolicy(values: {
    "disable-tunnels"?: boolean;
    "tunnel-bind-address"?: string;
    "allowed-tunnel-ports"?: string;
    "max-tunnels"?: string;
  }): TunnelPolicy {
    const allowedPorts = this.parseList(values["allowed-tunnel-ports"])?.map(
      (port) => {
        const parsed = parseInt(port, 10);
        if (!Number.isInteger(parsed) || parsed < 1 || parsed > 65535) {
          throw new Error(`allowedTunnelPorts entry is not a port: ${port}`);
        }
        return parsed;
      },
    );

    const maxTunnels = this.parseTimeout(values["max-tunnels"], "maxTunnels");

    return {
      enabled: values["disable-tunnels"] !== true,
      bindAddress:
        values["tunnel-bind-address"] || DEFAULT_TUNNEL_POLICY.bindAddress,
      allowedPorts,
      maxTunnels: maxTunnels || DEFAULT_TUNNEL_POLICY.maxTunnels,
    };
  }

  /**
   * Parse legacy comma-separated format: name=dev,host=1.2.3.4,port=22,user=alice,password=xxx
   * @private
   */
  private static parseLegacySshFormat(sshStr: string): SSHConfig {
    const conf: any = {};
    const parts = sshStr.split(",");
    
    for (const part of parts) {
      // Only split on the first '=' to handle values containing '='
      const equalIndex = part.indexOf("=");
      if (equalIndex > 0) {
        const k = part.substring(0, equalIndex).trim();
        const v = part.substring(equalIndex + 1).trim();
        if (k && v) {
          conf[k] = v;
        }
      }
    }
    
    const port = parseInt(conf.port, 10);
    if (isNaN(port)) {
      throw new Error(
        `Port for connection ${conf.name || "unknown"} must be a valid number`
      );
    }
    
    return this.normalizeConfig(conf);
  }

  /**
   * Normalize SSH config object to ensure proper types and structure
   * @private
   */
  private static normalizeConfig(config: any): SSHConfig {
    const port = typeof config.port === "number"
      ? config.port
      : parseInt(config.port, 10);

    if (isNaN(port)) {
      throw new Error(`Port must be a valid number, got: ${config.port}`);
    }

    return {
      name: config.name,
      host: config.host,
      port,
      username: config.username || config.user,
      password: config.password,
      privateKey: config.privateKey
        ? this.normalizeLocalPath(String(config.privateKey))
        : undefined,
      passphrase: config.passphrase || process.env.SSH_MCP_PASSPHRASE,
      agent: config.agent,
      algorithms: config.algorithms,
      proxy: config.proxy,
      socksProxy: config.socksProxy,
      pty: this.parseBoolean(config.pty),
      tryKeyboard: this.parseBoolean(config.tryKeyboard),
      transportMode:
        this.parseTransportMode(config.transportMode) ||
        this.DEFAULT_TRANSPORT_MODE,
      shellReadyTimeoutMs:
        this.parseTimeout(
          config.shellReadyTimeoutMs,
          "shellReadyTimeoutMs",
        ) || this.DEFAULT_SHELL_READY_TIMEOUT_MS,
      shellCommandTimeoutMs: this.parseTimeout(
        config.shellCommandTimeoutMs,
        "shellCommandTimeoutMs",
      ),
      commandTimeoutMs: this.parseTimeout(
        config.commandTimeoutMs,
        "commandTimeoutMs",
      ),
      connectionTimeoutMs: this.parseTimeout(
        config.connectionTimeoutMs,
        "connectionTimeoutMs",
      ),
      sftpTimeoutMs: this.parseTimeout(config.sftpTimeoutMs, "sftpTimeoutMs"),
      maxOutputBytes: this.parseMaxOutputBytes(config.maxOutputBytes),
      keepaliveIntervalMs: this.parseTimeout(
        config.keepaliveIntervalMs,
        "keepaliveIntervalMs",
      ),
      keepaliveCountMax: this.parseTimeout(
        config.keepaliveCountMax,
        "keepaliveCountMax",
      ),
      commandWhitelist: Array.isArray(config.commandWhitelist)
        ? config.commandWhitelist
        : config.whitelist
        ? typeof config.whitelist === "string"
          ? config.whitelist.split("|").map((s: string) => s.trim()).filter(Boolean)
          : config.whitelist
        : undefined,
      commandBlacklist: Array.isArray(config.commandBlacklist)
        ? config.commandBlacklist
        : config.blacklist
        ? typeof config.blacklist === "string"
          ? config.blacklist.split("|").map((s: string) => s.trim()).filter(Boolean)
          : config.blacklist
        : undefined,
      allowedLocalPaths: Array.isArray(config.allowedLocalPaths)
        ? config.allowedLocalPaths
            .map((allowedPath: unknown) =>
              this.normalizeLocalPath(String(allowedPath)),
            )
            .filter(Boolean)
        : typeof config.allowedLocalPaths === "string"
          ? config.allowedLocalPaths
              .split("|")
              .map((allowedPath: string) =>
                this.normalizeLocalPath(allowedPath.trim()),
              )
              .filter(Boolean)
          : undefined,
      allowedRemotePaths: Array.isArray(config.allowedRemotePaths)
        ? config.allowedRemotePaths
            .map((allowedPath: unknown) =>
              this.normalizeRemotePath(String(allowedPath)),
            )
        : typeof config.allowedRemotePaths === "string"
          ? config.allowedRemotePaths
              .split("|")
              .map((allowedPath: string) =>
                this.normalizeRemotePath(allowedPath.trim()),
              )
              .filter(Boolean)
          : undefined,
      commandTemplate: this.parseCommandTemplate(config.commandTemplate),
      proxyJump: config.proxyJump,
      sshConfigFile: config.sshConfigFile,
      guardProfile: this.parseGuardProfile(config.guardProfile),
      guardsFile: config.guardsFile
        ? this.normalizeLocalPath(String(config.guardsFile))
        : undefined,
      sudoPasswordEnv: config.sudoPasswordEnv,
      sudoUser: config.sudoUser,
      hostKeyChecking: this.parseHostKeyChecking(config.hostKeyChecking),
      hostKeyAlgorithms: Array.isArray(config.hostKeyAlgorithms)
        ? config.hostKeyAlgorithms.map((algorithm: unknown) => String(algorithm))
        : typeof config.hostKeyAlgorithms === "string"
          ? this.parseList(config.hostKeyAlgorithms)
          : undefined,
      knownHostsFiles: Array.isArray(config.knownHostsFiles)
        ? config.knownHostsFiles.map((file: unknown) =>
            this.normalizeLocalPath(String(file)),
          )
        : typeof config.knownHostsFiles === "string"
          ? this.parseList(config.knownHostsFiles)?.map((file) =>
              this.normalizeLocalPath(file),
            )
          : undefined,
    };
  }

  private static parseCommandTemplate(
    value: unknown,
  ): string | undefined {
    if (value === undefined || value === null || value === "") {
      return undefined;
    }

    const template = String(value);
    if (!template.includes("<command>") && !template.includes("<quotedCommand>")) {
      throw new Error(
        `commandTemplate must contain '<command>' or '<quotedCommand>' placeholder, got: ${template}`,
      );
    }

    return template;
  }

  private static normalizeLocalPath(localPath: string): string {
    return path.resolve(this.expandHomePath(localPath));
  }

  private static expandHomePath(localPath: string): string {
    if (localPath === "~") {
      return os.homedir();
    }
    if (localPath.startsWith("~/")) {
      return path.join(os.homedir(), localPath.slice(2));
    }
    return localPath;
  }

  private static normalizeRemotePath(remotePath: string): string {
    if (!remotePath) {
      return "";
    }
    if (!path.posix.isAbsolute(remotePath)) {
      throw new Error(
        `allowedRemotePaths entries must be absolute POSIX paths, got: ${remotePath}`,
      );
    }
    const normalized = path.posix.normalize(remotePath);
    if (normalized.length > 1 && normalized.endsWith("/")) {
      return normalized.slice(0, -1);
    }
    return normalized;
  }
}
