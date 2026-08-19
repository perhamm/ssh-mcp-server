import { randomBytes } from "node:crypto";
import { createRequire } from "node:module";
import type { Client, ClientChannel, SFTPWrapper, Stats } from "ssh2";
import {
  SSHConfig,
  SshConnectionConfigMap,
  ServerStatus,
  DynamicHostsConfig,
} from "../models/types.js";
import { Logger } from "../utils/logger.js";
import { collectSystemStatus } from "../utils/status-collector.js";
import { ToolError, toToolError } from "../utils/tool-error.js";
import { AuditLog } from "../utils/audit-log.js";
import {
  CompiledGuard,
  compileGuard,
  describeGuard,
  evaluateGuard,
  findForbiddenPath,
  loadGuardRuleset,
} from "../guards/guard-rules.js";
import {
  appendKnownHost,
  defaultKnownHostsFiles,
  formatFingerprint,
  HostKeyChecking,
  knownHostsCandidates,
  loadKnownHosts,
  readKeyType,
  verifyHostKey,
} from "../utils/known-hosts.js";
import {
  listSshConfigHosts,
  lookupSshConfig,
  resolveJumpChain,
  SshConfigHost,
  SshHopTarget,
} from "../utils/ssh-config-parser.js";
import fs from "fs";
import os from "os";
import path from "path";
import type { Duplex } from "node:stream";
import { pipeline } from "node:stream/promises";
import { StringDecoder } from "node:string_decoder";

const require = createRequire(import.meta.url);

type RunCommandOptions = {
  timeout?: number;
  sudo?: boolean;
  prevalidatedInternalCommand?: boolean;
};

type LocalPathPurpose = "read" | "write";

type RemotePathPurpose = "read" | "write";

type ShellCommandMatch = {
  output: string;
  exitCode: number;
  remainder: string;
};

/**
 * Incremental marker scanner state.
 *
 * Scanning the accumulated buffer on every chunk is quadratic, and not only
 * because of the repeated comparisons: `indexOf` needs a flat string, so each
 * call re-flattens the rope built by the appends and copies the whole buffer
 * again. `tail` therefore holds just the text that could still start a marker —
 * the previous scan already ruled out everything before it — so each chunk is
 * examined once against a short string, and the accumulated buffer is only
 * touched when a complete marker has been located.
 *
 * `tailStart` is the absolute index of `tail[0]` within that buffer, which is
 * what turns a tail-relative hit back into an absolute position.
 */
type ShellScanState = {
  outputStartIndex: number;
  tail: string;
  tailStart: number;
  countedOutputEndIndex: number;
  capturedOutputBytes: number;
};

type SshAuthMethod =
  | "none"
  | "password"
  | "publickey"
  | "agent"
  | "keyboard-interactive"
  | "hostbased";

const ANSI_OSC_PATTERN = /\u001b\][^\u0007\u001b]*(?:\u0007|\u001b\\)/g;
const ANSI_CSI_PATTERN = /\u001b\[[0-?]*[ -/]*[@-~]/g;

// Matches the exit code that `buildShellCommandScript` prints right after the
// end marker prefix, anchored so it can only be read at the expected offset.
const SHELL_EXIT_CODE_PATTERN = /^(-?\d+)__(?:\r)?\n/;
const SHELL_EXIT_CODE_MAX_LENGTH = 32;

const COMMAND_TEMPLATE_PLACEHOLDER = "<command>";
const QUOTED_COMMAND_TEMPLATE_PLACEHOLDER = "<quotedCommand>";
const DEFAULT_CONNECTION_TIMEOUT_MS = 30000;
const DEFAULT_COMMAND_TIMEOUT_MS = 30000;
const DEFAULT_KEEPALIVE_INTERVAL_MS = 10000;
const DEFAULT_KEEPALIVE_COUNT_MAX = 3;
const DEFAULT_SFTP_TIMEOUT_MS = 300000;
const DEFAULT_MAX_OUTPUT_BYTES = 10 * 1024 * 1024;
const DEFAULT_SUDO_PASSWORD_ENV = "SSH_MCP_SUDO_PASSWORD";

// Ed25519 first, and nothing that rests on SHA-1, CBC or DSA. ssh2 would
// otherwise negotiate ssh-rsa, 3des-cbc and hmac-md5 with an old server, which
// is exactly the set an attacker gets to pick from.
const DEFAULT_ALGORITHMS = {
  serverHostKey: [
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "rsa-sha2-512",
    "rsa-sha2-256",
  ],
  kex: [
    "curve25519-sha256",
    "curve25519-sha256@libssh.org",
    "ecdh-sha2-nistp256",
    "ecdh-sha2-nistp384",
    "ecdh-sha2-nistp521",
    "diffie-hellman-group-exchange-sha256",
    "diffie-hellman-group16-sha512",
    "diffie-hellman-group18-sha512",
    "diffie-hellman-group14-sha256",
  ],
  cipher: [
    "chacha20-poly1305@openssh.com",
    "aes256-gcm@openssh.com",
    "aes128-gcm@openssh.com",
    "aes256-ctr",
    "aes192-ctr",
    "aes128-ctr",
  ],
  hmac: [
    "hmac-sha2-256-etm@openssh.com",
    "hmac-sha2-512-etm@openssh.com",
    "hmac-sha2-256",
    "hmac-sha2-512",
  ],
} as const;

// ssh2's SFTP ReadStream/WriteStream keep a single request in flight, so
// transfer throughput is capped at one chunk per round trip regardless of the
// available bandwidth. fastGet/fastPut pipeline `concurrency` chunks instead,
// which is what makes large transfers usable on high latency links.
const SFTP_FAST_TRANSFER_OPTIONS = {
  concurrency: 64,
  chunkSize: 32 * 1024,
} as const;

// Under this size the streaming path already completes in a couple of round
// trips, so the extra stat fastGet needs would cost more than the concurrency
// saves. Staying on the streaming path below the threshold also keeps the
// existing behaviour for files whose reported size is unusable: fastGet/fastPut
// plan their chunks from that size and treat `size <= 0` as "nothing to
// transfer", which would silently produce an empty file for pseudo files such
// as /proc/cpuinfo.
const SFTP_FAST_TRANSFER_MIN_BYTES = 256 * 1024;

function applyCommandTemplate(template: string, command: string): string {
  const quotedCommand = shellQuote(command);
  return template
    .split(QUOTED_COMMAND_TEMPLATE_PLACEHOLDER)
    .join(quotedCommand)
    .split(`'${COMMAND_TEMPLATE_PLACEHOLDER}'`)
    .join(quotedCommand)
    .split(`"${COMMAND_TEMPLATE_PLACEHOLDER}"`)
    .join(quotedCommand)
    .split(COMMAND_TEMPLATE_PLACEHOLDER)
    .join(command);
}

function shellQuote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

/**
 * The caller cannot see the process working directory or the server's path
 * configuration, so a rejection that only says "must be within an allowed path"
 * leaves it nothing to correct against. Name the roots instead.
 */
function describeAllowedRoots(
  kind: "local" | "remote",
  allowedRoots: string[],
): string {
  return `Allowed ${kind} paths for this connection: ${allowedRoots.join(", ")}.`;
}

function isPathWithinRoot(candidate: string, root: string): boolean {
  const relativePath = path.relative(root, candidate);
  return (
    relativePath === "" ||
    (relativePath !== "" &&
      !relativePath.startsWith("..") &&
      !path.isAbsolute(relativePath))
  );
}

function redactProxyUrl(proxyUrl: URL): string {
  const redactedUrl = new URL(proxyUrl.toString());
  if (redactedUrl.username) {
    redactedUrl.username = "***";
  }
  if (redactedUrl.password) {
    redactedUrl.password = "***";
  }
  return redactedUrl.toString();
}

function normalizeUrlHostname(hostname: string): string {
  if (hostname.startsWith("[") && hostname.endsWith("]")) {
    return hostname.slice(1, -1);
  }
  return hostname;
}

function formatHostPort(host: string, port: number): string {
  const formattedHost = host.includes(":") && !host.startsWith("[")
    ? `[${host}]`
    : host;
  return `${formattedHost}:${port}`;
}

function parseProxyPort(proxyUrl: URL, defaultPort?: number): number {
  const port = proxyUrl.port
    ? Number.parseInt(proxyUrl.port, 10)
    : defaultPort;
  if (!port || !Number.isInteger(port) || port <= 0 || port > 65535) {
    throw new Error("Proxy URL must include a valid port");
  }
  return port;
}

export function matchesHostPattern(alias: string, pattern: string): boolean {
  const regexSource = pattern
    .replace(/[.+^${}()|[\]\\]/g, "\\$&")
    .replace(/\*/g, ".*")
    .replace(/\?/g, ".");

  return new RegExp(`^${regexSource}$`).test(alias);
}

/**
 * Keep a credential that was written to the remote side out of what the caller
 * gets back: a pty echoes what is typed into it, so a sudo password can end up
 * in the captured output.
 */
export function redactSecret(output: string, secret?: string): string {
  if (!secret || !output) {
    return output;
  }

  return output.split(secret).join("***");
}

function redactToolError(error: unknown, secret?: string): unknown {
  if (!secret) {
    return error;
  }

  if (error instanceof ToolError) {
    return new ToolError(
      error.code,
      redactSecret(error.message, secret),
      error.retriable,
    );
  }

  if (error instanceof Error) {
    error.message = redactSecret(error.message, secret);
  }

  return error;
}

function isPasswordPrompt(prompt: string): boolean {
  const promptText = prompt.toLowerCase();
  return promptText.includes("password") || promptText.includes("密码");
}

function isAuthMethodAllowedByServer(
  method: SshAuthMethod,
  methodsLeft: string[] | null,
): boolean {
  if (methodsLeft === null) {
    return true;
  }

  // ssh-agent uses the SSH publickey protocol method.
  if (method === "agent") {
    return methodsLeft.includes("publickey");
  }

  return methodsLeft.includes(method);
}

/**
 * SSH Connection Manager class
 */
export class SSHConnectionManager {
  private static instance: SSHConnectionManager;
  private clients: Map<string, Client> = new Map();
  private configs: SshConnectionConfigMap = {};
  private connected: Map<string, boolean> = new Map();
  private statusCache: Map<string, ServerStatus> = new Map();
  private pendingConnections: Map<string, Promise<void>> = new Map();
  private pendingStatusCollections: Map<string, NodeJS.Timeout> = new Map();
  private commandWhitelistRegexes: Map<string, RegExp[]> = new Map();
  private commandBlacklistRegexes: Map<string, RegExp[]> = new Map();
  private shellStreams: Map<string, ClientChannel> = new Map();
  private shellReady: Map<string, boolean> = new Map();
  private shellQueues: Map<string, Promise<unknown>> = new Map();
  private shellBuffers: Map<string, string> = new Map();
  // A multi-byte character can be split across two TCP chunks, so the channel
  // needs one decoder for its whole lifetime rather than a decode per chunk.
  private shellDecoders: Map<string, StringDecoder> = new Map();
  private guards: Map<string, CompiledGuard> = new Map();
  private jumpClients: Map<string, Client[]> = new Map();
  private connectionCloseListeners: Array<(key: string) => void> = [];
  private hostKeyFailures: Map<string, string> = new Map();
  private audit = AuditLog.getInstance();
  private dynamicHosts: DynamicHostsConfig = { enabled: false, template: {} };
  private defaultName: string = "default";

  private constructor() {}

  /**
   * Get singleton instance
   */
  public static getInstance(): SSHConnectionManager {
    if (!SSHConnectionManager.instance) {
      SSHConnectionManager.instance = new SSHConnectionManager();
    }
    return SSHConnectionManager.instance;
  }

  /**
   * Batch set SSH configurations
   */
  public setConfig(
    configs: SshConnectionConfigMap,
    defaultName?: string,
  ): void {
    this.disconnect();

    this.commandWhitelistRegexes.clear();
    this.commandBlacklistRegexes.clear();
    this.guards.clear();
    this.configs = {};

    for (const [name, config] of Object.entries(configs)) {
      this.registerConfig(name, config);
    }

    if (defaultName && configs[defaultName]) {
      this.defaultName = defaultName;
    } else if (Object.keys(configs).length > 0) {
      this.defaultName = Object.keys(configs)[0];
    }
  }

  /**
   * Enable connections that are resolved from the SSH config when they are
   * first used, so a single server instance can reach every host alias the
   * operator already has in ~/.ssh/config.
   */
  public setDynamicHosts(dynamicHosts: DynamicHostsConfig): void {
    this.dynamicHosts = dynamicHosts;
  }

  public getDynamicHosts(): DynamicHostsConfig {
    return this.dynamicHosts;
  }

  /**
   * List the SSH config aliases this server is allowed to connect to.
   */
  public getSshConfigHosts(): SshConfigHost[] {
    if (!this.dynamicHosts.enabled) {
      return [];
    }

    return listSshConfigHosts(this.dynamicHosts.sshConfigFile).filter((host) =>
      this.isHostAllowed(host.alias),
    );
  }

  private registerConfig(name: string, config: SSHConfig): void {
    this.commandWhitelistRegexes.set(
      name,
      this.compilePatterns(config.commandWhitelist, name, "whitelist"),
    );
    this.commandBlacklistRegexes.set(
      name,
      this.compilePatterns(config.commandBlacklist, name, "blacklist"),
    );
    this.guards.set(name, this.compileGuardForConfig(name, config));
    this.configs[name] = config;
  }

  private compileGuardForConfig(
    name: string,
    config: SSHConfig,
  ): CompiledGuard {
    const profile = config.guardProfile || "off";
    try {
      return compileGuard(profile, loadGuardRuleset(config.guardsFile));
    } catch (error) {
      throw new Error(
        `Failed to load guard profile for '${name}': ${(error as Error).message}`,
      );
    }
  }

  public getGuard(name?: string): CompiledGuard | undefined {
    return this.guards.get(name || this.defaultName);
  }

  public getGuardForTemplate(
    template: Partial<SSHConfig>,
  ): CompiledGuard {
    return compileGuard(
      template.guardProfile || "off",
      loadGuardRuleset(template.guardsFile),
    );
  }

  /**
   * Get specified connection configuration
   */
  public getConfig(name?: string): SSHConfig {
    const key = name || this.defaultName;
    if (!this.configs[key]) {
      const resolved = this.resolveDynamicConfig(key);
      if (!resolved) {
        throw new ToolError(
          "SSH_CONFIGURATION_MISSING",
          this.dynamicHosts.enabled
            ? `SSH configuration for '${key}' not set and no such host alias in the SSH config. Call list-ssh-hosts to see the available aliases.`
            : `SSH configuration for '${key}' not set`,
          false,
        );
      }
      this.registerConfig(key, resolved);
    }
    return this.configs[key];
  }

  /**
   * Build a connection from an SSH config alias.
   *
   * Credentials stay on this side: the key path comes from the SSH config or
   * the agent socket, so the caller only ever names an alias.
   */
  private resolveDynamicConfig(alias: string): SSHConfig | undefined {
    if (!this.dynamicHosts.enabled || !alias) {
      return undefined;
    }

    if (!this.isHostAllowed(alias)) {
      throw new ToolError(
        "SSH_HOST_NOT_ALLOWED",
        `Host alias '${alias}' is not in the allowed hosts of this server`,
        false,
      );
    }

    // A `Host *` block answers for any name, so an alias that is not declared
    // in the config would otherwise let the caller point this server at an
    // arbitrary host of its choosing.
    const declared = listSshConfigHosts(this.dynamicHosts.sshConfigFile).some(
      (host) => host.alias === alias,
    );
    if (!declared) {
      return undefined;
    }

    // A declared alias without a HostName is connected to by its own name,
    // exactly as ssh does it.
    const entry = lookupSshConfig(alias, this.dynamicHosts.sshConfigFile) || {};
    const template = this.dynamicHosts.template;
    const username = entry.user || template.username || os.userInfo().username;
    const privateKey = entry.identityFile || template.privateKey;
    const agent = template.agent || process.env.SSH_AUTH_SOCK;

    if (!privateKey && !agent) {
      throw new ToolError(
        "SSH_AUTHENTICATION_MISSING",
        `Host alias '${alias}' has no IdentityFile in the SSH config and no SSH agent is available`,
        false,
      );
    }

    return {
      ...template,
      name: alias,
      host: entry.hostName || alias,
      port: entry.port || 22,
      username,
      privateKey,
      agent,
      proxyJump: entry.proxyJump || template.proxyJump,
      knownHostsFiles: entry.userKnownHostsFiles || template.knownHostsFiles,
      sshConfigFile: this.dynamicHosts.sshConfigFile,
      transportMode: template.transportMode || "exec",
    };
  }

  private isHostAllowed(alias: string): boolean {
    const patterns = this.dynamicHosts.allowPatterns;
    if (!patterns || patterns.length === 0) {
      return true;
    }

    return patterns.some((pattern) => matchesHostPattern(alias, pattern));
  }

  /**
   * Batch connect all configured SSH connections
   */
  public async connectAll(): Promise<void> {
    const names = Object.keys(this.configs);
    const results = await Promise.allSettled(
      names.map((name) => this.connect(name)),
    );
    const failures = results
      .map((result, index) => ({ result, name: names[index] }))
      .filter(
        (entry): entry is {
          result: PromiseRejectedResult;
          name: string;
        } => entry.result.status === "rejected",
      );

    if (failures.length > 0) {
      throw new ToolError(
        "SSH_CONNECTION_FAILED",
        failures
          .map(
            ({ name, result }) =>
              `[${name}] ${
                result.reason instanceof Error
                  ? result.reason.message
                  : String(result.reason)
              }`,
          )
          .join("; "),
        true,
      );
    }
  }

  /**
   * Connect to SSH with specified name
   */
  public async connect(name?: string): Promise<void> {
    const key = name || this.defaultName;
    if (this.hasUsableConnection(key)) {
      return;
    }

    const existingConnection = this.pendingConnections.get(key);
    if (existingConnection) {
      await existingConnection;
      return;
    }

    const config = this.getConfig(key);
    const client = this.createClient();
    this.hostKeyFailures.delete(key);
    const connectionPromise = new Promise<void>(async (resolve, reject) => {
      let settled = false;
      const timeoutMs = this.getConnectionTimeoutMs(config);
      const timeoutId = setTimeout(() => {
        rejectOnce(
          new ToolError(
            "SSH_CONNECTION_TIMEOUT",
            `SSH connection [${key}] timed out after ${timeoutMs}ms`,
            true,
          ),
        );
        this.invalidateConnection(key);
        try {
          client.destroy();
        } catch {
          // Ignore cleanup errors during connection timeout.
        }
      }, timeoutMs);

      const clearConnectionTimeout = () => clearTimeout(timeoutId);

      const resolveOnce = () => {
        if (settled) {
          return;
        }
        settled = true;
        clearConnectionTimeout();
        resolve();
      };

      const rejectOnce = (error: unknown) => {
        if (settled) {
          return;
        }
        settled = true;
        clearConnectionTimeout();
        reject(error);
      };

      client.on("ready", async () => {
        Logger.log(
          `Successfully connected to SSH server [${key}] ${config.host}:${config.port}`,
        );
        this.audit.record({
          event: "connect",
          result: "ok",
          connection: key,
          host: config.host,
          port: config.port,
          username: config.username,
        });

        try {
          if (this.getTransportMode(config) === "shell") {
            await this.initializeShellSession(client, key, config);
          }

          this.clients.set(key, client);
          this.connected.set(key, true);
          this.scheduleStatusCollection(key);
          resolveOnce();
        } catch (error) {
          this.connected.set(key, false);
          this.cleanupShellState(key, true);
          try {
            client.end();
          } catch {
            // Ignore cleanup errors during failed initialization.
          }
          rejectOnce(
            error instanceof ToolError
              ? error
              : new ToolError(
                  "SSH_CONNECTION_FAILED",
                  `SSH connection [${key}] failed: ${(error as Error).message}`,
                  true,
                ),
          );
        }
      });

      client.on("error", (err: Error) => {
        this.connected.set(key, false);
        if (this.clients.get(key) === client || this.shellStreams.has(key)) {
          this.invalidateConnection(key);
        }
        rejectOnce(
          this.hostKeyError(key) ||
            new ToolError(
              "SSH_CONNECTION_FAILED",
              `SSH connection [${key}] failed: ${err.message}`,
              true,
            ),
        );
      });

      client.on("close", () => {
        this.clearConnectionState(key);
        Logger.log(`SSH connection [${key}] closed`, "info");
      });

      try {
        const sshConfig = await this.buildClientConfig(key, config);
        client.connect(sshConfig);
      } catch (error) {
        rejectOnce(error);
      }
    });

    this.pendingConnections.set(key, connectionPromise);

    try {
      await connectionPromise;
    } finally {
      this.pendingConnections.delete(key);
    }
  }

  /**
   * Get SSH Client with specified name
   */
  public getClient(name?: string): Client {
    const key = name || this.defaultName;
    const client = this.clients.get(key);
    if (!client) {
      throw new Error(`SSH client for '${key}' not connected`);
    }
    return client;
  }

  /**
   * Execute SSH command
   */
  public async executeCommand(
    cmdString: string,
    directory?: string,
    name?: string,
    options: { timeout?: number; sudo?: boolean } = {},
  ): Promise<string> {
    const startedAt = Date.now();
    const key = name || this.defaultName;

    try {
      const output = await this.runCommandInternal(
        cmdString,
        directory,
        name,
        options,
      );
      this.audit.record({
        event: "command",
        result: "ok",
        connection: key,
        command: cmdString,
        directory,
        sudo: options.sudo === true,
        durationMs: Date.now() - startedAt,
        bytes: Buffer.byteLength(output),
      });
      return output;
    } catch (error) {
      const toolError = toToolError(error, "UNKNOWN_ERROR");
      this.audit.record({
        event: "command",
        result:
          toolError.code === "COMMAND_VALIDATION_FAILED" ||
          toolError.code === "SUDO_NOT_ALLOWED"
            ? "blocked"
            : "error",
        connection: key,
        command: cmdString,
        directory,
        sudo: options.sudo === true,
        code: toolError.code,
        reason: toolError.message,
        durationMs: Date.now() - startedAt,
      });
      throw error;
    }
  }

  /**
   * Read the sudo password from the server environment.
   *
   * The password is never part of the tool schema, the command line or the
   * output, so the model can ask for elevation without ever seeing it.
   */
  private resolveSudoPassword(config: SSHConfig, key: string): string {
    const guard = this.guards.get(key);
    if (guard && !guard.allowSudo) {
      throw new ToolError(
        "SUDO_NOT_ALLOWED",
        `Guard profile '${guard.profile}' (ruleset ${guard.version}) does not allow sudo on [${key}]`,
        false,
      );
    }

    const variableName = config.sudoPasswordEnv || DEFAULT_SUDO_PASSWORD_ENV;
    const password = process.env[variableName];

    if (!password) {
      throw new ToolError(
        "SUDO_PASSWORD_MISSING",
        `sudo was requested for [${key}] but the environment variable ${variableName} is empty. Set it in the MCP server environment.`,
        false,
      );
    }

    return password;
  }

  private buildSudoCommand(config: SSHConfig, command: string): string {
    const sudoUser = config.sudoUser || "root";
    return `sudo -S -k -p '' -u ${shellQuote(sudoUser)} -- /bin/sh -c ${shellQuote(
      command,
    )}`;
  }

  /**
   * Upload file
   */
  private validateLocalPath(
    localPath: string,
    name?: string,
    purpose: LocalPathPurpose = "read",
  ): string {
    if (typeof localPath !== "string" || localPath.length === 0) {
      throw new ToolError(
        "LOCAL_PATH_NOT_ALLOWED",
        "Local path must be a non-empty string.",
        false,
      );
    }
    if (localPath.includes("\0")) {
      throw new ToolError(
        "LOCAL_PATH_NOT_ALLOWED",
        "Local path must not contain null bytes.",
        false,
      );
    }

    const resolvedPath = path.resolve(localPath);
    const allowedRoots = this.getAllowedLocalRoots(name);
    const parentPath = path.dirname(resolvedPath);
    const existingPath = this.tryRealpath(resolvedPath);
    const parentRealPath = this.tryRealpath(parentPath);

    let pathToCheck = existingPath;
    if (!pathToCheck && parentRealPath) {
      pathToCheck = path.join(parentRealPath, path.basename(resolvedPath));
    }
    if (!pathToCheck) {
      pathToCheck = resolvedPath;
    }

    if (purpose === "write") {
      // `download` writes on this side, so the paths the forbidden core keeps
      // off limits remotely have to be off limits here as well: a downloaded
      // file must not be able to become the operator's authorized_keys.
      const guard = this.guards.get(name || this.defaultName);
      const forbiddenPath = guard
        ? findForbiddenPath(
            pathToCheck.split(path.sep).join("/"),
            guard.forbiddenRemoteWritePaths,
          )
        : undefined;

      if (forbiddenPath) {
        throw new ToolError(
          "LOCAL_PATH_FORBIDDEN",
          `Local path ${pathToCheck} is inside ${forbiddenPath}, which the forbidden core keeps off limits for writes (ruleset ${guard?.version}).`,
          false,
        );
      }
    }

    if (purpose === "write" && !parentRealPath) {
      throw new ToolError(
        "LOCAL_PATH_NOT_ALLOWED",
        `Local path parent directory must exist and be within an allowed local path. Resolved to: ${resolvedPath}. ${describeAllowedRoots(
          "local",
          allowedRoots,
        )}`,
        false,
      );
    }

    const isAllowed = allowedRoots.some((allowedRoot) =>
      isPathWithinRoot(pathToCheck, allowedRoot),
    );

    if (!isAllowed) {
      throw new ToolError(
        "LOCAL_PATH_NOT_ALLOWED",
        `Path traversal detected. Local path resolved to: ${pathToCheck}. ${describeAllowedRoots(
          "local",
          allowedRoots,
        )}`,
        false,
      );
    }
    return resolvedPath;
  }

  private getAllowedLocalRoots(name?: string): string[] {
    const config = this.getConfig(name);
    return [process.cwd(), ...(config.allowedLocalPaths || [])]
      .filter((allowedPath) => allowedPath.trim().length > 0)
      .map((allowedPath) => {
        const resolvedRoot = path.resolve(allowedPath);
        return this.tryRealpath(resolvedRoot) || resolvedRoot;
      });
  }

  private tryRealpath(localPath: string): string | undefined {
    try {
      return fs.realpathSync.native(localPath);
    } catch {
      return undefined;
    }
  }

  private validateRemotePath(
    remotePath: string,
    name?: string,
    purpose: RemotePathPurpose = "read",
  ): string {
    if (typeof remotePath !== "string" || remotePath.length === 0) {
      throw new ToolError(
        "REMOTE_PATH_NOT_ALLOWED",
        "Remote path must be a non-empty string.",
        false,
      );
    }
    if (remotePath.includes("\0")) {
      throw new ToolError(
        "REMOTE_PATH_NOT_ALLOWED",
        "Remote path must not contain null bytes.",
        false,
      );
    }
    if (!path.posix.isAbsolute(remotePath)) {
      throw new ToolError(
        "REMOTE_PATH_NOT_ALLOWED",
        `Remote path must be an absolute POSIX path, got: ${remotePath}`,
        false,
      );
    }

    const resolvedPath = path.posix.normalize(remotePath);
    const config = this.getConfig(name);
    const guard = this.guards.get(name || this.defaultName);

    // SFTP would otherwise be the way around the forbidden command rules: an
    // upload can drop a cron job or an authorized_keys file just as well.
    if (guard) {
      const forbiddenPaths =
        purpose === "write"
          ? [
              ...guard.forbiddenRemoteWritePaths,
              ...guard.forbiddenRemoteReadPaths,
            ]
          : guard.forbiddenRemoteReadPaths;
      const forbiddenPath = findForbiddenPath(resolvedPath, forbiddenPaths);

      if (forbiddenPath) {
        throw new ToolError(
          "REMOTE_PATH_FORBIDDEN",
          `Remote path ${resolvedPath} is inside ${forbiddenPath}, which the forbidden core keeps off limits for ${
            purpose === "write" ? "writes" : "reads"
          } (ruleset ${guard.version}). No guard profile lifts this.`,
          false,
        );
      }
    }

    const allowedRoots = config.allowedRemotePaths || [];

    if (allowedRoots.length === 0) {
      return resolvedPath;
    }

    const isAllowed = allowedRoots.some(
      (allowedRoot) =>
        resolvedPath === allowedRoot ||
        resolvedPath.startsWith(
          allowedRoot.endsWith("/") ? allowedRoot : `${allowedRoot}/`,
        ),
    );

    if (!isAllowed) {
      throw new ToolError(
        "REMOTE_PATH_NOT_ALLOWED",
        `Remote path is not within the configured allowedRemotePaths. Resolved to: ${resolvedPath}. ${describeAllowedRoots(
          "remote",
          allowedRoots,
        )}`,
        false,
      );
    }
    return resolvedPath;
  }

  /**
   * Upload file
   */
  public async upload(
    localPath: string,
    remotePath: string,
    name?: string,
  ): Promise<string> {
    try {
      const result = await this.uploadInternal(localPath, remotePath, name);
      this.audit.record({
        event: "upload",
        result: "ok",
        connection: name || this.defaultName,
        localPath,
        remotePath,
      });
      return result;
    } catch (error) {
      const toolError = toToolError(error, "UNKNOWN_ERROR");
      this.audit.record({
        event: "upload",
        result: "blocked",
        connection: name || this.defaultName,
        localPath,
        remotePath,
        code: toolError.code,
        reason: toolError.message,
      });
      throw error;
    }
  }

  private async uploadInternal(
    localPath: string,
    remotePath: string,
    name?: string,
  ): Promise<string> {
    const config = this.getConfig(name);
    const key = name || this.defaultName;
    if (this.getTransportMode(config) === "shell") {
      throw new ToolError(
        "UNSUPPORTED_IN_SHELL_MODE",
        "Current bastion shell mode does not support SFTP upload/download.",
        false,
      );
    }

    this.assertFileWriteAllowed(key);
    const validatedLocalPath = this.validateLocalPath(localPath, name, "read");
    const validatedRemotePath = this.validateRemotePath(remotePath, name, "write");
    const client = await this.ensureConnected(name);
    const sftpTimeoutMs = this.getSftpTimeoutMs(config);
    const sftp = await this.withTimeout(
      this.openSftp(client),
      sftpTimeoutMs,
      () => this.invalidateConnection(key),
      `SFTP open timed out after ${sftpTimeoutMs}ms`,
    );

    try {
      const localSize = await this.getLocalSizeForFastTransfer(
        validatedLocalPath,
      );

      if (localSize === undefined) {
        await this.withTimeout(
          pipeline(
            fs.createReadStream(validatedLocalPath),
            sftp.createWriteStream(validatedRemotePath),
          ),
          sftpTimeoutMs,
          () => this.invalidateConnection(key),
          `SFTP upload timed out after ${sftpTimeoutMs}ms`,
        );
      } else {
        await this.withTimeout(
          new Promise<void>((resolve, reject) => {
            sftp.fastPut(
              validatedLocalPath,
              validatedRemotePath,
              SFTP_FAST_TRANSFER_OPTIONS,
              (err) => (err ? reject(err) : resolve()),
            );
          }),
          sftpTimeoutMs,
          () => this.invalidateConnection(key),
          `SFTP upload timed out after ${sftpTimeoutMs}ms`,
        );
        await this.appendUploadTail(
          sftp,
          validatedLocalPath,
          validatedRemotePath,
          localSize,
          sftpTimeoutMs,
          key,
        );
      }
      return "File uploaded successfully";
    } catch (error) {
      if (error instanceof ToolError && error.code === "OPERATION_TIMEOUT") {
        throw error;
      }
      if (this.errorPathMatches(error, validatedLocalPath)) {
        throw new ToolError(
          "LOCAL_FILE_READ_FAILED",
          `Failed to read local file: ${(error as Error).message}`,
          false,
        );
      }
      throw new ToolError(
        "SFTP_ERROR",
        `File upload failed: ${(error as Error).message}`,
        true,
      );
    } finally {
      this.closeSftp(sftp);
    }
  }

  /**
   * Download file
   */
  public async download(
    remotePath: string,
    localPath: string,
    name?: string,
  ): Promise<string> {
    try {
      const result = await this.downloadInternal(remotePath, localPath, name);
      this.audit.record({
        event: "download",
        result: "ok",
        connection: name || this.defaultName,
        localPath,
        remotePath,
      });
      return result;
    } catch (error) {
      const toolError = toToolError(error, "UNKNOWN_ERROR");
      this.audit.record({
        event: "download",
        result: "blocked",
        connection: name || this.defaultName,
        localPath,
        remotePath,
        code: toolError.code,
        reason: toolError.message,
      });
      throw error;
    }
  }

  private async downloadInternal(
    remotePath: string,
    localPath: string,
    name?: string,
  ): Promise<string> {
    const config = this.getConfig(name);
    const key = name || this.defaultName;
    if (this.getTransportMode(config) === "shell") {
      throw new ToolError(
        "UNSUPPORTED_IN_SHELL_MODE",
        "Current bastion shell mode does not support SFTP upload/download.",
        false,
      );
    }

    const validatedLocalPath = this.validateLocalPath(localPath, name, "write");
    const validatedRemotePath = this.validateRemotePath(remotePath, name);
    const client = await this.ensureConnected(name);
    const sftpTimeoutMs = this.getSftpTimeoutMs(config);
    const sftp = await this.withTimeout(
      this.openSftp(client),
      sftpTimeoutMs,
      () => this.invalidateConnection(key),
      `SFTP open timed out after ${sftpTimeoutMs}ms`,
    );
    const tempLocalPath = `${validatedLocalPath}.tmp-${process.pid}-${Date.now()}-${Math.random()
      .toString(16)
      .slice(2)}`;

    try {
      const remoteSize = await this.getRemoteSizeForFastTransfer(
        sftp,
        validatedRemotePath,
        sftpTimeoutMs,
        key,
      );

      if (remoteSize === undefined) {
        await this.withTimeout(
          pipeline(
            sftp.createReadStream(validatedRemotePath),
            fs.createWriteStream(tempLocalPath, { flags: "wx" }),
          ),
          sftpTimeoutMs,
          () => this.invalidateConnection(key),
          `SFTP download timed out after ${sftpTimeoutMs}ms`,
        );
      } else {
        // fastGet opens the destination with "w", which would drop the
        // exclusive-create guarantee the streaming path gets from "wx".
        // Claiming the temp name first keeps it.
        await fs.promises.writeFile(tempLocalPath, "", { flag: "wx" });
        await this.withTimeout(
          new Promise<void>((resolve, reject) => {
            sftp.fastGet(
              validatedRemotePath,
              tempLocalPath,
              SFTP_FAST_TRANSFER_OPTIONS,
              (err) => (err ? reject(err) : resolve()),
            );
          }),
          sftpTimeoutMs,
          () => this.invalidateConnection(key),
          `SFTP download timed out after ${sftpTimeoutMs}ms`,
        );
        await this.appendDownloadTail(
          sftp,
          validatedRemotePath,
          tempLocalPath,
          sftpTimeoutMs,
          key,
        );
      }
      await fs.promises.rename(tempLocalPath, validatedLocalPath);
      return "File downloaded successfully";
    } catch (error) {
      await this.unlinkIfExists(tempLocalPath);
      if (error instanceof ToolError && error.code === "OPERATION_TIMEOUT") {
        throw error;
      }
      if (
        this.errorPathMatches(error, tempLocalPath) ||
        this.errorPathMatches(error, validatedLocalPath)
      ) {
        throw new ToolError(
          "LOCAL_FILE_WRITE_FAILED",
          `Failed to save file: ${(error as Error).message}`,
          false,
        );
      }
      throw new ToolError(
        "SFTP_ERROR",
        `File download failed: ${(error as Error).message}`,
        true,
      );
    } finally {
      this.closeSftp(sftp);
    }
  }

  private openSftp(client: Client): Promise<SFTPWrapper> {
    return new Promise<SFTPWrapper>((resolve, reject) => {
      client.sftp((err: Error | undefined, sftp: SFTPWrapper) => {
        if (err) {
          reject(
            new ToolError(
              "SFTP_ERROR",
              `SFTP connection failed: ${err.message}`,
              true,
            ),
          );
          return;
        }

        resolve(sftp);
      });
    });
  }

  private statRemote(
    sftp: SFTPWrapper,
    remotePath: string,
  ): Promise<Stats> {
    return new Promise<Stats>((resolve, reject) => {
      sftp.stat(remotePath, (err, stats) =>
        err ? reject(err) : resolve(stats),
      );
    });
  }

  /**
   * Size to hand to the concurrent transfer path, or undefined to stay on the
   * streaming path. Anything unexpected — a missing file, a directory, a
   * server without stat support — falls back so the streaming path reports the
   * same error it reports today.
   */
  private async getRemoteSizeForFastTransfer(
    sftp: SFTPWrapper,
    remotePath: string,
    timeoutMs: number,
    key: string,
  ): Promise<number | undefined> {
    let stats: Stats;
    try {
      stats = await this.withTimeout(
        this.statRemote(sftp, remotePath),
        timeoutMs,
        () => this.invalidateConnection(key),
        `SFTP stat timed out after ${timeoutMs}ms`,
      );
    } catch (error) {
      // A timeout already tore the connection down, so it has to surface.
      if (error instanceof ToolError) {
        throw error;
      }
      return undefined;
    }

    return stats.isFile() && stats.size >= SFTP_FAST_TRANSFER_MIN_BYTES
      ? stats.size
      : undefined;
  }

  private async getLocalSizeForFastTransfer(
    localPath: string,
  ): Promise<number | undefined> {
    try {
      const stats = await fs.promises.stat(localPath);
      return stats.isFile() && stats.size >= SFTP_FAST_TRANSFER_MIN_BYTES
        ? stats.size
        : undefined;
    } catch {
      return undefined;
    }
  }

  /**
   * fastGet transfers exactly the byte count the remote file had when it
   * started, so data appended while it ran would be dropped. The streaming path
   * reads until EOF and would have picked that tail up, so fetch it here to
   * keep both paths equivalent for files that are still being written.
   */
  private async appendDownloadTail(
    sftp: SFTPWrapper,
    remotePath: string,
    tempLocalPath: string,
    timeoutMs: number,
    key: string,
  ): Promise<void> {
    const downloadedBytes = (await fs.promises.stat(tempLocalPath)).size;
    const stats = await this.withTimeout(
      this.statRemote(sftp, remotePath),
      timeoutMs,
      () => this.invalidateConnection(key),
      `SFTP stat timed out after ${timeoutMs}ms`,
    );

    if (stats.size <= downloadedBytes) {
      return;
    }

    await this.withTimeout(
      pipeline(
        sftp.createReadStream(remotePath, { start: downloadedBytes }),
        fs.createWriteStream(tempLocalPath, { flags: "a" }),
      ),
      timeoutMs,
      () => this.invalidateConnection(key),
      `SFTP download timed out after ${timeoutMs}ms`,
    );
  }

  /**
   * Upload counterpart of appendDownloadTail. The local stat is free, so the
   * remote round trip only happens when the local file actually grew.
   */
  private async appendUploadTail(
    sftp: SFTPWrapper,
    localPath: string,
    remotePath: string,
    sizeBeforeTransfer: number,
    timeoutMs: number,
    key: string,
  ): Promise<void> {
    const currentLocalSize = (await fs.promises.stat(localPath)).size;
    if (currentLocalSize <= sizeBeforeTransfer) {
      return;
    }

    const stats = await this.withTimeout(
      this.statRemote(sftp, remotePath),
      timeoutMs,
      () => this.invalidateConnection(key),
      `SFTP stat timed out after ${timeoutMs}ms`,
    );

    if (stats.size >= currentLocalSize) {
      return;
    }

    await this.withTimeout(
      pipeline(
        fs.createReadStream(localPath, { start: stats.size }),
        sftp.createWriteStream(remotePath, { flags: "a" }),
      ),
      timeoutMs,
      () => this.invalidateConnection(key),
      `SFTP upload timed out after ${timeoutMs}ms`,
    );
  }

  private closeSftp(sftp: SFTPWrapper): void {
    try {
      sftp.end();
    } catch {
      // Ignore cleanup errors after transfer completion.
    }
  }

  private withTimeout<T>(
    promise: Promise<T>,
    timeoutMs: number,
    onTimeout: () => void,
    message: string,
  ): Promise<T> {
    let timeoutId: NodeJS.Timeout;
    return new Promise<T>((resolve, reject) => {
      timeoutId = setTimeout(() => {
        try {
          onTimeout();
        } catch {
          // Ignore cleanup errors while rejecting a timed out operation.
        }
        reject(new ToolError("OPERATION_TIMEOUT", message, true));
      }, timeoutMs);

      promise.then(
        (value) => {
          clearTimeout(timeoutId);
          resolve(value);
        },
        (error) => {
          clearTimeout(timeoutId);
          reject(error);
        },
      );
    });
  }

  private errorPathMatches(error: unknown, localPath: string): boolean {
    const errorPath = (error as NodeJS.ErrnoException).path;
    return typeof errorPath === "string" && path.resolve(errorPath) === localPath;
  }

  private async unlinkIfExists(localPath: string): Promise<void> {
    try {
      await fs.promises.unlink(localPath);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
        Logger.log(
          `Failed to remove partial local file ${localPath}: ${(error as Error).message}`,
          "error",
        );
      }
    }
  }

  /**
   * Disconnect SSH connection
   */
  public disconnect(): void {
    for (const timeoutId of this.pendingStatusCollections.values()) {
      clearTimeout(timeoutId);
    }
    this.pendingStatusCollections.clear();

    for (const [key] of this.clients) {
      this.cleanupShellState(key, true);
    }

    if (this.clients.size > 0) {
      for (const client of this.clients.values()) {
        client.end();
      }
      this.clients.clear();
    }

    for (const key of Array.from(this.jumpClients.keys())) {
      this.closeJumpClients(key);
    }

    this.connected.clear();
    this.statusCache.clear();
    this.pendingConnections.clear();
    this.hostKeyFailures.clear();
    this.shellStreams.clear();
    this.shellReady.clear();
    this.shellQueues.clear();
    this.shellBuffers.clear();
    this.shellDecoders.clear();
  }

  /**
   * Get basic information of all configured servers
   */
  public getAllServerInfos(): Array<{
    name: string;
    host: string;
    port: number;
    username: string;
    connected: boolean;
    guards: string;
    proxyJump?: string;
    status?: ServerStatus;
  }> {
    return Object.keys(this.configs).map((key) => {
      const config = this.configs[key];
      const status = this.statusCache.get(key);
      return {
        name: key,
        host: config.host,
        port: config.port,
        username: config.username,
        connected: this.connected.get(key) === true,
        guards: describeGuard(this.guards.get(key)),
        proxyJump: config.proxyJump,
        status: status,
      };
    });
  }

  /**
   * Hand out a connected client for callers that open their own channels,
   * such as the tunnel manager.
   */
  public async getConnectedClient(name?: string): Promise<Client> {
    const key = name || this.defaultName;
    const config = this.getConfig(key);
    const connectionTimeoutMs = this.getConnectionTimeoutMs(config);
    return this.withTimeout(
      this.ensureConnected(key),
      connectionTimeoutMs,
      () => this.invalidateConnection(key),
      `SSH connection [${key}] timed out after ${connectionTimeoutMs}ms`,
    );
  }

  public onConnectionClosed(listener: (key: string) => void): void {
    this.connectionCloseListeners.push(listener);
  }

  private closeJumpClients(key: string): void {
    const clients = this.jumpClients.get(key);
    if (!clients) {
      return;
    }

    this.jumpClients.delete(key);
    for (const client of clients.reverse()) {
      try {
        client.end();
      } catch {
        // Ignore cleanup errors while tearing down a jump chain.
      }
    }
  }

  private createClient(): Client {
    const { Client } = require("ssh2") as typeof import("ssh2");
    return new Client();
  }

  private async ensureConnected(name?: string): Promise<Client> {
    const key = name || this.defaultName;
    if (!this.hasUsableConnection(key)) {
      await this.connect(key);
    }

    const client = this.clients.get(key);
    if (!client) {
      throw new Error(`SSH client for '${key}' not initialized`);
    }
    return client;
  }

  private hasUsableConnection(key: string): boolean {
    const client = this.clients.get(key);
    if (!client || this.connected.get(key) !== true) {
      return false;
    }

    const config = this.getConfig(key);
    if (this.getTransportMode(config) === "shell") {
      return (
        this.shellReady.get(key) === true && this.shellStreams.has(key)
      );
    }

    return true;
  }

  private getTransportMode(config: SSHConfig): "exec" | "shell" {
    return config.transportMode || "exec";
  }

  private getShellReadyTimeoutMs(config: SSHConfig): number {
    return config.shellReadyTimeoutMs || 10000;
  }

  private getShellCommandTimeoutMs(config: SSHConfig): number {
    return config.shellCommandTimeoutMs || DEFAULT_COMMAND_TIMEOUT_MS;
  }

  private getCommandTimeoutMs(config: SSHConfig): number {
    return config.commandTimeoutMs || DEFAULT_COMMAND_TIMEOUT_MS;
  }

  private getConnectionTimeoutMs(config: SSHConfig): number {
    return config.connectionTimeoutMs || DEFAULT_CONNECTION_TIMEOUT_MS;
  }

  private getSftpTimeoutMs(config: SSHConfig): number {
    return config.sftpTimeoutMs || DEFAULT_SFTP_TIMEOUT_MS;
  }

  private getMaxOutputBytes(config: SSHConfig): number {
    const configured = config.maxOutputBytes;
    if (configured === undefined) {
      return DEFAULT_MAX_OUTPUT_BYTES;
    }
    if (!Number.isSafeInteger(configured) || configured < 0) {
      throw new ToolError(
        "COMMAND_VALIDATION_FAILED",
        `maxOutputBytes must be a non-negative integer, got: ${String(configured)}`,
        false,
      );
    }
    return configured;
  }

  private async createSocksProxySocket(
    proxyUrl: URL,
    config: SSHConfig,
  ): Promise<Duplex> {
    const { SocksClient } = require("socks") as typeof import("socks");
    const proxyHost = normalizeUrlHostname(proxyUrl.hostname);
    const proxyPort = parseProxyPort(proxyUrl);
    if (!proxyHost) {
      throw new Error("Proxy URL must include a host");
    }

    const proxy: {
      host: string;
      port: number;
      type: 5;
      userId?: string;
      password?: string;
    } = {
      host: proxyHost,
      port: proxyPort,
      type: 5,
    };

    if (proxyUrl.username) {
      proxy.userId = decodeURIComponent(proxyUrl.username);
    }
    if (proxyUrl.password) {
      proxy.password = decodeURIComponent(proxyUrl.password);
    }

    const { socket } = await SocksClient.createConnection({
      proxy,
      command: "connect",
      destination: {
        host: config.host,
        port: config.port,
      },
      timeout: this.getConnectionTimeoutMs(config),
    });
    return socket;
  }

  private createHttpProxySocket(
    proxyUrl: URL,
    config: SSHConfig,
  ): Promise<Duplex> {
    const isTlsProxy = proxyUrl.protocol === "https:";
    const proxyHost = normalizeUrlHostname(proxyUrl.hostname);
    const proxyPort = parseProxyPort(proxyUrl, isTlsProxy ? 443 : 80);
    if (!proxyHost) {
      throw new Error("Proxy URL must include a host");
    }

    const destination = formatHostPort(config.host, config.port);
    const headers: Record<string, string> = { Host: destination };
    if (proxyUrl.username || proxyUrl.password) {
      const username = decodeURIComponent(proxyUrl.username);
      const password = decodeURIComponent(proxyUrl.password);
      headers["Proxy-Authorization"] = `Basic ${Buffer.from(
        `${username}:${password}`,
      ).toString("base64")}`;
    }

    return new Promise<Duplex>((resolve, reject) => {
      const options = {
        method: "CONNECT",
        hostname: proxyHost,
        port: proxyPort,
        path: destination,
        headers,
      };
      const proxyRequest = isTlsProxy
        ? (require("node:https") as typeof import("node:https")).request(options)
        : (require("node:http") as typeof import("node:http")).request(options);

      proxyRequest.once("connect", (response, socket, head) => {
        proxyRequest.setTimeout(0);
        if (response.statusCode !== 200) {
          socket.destroy();
          reject(
            new Error(
              `HTTP proxy CONNECT failed with status ${response.statusCode ?? "unknown"}`,
            ),
          );
          return;
        }
        if (head.length > 0) {
          socket.unshift(head);
        }
        resolve(socket);
      });
      proxyRequest.once("error", reject);
      proxyRequest.setTimeout(this.getConnectionTimeoutMs(config), () => {
        proxyRequest.destroy(new Error("HTTP proxy CONNECT timed out"));
      });
      proxyRequest.end();
    });
  }

  private async createProxySocket(
    proxyUrl: URL,
    config: SSHConfig,
  ): Promise<Duplex> {
    switch (proxyUrl.protocol) {
      case "socks:":
      case "socks5:":
        return this.createSocksProxySocket(proxyUrl, config);
      case "http:":
      case "https:":
        return this.createHttpProxySocket(proxyUrl, config);
      default:
        throw new Error(
          `Unsupported proxy protocol '${proxyUrl.protocol}'. Use socks://, socks5://, http://, or https://`,
        );
    }
  }

  /**
   * A profile that only allows reading commands has to cover SFTP too,
   * otherwise `upload` is a way to change the host it just refused to change.
   */
  private assertFileWriteAllowed(key: string): void {
    const guard = this.guards.get(key);
    if (guard && !guard.allowFileWrite) {
      throw new ToolError(
        "COMMAND_VALIDATION_FAILED",
        `Guard profile '${guard.profile}' (ruleset ${guard.version}) is read-only and does not allow uploads on [${key}]`,
        false,
      );
    }
  }

  /**
   * The negotiated algorithms, modern by default.
   *
   * `algorithms` in a connection config replaces the defaults wholesale, the
   * way it did before; `hostKeyAlgorithms` narrows only the host key list, so
   * a fleet that is fully on Ed25519 can pin it with a single option.
   */
  private buildAlgorithms(config: SSHConfig): Record<string, unknown> {
    const algorithms: Record<string, unknown> = {
      ...DEFAULT_ALGORITHMS,
      ...(config.algorithms as Record<string, unknown> | undefined),
    };

    if (config.hostKeyAlgorithms && config.hostKeyAlgorithms.length > 0) {
      algorithms.serverHostKey = config.hostKeyAlgorithms;
    }

    return algorithms;
  }

  private getKnownHostsFiles(config: SSHConfig): string[] {
    return config.knownHostsFiles && config.knownHostsFiles.length > 0
      ? config.knownHostsFiles
      : defaultKnownHostsFiles();
  }

  /**
   * Verify the host key against known_hosts before the session is trusted.
   *
   * Without this the server accepts whatever key answers on the target
   * address, which is exactly what a machine-in-the-middle needs. `strict`
   * refuses an unknown host, `accept-new` records it on first sight, and a key
   * that contradicts known_hosts is refused in every mode.
   */
  private createHostVerifier(
    key: string,
    config: SSHConfig,
    host: string,
    port: number,
    aliases: string[] = [],
  ): (hostKey: Buffer) => boolean {
    const mode: HostKeyChecking = config.hostKeyChecking || "strict";
    const files = this.getKnownHostsFiles(config);
    const target = port === 22 ? host : `${host}:${port}`;

    return (hostKey: Buffer): boolean => {
      const fingerprint = formatFingerprint(hostKey);
      const keyType = readKeyType(hostKey);

      if (!keyType) {
        this.hostKeyFailures.set(
          key,
          `Host key of ${target} could not be parsed (${fingerprint})`,
        );
        return false;
      }

      const keyBase64 = hostKey.toString("base64");
      const verdict = verifyHostKey(
        loadKnownHosts(files),
        knownHostsCandidates(host, port, aliases),
        keyType,
        keyBase64,
      );

      if (verdict.status === "match") {
        return true;
      }

      if (verdict.status === "unknown" && mode === "accept-new") {
        try {
          appendKnownHost(files[0], host, port, keyType, keyBase64);
          Logger.log(
            `[${key}] Recorded new host key for ${target} in ${files[0]}: ${keyType} ${fingerprint}`,
            "info",
          );
          return true;
        } catch (error) {
          this.hostKeyFailures.set(
            key,
            `Failed to record the host key of ${target} in ${files[0]}: ${
              (error as Error).message
            }`,
          );
          return false;
        }
      }

      if (verdict.status === "revoked") {
        this.hostKeyFailures.set(
          key,
          `Host key of ${target} is marked @revoked in known_hosts (${keyType} ${fingerprint})`,
        );
        return false;
      }

      if (verdict.status === "mismatch") {
        this.hostKeyFailures.set(
          key,
          `HOST KEY MISMATCH for ${target}: the server offered ${keyType} ${fingerprint}, known_hosts has a different key (${verdict.knownKeyTypes.join(
            ", ",
          )}). Refusing to connect. Either the host was rebuilt, or someone is between you and it.`,
        );
        return false;
      }

      this.hostKeyFailures.set(
        key,
        `Host key of ${target} is not in known_hosts (${files.join(
          ", ",
        )}): ${keyType} ${fingerprint}. Verify that fingerprint, add the host to known_hosts, or start the server with --host-key-checking accept-new.`,
      );
      return false;
    };
  }

  private hostKeyError(key: string): ToolError | undefined {
    const message = this.hostKeyFailures.get(key);
    if (!message) {
      return undefined;
    }

    this.hostKeyFailures.delete(key);
    this.audit.record({
      event: "host-key",
      result: "blocked",
      connection: key,
      code: "SSH_HOST_KEY_REJECTED",
      reason: message,
    });
    return new ToolError("SSH_HOST_KEY_REJECTED", message, false);
  }

  /**
   * Walk the ProxyJump chain and return the channel that reaches the target.
   *
   * Each hop is connected through the channel opened by the previous one,
   * which is what `ssh -J bastion,gateway host` does, and lets a host that is
   * only reachable behind a bastion be named by its SSH config alias alone.
   */
  private async createJumpSocket(key: string, config: SSHConfig): Promise<Duplex> {
    const hops = resolveJumpChain(
      config.proxyJump as string,
      config.sshConfigFile,
    );

    if (hops.length === 0) {
      throw new ToolError(
        "SSH_CONNECTION_FAILED",
        `proxyJump for [${key}] resolved to an empty chain: ${config.proxyJump}`,
        false,
      );
    }

    this.closeJumpClients(key);
    const clients: Client[] = [];
    let sock: Duplex | undefined;

    try {
      for (let index = 0; index < hops.length; index++) {
        const hop = hops[index];
        const nextHop = hops[index + 1];
        const target = nextHop
          ? { host: nextHop.host, port: nextHop.port }
          : { host: config.host, port: config.port };

        const hopClient = this.createClient();
        await this.connectJumpClient(hopClient, key, hop, config, sock);
        clients.push(hopClient);

        Logger.log(
          `[${key}] Jump hop ${index + 1}/${hops.length} ready: ${hop.host}:${hop.port} -> ${target.host}:${target.port}`,
          "info",
        );

        sock = await new Promise<Duplex>((resolve, reject) => {
          hopClient.forwardOut(
            "127.0.0.1",
            0,
            target.host,
            target.port,
            (err, stream) => (err ? reject(err) : resolve(stream as Duplex)),
          );
        });
      }

      this.jumpClients.set(key, clients);
      return sock as Duplex;
    } catch (error) {
      for (const client of clients.reverse()) {
        try {
          client.end();
        } catch {
          // Ignore cleanup errors while unwinding a failed jump chain.
        }
      }
      throw new ToolError(
        "SSH_CONNECTION_FAILED",
        `Failed to reach [${key}] through proxyJump '${config.proxyJump}': ${
          (error as Error).message
        }`,
        true,
      );
    }
  }

  private connectJumpClient(
    client: Client,
    key: string,
    hop: SshHopTarget,
    config: SSHConfig,
    sock?: Duplex,
  ): Promise<void> {
    const hopConfig: Record<string, unknown> = {
      host: hop.host,
      port: hop.port,
      username: hop.username || config.username,
      algorithms: this.buildAlgorithms(config),
      readyTimeout: this.getConnectionTimeoutMs(config),
      timeout: this.getConnectionTimeoutMs(config),
      keepaliveInterval:
        config.keepaliveIntervalMs || DEFAULT_KEEPALIVE_INTERVAL_MS,
      keepaliveCountMax:
        config.keepaliveCountMax || DEFAULT_KEEPALIVE_COUNT_MAX,
    };

    if (sock) {
      hopConfig.sock = sock;
    }

    if ((config.hostKeyChecking || "strict") !== "off") {
      hopConfig.hostVerifier = this.createHostVerifier(
        key,
        config,
        hop.host,
        hop.port,
        hop.alias && hop.alias !== hop.host ? [hop.alias] : [],
      );
    }

    const identityFile = hop.identityFile || config.privateKey;
    if (identityFile) {
      try {
        hopConfig.privateKey = fs.readFileSync(identityFile, "utf8");
        if (config.passphrase) {
          hopConfig.passphrase = config.passphrase;
        }
      } catch (error) {
        throw new ToolError(
          "LOCAL_FILE_READ_FAILED",
          `Failed to read jump host key ${identityFile} for [${key}]: ${
            (error as Error).message
          }`,
          false,
        );
      }
    }

    const agent = config.agent || process.env.SSH_AUTH_SOCK;
    if (agent) {
      hopConfig.agent = agent;
    }

    if (!hopConfig.privateKey && !hopConfig.agent) {
      throw new ToolError(
        "SSH_AUTHENTICATION_MISSING",
        `No key or agent available for jump host ${hop.host} of [${key}]`,
        false,
      );
    }

    return new Promise<void>((resolve, reject) => {
      let settled = false;

      client.on("error", (error: Error) => {
        if (settled) {
          Logger.log(
            `[${key}] Jump host ${hop.host} error: ${error.message}`,
            "error",
          );
          return;
        }
        settled = true;
        reject(this.hostKeyError(key) || error);
      });

      client.on("close", () => {
        if (!settled) {
          settled = true;
          reject(
            this.hostKeyError(key) ||
              new Error(`Jump host ${hop.host} closed the connection`),
          );
        }
      });

      client.once("ready", () => {
        settled = true;
        resolve();
      });

      client.connect(hopConfig);
    });
  }

  private async buildClientConfig(
    key: string,
    config: SSHConfig,
  ): Promise<Record<string, unknown>> {
    const sshConfig: Record<string, unknown> = {
      host: config.host,
      port: config.port,
      username: config.username,
      readyTimeout: this.getConnectionTimeoutMs(config),
      timeout: this.getConnectionTimeoutMs(config),
      keepaliveInterval:
        config.keepaliveIntervalMs || DEFAULT_KEEPALIVE_INTERVAL_MS,
      keepaliveCountMax:
        config.keepaliveCountMax || DEFAULT_KEEPALIVE_COUNT_MAX,
    };
    sshConfig.algorithms = this.buildAlgorithms(config);

    if ((config.hostKeyChecking || "strict") !== "off") {
      sshConfig.hostVerifier = this.createHostVerifier(
        key,
        config,
        config.host,
        config.port,
        config.name && config.name !== config.host ? [config.name] : [],
      );
    }

    if (config.proxy && config.socksProxy) {
      throw new ToolError(
        "SSH_CONNECTION_FAILED",
        `Proxy configuration for [${key}] cannot use both 'proxy' and 'socksProxy'`,
        false,
      );
    }

    const proxyValue = config.proxy || config.socksProxy;
    if (proxyValue) {
      try {
        const proxyUrl = new URL(proxyValue);
        if (
          config.socksProxy &&
          proxyUrl.protocol !== "socks:" &&
          proxyUrl.protocol !== "socks5:"
        ) {
          throw new Error(
            "The legacy 'socksProxy' option only supports socks:// or socks5:// URLs; use 'proxy' for HTTP or HTTPS proxies",
          );
        }
        Logger.log(
          `Using proxy for [${key}]: ${redactProxyUrl(proxyUrl)}`,
          "info",
        );
        sshConfig.sock = await this.createProxySocket(proxyUrl, config);
        Logger.log(
          `Proxy socket ready for [${key}] to ${config.host}:${config.port}`,
          "info",
        );
      } catch (error) {
        throw new ToolError(
          "SSH_CONNECTION_FAILED",
          `Failed to create proxy connection for [${key}]: ${
            (error as Error).message
          }`,
          true,
        );
      }
    }

    if (config.proxyJump) {
      if (sshConfig.sock) {
        throw new ToolError(
          "SSH_CONNECTION_FAILED",
          `Configuration for [${key}] cannot use both a proxy and proxyJump`,
          false,
        );
      }
      sshConfig.sock = await this.createJumpSocket(key, config);
    }

    // Enable keyboard-interactive authentication for 2FA/MFA
    if (config.tryKeyboard) {
      sshConfig.tryKeyboard = true;

      // Build ordered preference of methods this connection supports.
      const authMethods: SshAuthMethod[] = [];
      if (config.privateKey) {
        authMethods.push("publickey");
      }
      if (config.agent) {
        authMethods.push("agent");
      }
      if (config.password) {
        authMethods.push("password");
      }
      authMethods.push("keyboard-interactive");

      const triedMethods: SshAuthMethod[] = [];
      const maxAuthAttempts = authMethods.length;

      sshConfig.authHandler = (
        methodsLeft: string[] | null,
        partialSuccess: boolean | null,
        callback: (nextAuth: SshAuthMethod | false) => void,
      ) => {
        // Prevent infinite retry loops.
        if (triedMethods.length >= maxAuthAttempts) {
          Logger.log(
            `[${key}] Authentication failed after trying [${triedMethods.join(", ")}]`,
            "error",
          );
          return callback(false);
        }

        // Pick the next preferred method that hasn't been attempted yet
        // (and is still allowed by the server if methodsLeft is provided).
        const candidates =
          methodsLeft !== null
            ? authMethods.filter((m) =>
                isAuthMethodAllowedByServer(m, methodsLeft),
              )
            : authMethods;

        const nextMethod = candidates.find(
          (m) => !triedMethods.includes(m),
        );

        if (!nextMethod) {
          Logger.log(
            `[${key}] All supported auth methods exhausted`,
            "error",
          );
          return callback(false);
        }

        triedMethods.push(nextMethod);
        Logger.log(
          `[${key}] Trying auth method: ${nextMethod} (${triedMethods.length}/${maxAuthAttempts})`,
          "info",
        );
        return callback(nextMethod);
      };

      // Handle keyboard-interactive prompts (for 2FA codes)
      sshConfig.keyboard = (
        name: string,
        instructions: string,
        instructionsLang: string,
        prompts: Array<{ prompt: string; echo: boolean }>,
        finish: (responses: string[]) => void,
      ) => {
        Logger.log(
          `[${key}] Keyboard-interactive authentication requested`,
          "info",
        );
        Logger.log(`[${key}] Name: ${name}`, "debug");
        Logger.log(`[${key}] Instructions: ${instructions}`, "debug");
        Logger.log(`[${key}] Prompts: ${JSON.stringify(prompts)}`, "debug");

        const otpCode = process.env.SSH_MCP_2FA_CODE;
        const responses: string[] = [];
        for (const prompt of prompts) {
          if (config.password && isPasswordPrompt(prompt.prompt)) {
            // For password prompts, use the configured password
            responses.push(config.password);
            Logger.log(
              `[${key}] Responding to password prompt: ${prompt.prompt}`,
              "debug",
            );
          } else if (otpCode) {
            // For 2FA/verification code prompts, use SSH_MCP_2FA_CODE if provided
            responses.push(otpCode);
            Logger.log(
              `[${key}] Responding to non-password prompt with SSH_MCP_2FA_CODE: ${prompt.prompt}`,
              "info",
            );
          } else if (config.password && prompts.length === 1 && !prompt.echo) {
            // Single non-echoing prompt without "password" label:
            // treat as password prompt (common on embedded devices)
            responses.push(config.password);
            Logger.log(
              `[${key}] Responding to single non-echo prompt (assumed password): ${prompt.prompt}`,
              "debug",
            );
          } else {
            // No code available — empty response will fail the auth attempt;
            // set SSH_MCP_2FA_CODE before connecting to enable 2FA/MFA.
            responses.push("");
            Logger.log(
              `[${key}] Empty response for prompt (set SSH_MCP_2FA_CODE to satisfy 2FA): ${prompt.prompt}`,
              "info",
            );
          }
        }

        finish(responses);
      };
    }

    if (config.agent) {
      sshConfig.agent = config.agent;
      Logger.log(
        `Using SSH agent authentication for [${key}]: ${config.agent}`,
        "info",
      );
      if (!config.tryKeyboard) {
        return sshConfig;
      }
    }

    if (config.privateKey) {
      try {
        sshConfig.privateKey = fs.readFileSync(config.privateKey, "utf8");
        if (config.passphrase) {
          sshConfig.passphrase = config.passphrase;
        }
        Logger.log(
          `Using SSH private key authentication for [${key}]`,
          "info",
        );
        if (!config.tryKeyboard) {
          return sshConfig;
        }
      } catch (error) {
        throw new ToolError(
          "LOCAL_FILE_READ_FAILED",
          `Failed to read private key file for [${key}]: ${
            (error as Error).message
          }`,
          false,
        );
      }
    }

    if (config.password) {
      sshConfig.password = config.password;
      Logger.log(`Using password authentication for [${key}]`, "info");
      if (!config.tryKeyboard) {
        return sshConfig;
      }
    }

    if (!config.agent && !config.privateKey && !config.password && !config.tryKeyboard) {
      throw new ToolError(
        "SSH_AUTHENTICATION_MISSING",
        `No valid authentication method provided for [${key}] (agent, password, private key, or tryKeyboard)`,
        false,
      );
    }

    return sshConfig;
  }

  private scheduleStatusCollection(key: string): void {
    const existingStatusCollection = this.pendingStatusCollections.get(key);
    if (existingStatusCollection) {
      clearTimeout(existingStatusCollection);
    }

    const timeoutId = setTimeout(() => {
      this.pendingStatusCollections.delete(key);
      void this.collectStatusForConnection(key);
    }, 1000);

    this.pendingStatusCollections.set(key, timeoutId);
  }

  private async collectStatusForConnection(key: string): Promise<void> {
    try {
      const status = await collectSystemStatus(
        (command, connectionName) =>
          this.runCommandInternal(command, undefined, connectionName, {
            prevalidatedInternalCommand: true,
          }),
        key,
        (command, connectionName) =>
          this.validateCommand(command, connectionName).isAllowed,
      );
      this.statusCache.set(key, status);
      Logger.log(`System status collected for [${key}]`, "info");
    } catch (error) {
      Logger.log(
        `Failed to collect system status for [${key}]: ${(error as Error).message}`,
        "error",
      );
      this.statusCache.set(key, {
        reachable: true,
        lastUpdated: new Date().toISOString(),
      });
    }
  }

  private compilePatterns(
    patterns: string[] | undefined,
    connectionName: string,
    kind: "whitelist" | "blacklist",
  ): RegExp[] {
    if (!patterns || patterns.length === 0) {
      return [];
    }

    return patterns.map((pattern) => {
      try {
        return new RegExp(pattern);
      } catch (error) {
        throw new Error(
          `Invalid ${kind} pattern for '${connectionName}': ${pattern} (${(error as Error).message})`,
        );
      }
    });
  }

  private validateCommand(
    command: string,
    name?: string,
  ): { isAllowed: boolean; reason?: string } {
    const key = name || this.defaultName;

    // A connection resolved from the SSH config gets its guards compiled when
    // the configuration is built, so the alias has to be resolved before the
    // first command is judged. Otherwise that command would see no profile.
    if (!this.guards.has(key) && this.dynamicHosts.enabled) {
      this.getConfig(key);
    }

    const whitelistRegexes = this.commandWhitelistRegexes.get(key) || [];
    if (whitelistRegexes.length > 0) {
      const matchesWhitelist = whitelistRegexes.some((regex) =>
        regex.test(command),
      );
      if (!matchesWhitelist) {
        return {
          isAllowed: false,
          reason: "Command not in whitelist, execution forbidden",
        };
      }
    }

    const blacklistRegexes = this.commandBlacklistRegexes.get(key) || [];
    if (blacklistRegexes.length > 0) {
      const matchesBlacklist = blacklistRegexes.some((regex) =>
        regex.test(command),
      );
      if (matchesBlacklist) {
        return {
          isAllowed: false,
          reason: "Command matches blacklist, execution forbidden",
        };
      }
    }

    const guard = this.guards.get(key);
    if (guard) {
      const verdict = evaluateGuard(guard, command);
      if (!verdict.allowed) {
        return { isAllowed: false, reason: verdict.reason };
      }
    }

    return {
      isAllowed: true,
    };
  }

  private formatCommandFailure(
    stdout: string,
    stderr: string,
    exitCode?: number,
    exitSignal?: string,
  ): string {
    const outputSections: string[] = [];

    if (stdout) {
      outputSections.push(stdout);
    }

    if (stderr) {
      outputSections.push(`[stderr]\n${stderr}`);
    }

    if (exitCode !== undefined) {
      outputSections.push(`[exit code] ${exitCode}`);
    }

    if (exitSignal) {
      outputSections.push(`[signal] ${exitSignal}`);
    }

    return outputSections.join("\n");
  }

  /**
   * Format the output of a command that finished successfully.
   *
   * stderr is kept instead of being dropped: with `pty: false` a successful
   * command's stderr is delivered on a separate channel, and discarding it
   * silently loses warnings and progress output written there by tools such as
   * git, docker and npm. With the default `pty: true` the remote end merges
   * stderr into stdout, so `stderr` is empty here and the output is unchanged.
   */
  private formatCommandSuccess(stdout: string, stderr: string): string {
    if (!stderr) {
      return stdout;
    }

    return [stdout, `[stderr]\n${stderr}`].filter(Boolean).join("\n");
  }

  private async runCommandInternal(
    cmdString: string,
    directory?: string,
    name?: string,
    options: RunCommandOptions = {},
  ): Promise<string> {
    if (!options.prevalidatedInternalCommand) {
      const validationResult = this.validateCommand(cmdString, name);
      if (!validationResult.isAllowed) {
        throw new ToolError(
          "COMMAND_VALIDATION_FAILED",
          `Command validation failed: ${validationResult.reason}`,
          false,
        );
      }
    }

    const key = name || this.defaultName;
    const config = this.getConfig(name);
    const transportMode = this.getTransportMode(config);
    const sudoPassword = options.sudo
      ? this.resolveSudoPassword(config, key)
      : undefined;
    const timeout =
      options.timeout ??
      (transportMode === "shell"
        ? this.getShellCommandTimeoutMs(config)
        : this.getCommandTimeoutMs(config));
    const connectionTimeoutMs = this.getConnectionTimeoutMs(config);
    const client = await this.withTimeout(
      this.ensureConnected(name),
      connectionTimeoutMs,
      () => this.invalidateConnection(key),
      `SSH connection [${key}] timed out after ${connectionTimeoutMs}ms`,
    );

    if (transportMode === "shell") {
      return this.runShellCommand(
        cmdString,
        directory,
        name,
        timeout,
        sudoPassword,
      );
    }

    return this.runExecCommand(
      client,
      config,
      cmdString,
      directory,
      timeout,
      key,
      sudoPassword,
    );
  }

  private async runExecCommand(
    client: Client,
    config: SSHConfig,
    cmdString: string,
    directory: string | undefined,
    timeout: number,
    key: string,
    sudoPassword?: string,
  ): Promise<string> {
    try {
      const output = await this.execCommandChannel(
        client,
        config,
        cmdString,
        directory,
        timeout,
        key,
        sudoPassword,
      );
      return redactSecret(output, sudoPassword);
    } catch (error) {
      throw redactToolError(error, sudoPassword);
    }
  }

  private execCommandChannel(
    client: Client,
    config: SSHConfig,
    cmdString: string,
    directory: string | undefined,
    timeout: number,
    key: string,
    sudoPassword?: string,
  ): Promise<string> {
    let commandToRun = directory
      ? `cd -- ${shellQuote(directory)} && ${cmdString}`
      : cmdString;

    if (sudoPassword) {
      commandToRun = this.buildSudoCommand(config, commandToRun);
    }

    if (config.commandTemplate) {
      commandToRun = applyCommandTemplate(config.commandTemplate, commandToRun);
    }

    const maxOutputBytes = this.getMaxOutputBytes(config);

    return new Promise<string>((resolve, reject) => {
      let openTimeoutId: NodeJS.Timeout | undefined;
      let commandTimeoutId: NodeJS.Timeout | undefined;
      let settled = false;

      const cleanup = () => {
        if (openTimeoutId) {
          clearTimeout(openTimeoutId);
        }
        if (commandTimeoutId) {
          clearTimeout(commandTimeoutId);
        }
      };

      client.exec(
        commandToRun,
        // A pty echoes back what is written to it, so sudo runs without one:
        // `sudo -S` then reads the password from stdin and nothing echoes it.
        { pty: sudoPassword ? false : config.pty !== undefined ? config.pty : true },
        (err: Error | undefined, stream: ClientChannel) => {
          if (openTimeoutId) {
            clearTimeout(openTimeoutId);
            openTimeoutId = undefined;
          }

          if (settled) {
            try {
              stream?.close();
            } catch {
              // Ignore late stream cleanup errors after timeout.
            }
            return;
          }

          if (err) {
            cleanup();
            settled = true;
            reject(
              new ToolError(
                "COMMAND_EXECUTION_ERROR",
                `Command execution error: ${err.message}`,
                true,
              ),
            );
            return;
          }

          if (sudoPassword) {
            stream.write(`${sudoPassword}\n`);
          }

          let data = "";
          let errorData = "";
          let exitCode: number | undefined;
          let exitSignal: string | undefined;
          let capturedBytes = 0;
          // Decoding each chunk on its own corrupts any multi-byte character
          // that happens to be split across a chunk boundary.
          const stdoutDecoder = new StringDecoder("utf8");
          const stderrDecoder = new StringDecoder("utf8");

          // Without a cap a single command (`cat` on a huge file, an unbounded
          // `journalctl`, ...) can buffer unbounded output in memory until the
          // command timeout fires. Stop capturing and close the channel instead.
          const appendChunk = (chunk: Buffer, isStderr: boolean) => {
            if (settled) {
              return;
            }

            if (
              maxOutputBytes > 0 &&
              capturedBytes + chunk.length > maxOutputBytes
            ) {
              const remaining = maxOutputBytes - capturedBytes;
              if (remaining > 0) {
                const partial = chunk.subarray(0, remaining);
                if (isStderr) {
                  errorData += stderrDecoder.write(partial);
                } else {
                  data += stdoutDecoder.write(partial);
                }
              }
              capturedBytes = maxOutputBytes;
              cleanup();
              settled = true;
              try {
                stream.close();
              } catch {
                // Ignore close errors while aborting an oversized command.
              }
              const stdout = data.trimEnd();
              const stderr = errorData.trimEnd();
              reject(
                new ToolError(
                  "OUTPUT_LIMIT_EXCEEDED",
                  [
                    this.formatCommandSuccess(stdout, stderr),
                    `[truncated] Output exceeded maxOutputBytes=${maxOutputBytes}; the command was aborted.`,
                  ]
                    .filter(Boolean)
                    .join("\n"),
                  false,
                ),
              );
              return;
            }

            capturedBytes += chunk.length;
            if (isStderr) {
              errorData += stderrDecoder.write(chunk);
            } else {
              data += stdoutDecoder.write(chunk);
            }
          };

          stream.on("data", (chunk: Buffer) => appendChunk(chunk, false));
          stream.stderr.on("data", (chunk: Buffer) => appendChunk(chunk, true));

          stream.on(
            "exit",
            (code: number | undefined, signal: string | undefined) => {
              exitCode = code;
              exitSignal = signal;
            },
          );

          stream.on("close", (code?: number, signal?: string) => {
            cleanup();
            if (settled) {
              return;
            }
            settled = true;

            if (exitCode === undefined) {
              exitCode = code;
            }

            if (!exitSignal && signal) {
              exitSignal = signal;
            }

            // Flush any trailing incomplete multi-byte sequence.
            const stdout = (data + stdoutDecoder.end()).trimEnd();
            const stderr = (errorData + stderrDecoder.end()).trimEnd();

            const hasNonZeroExitCode =
              exitCode !== undefined && exitCode !== 0;
            const hasExitSignal =
              exitSignal !== undefined && exitSignal !== "";

            if (hasNonZeroExitCode || hasExitSignal) {
              reject(
                new ToolError(
                  "COMMAND_EXECUTION_ERROR",
                  this.formatCommandFailure(
                    stdout,
                    stderr,
                    exitCode,
                    exitSignal,
                  ) ||
                    (hasExitSignal
                      ? `Command terminated by signal ${exitSignal}${
                          exitCode !== undefined ? ` (exit code ${exitCode})` : ""
                        }`
                      : `Command failed with exit code ${exitCode}`),
                  false,
                ),
              );
              return;
            }

            resolve(this.formatCommandSuccess(stdout, stderr));
          });

          stream.on("error", (streamError: Error) => {
            cleanup();
            settled = true;
            reject(
              new ToolError(
                "COMMAND_EXECUTION_ERROR",
                `Stream error: ${streamError.message}`,
                true,
              ),
            );
          });

          commandTimeoutId = setTimeout(() => {
            try {
              stream.close();
            } catch {
              // Ignore stream close errors during timeout handling.
            }

            if (!settled) {
              settled = true;
              const stdout = data.trimEnd();
              const stderr = errorData.trimEnd();
              reject(
                new ToolError(
                  "COMMAND_TIMEOUT",
                  [
                    this.formatCommandFailure(stdout, stderr),
                    `[timeout] Command timed out after ${timeout}ms`,
                  ]
                    .filter(Boolean)
                    .join("\n"),
                  true,
                ),
              );
            }
          }, timeout);
        },
      );

      openTimeoutId = setTimeout(() => {
        if (!settled) {
          settled = true;
          this.invalidateConnection(key);
          reject(
            new ToolError(
              "COMMAND_TIMEOUT",
              `[timeout] Command channel did not open within ${timeout}ms`,
              true,
            ),
          );
        }
      }, timeout);
    });
  }

  private async initializeShellSession(
    client: Client,
    key: string,
    config: SSHConfig,
  ): Promise<void> {
    const stream = await new Promise<ClientChannel>((resolve, reject) => {
      client.shell(
        { term: "xterm" },
        (err: Error | undefined, channel: ClientChannel) => {
          if (err) {
            reject(
              new ToolError(
                "SSH_CONNECTION_FAILED",
                `Failed to initialize shell transport for [${key}]: ${err.message}`,
                true,
              ),
            );
            return;
          }
          resolve(channel);
        },
      );
    });

    this.shellStreams.set(key, stream);
    this.shellReady.set(key, false);
    this.shellQueues.set(key, Promise.resolve());
    this.shellBuffers.set(key, "");
    this.shellDecoders.set(key, new StringDecoder("utf8"));

    const readyId = this.generateMarkerId("ready");
    const readyMarker = `__MCP_READY__${readyId}__`;

    try {
      await this.waitForShellReady(
        key,
        stream,
        readyMarker,
        this.getShellReadyTimeoutMs(config),
      );
      this.configureShellSession(stream);
      this.shellReady.set(key, true);
      this.attachShellLifecycleListeners(key, stream);
    } catch (error) {
      this.cleanupShellState(key, true);
      throw new ToolError(
        "SSH_CONNECTION_FAILED",
        `Shell transport initialization failed for [${key}]: ${
          (error as Error).message
        }`,
        true,
      );
    }
  }

  private waitForShellReady(
    key: string,
    stream: ClientChannel,
    readyMarker: string,
    timeout: number,
  ): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      let settled = false;
      let timeoutId: NodeJS.Timeout;
      let probeIntervalId: NodeJS.Timeout;
      const payload = `printf '${readyMarker}\\n'\n`;

      const cleanup = () => {
        if (timeoutId) {
          clearTimeout(timeoutId);
        }
        if (probeIntervalId) {
          clearInterval(probeIntervalId);
        }
        stream.off("data", onData);
        stream.off("close", onClose);
        stream.off("error", onError);
      };

      const resolveIfReady = () => {
        const buffer = this.shellBuffers.get(key) || "";
        const markerIndex = buffer.indexOf(readyMarker);
        if (markerIndex === -1) {
          return;
        }

        const lineEndIndex = buffer.indexOf("\n", markerIndex);
        if (lineEndIndex === -1) {
          return;
        }

        if (!settled) {
          settled = true;
          this.shellBuffers.set(key, buffer.slice(lineEndIndex + 1));
          cleanup();
          resolve();
        }
      };

      const onData = (chunk: Buffer) => {
        this.appendShellBuffer(key, chunk);
        resolveIfReady();
      };

      const onClose = () => {
        if (settled) {
          return;
        }
        settled = true;
        cleanup();
        reject(new Error("Shell channel closed before ready probe completed"));
      };

      const onError = (error: Error) => {
        if (settled) {
          return;
        }
        settled = true;
        cleanup();
        reject(error);
      };

      stream.on("data", onData);
      stream.on("close", onClose);
      stream.on("error", onError);

      timeoutId = setTimeout(() => {
        if (settled) {
          return;
        }
        settled = true;
        cleanup();
        reject(
          new Error(`Timed out waiting for shell ready marker after ${timeout}ms`),
        );
      }, timeout);

      stream.write(payload);
      probeIntervalId = setInterval(() => {
        if (!settled) {
          stream.write(payload);
        }
      }, 1000);
      resolveIfReady();
    });
  }

  private attachShellLifecycleListeners(
    key: string,
    stream: ClientChannel,
  ): void {
    const handleUnavailable = (reason: string) => {
      if (this.shellStreams.get(key) !== stream) {
        return;
      }

      Logger.log(`Shell channel [${key}] unavailable: ${reason}`, "error");
      this.invalidateConnection(key);
    };

    stream.on("close", () => handleUnavailable("closed"));
    stream.on("error", (error: Error) =>
      handleUnavailable(`error: ${error.message}`),
    );
  }

  private configureShellSession(stream: ClientChannel): void {
    stream.write("export PS1=''\n");
    stream.write("stty -echo >/dev/null 2>&1 || true\n");
  }

  private async runShellCommand(
    cmdString: string,
    directory: string | undefined,
    name: string | undefined,
    timeout: number,
    sudoPassword?: string,
  ): Promise<string> {
    const key = name || this.defaultName;
    try {
      const output = await this.enqueueShellCommand(key, () =>
        this.executeShellCommand(key, cmdString, directory, timeout, sudoPassword),
      );
      return redactSecret(output, sudoPassword);
    } catch (error) {
      throw redactToolError(error, sudoPassword);
    }
  }

  private enqueueShellCommand<T>(
    key: string,
    task: () => Promise<T>,
  ): Promise<T> {
    const previous = this.shellQueues.get(key) || Promise.resolve();
    const next = previous.catch(() => undefined).then(task);
    this.shellQueues.set(
      key,
      next.then(
        () => undefined,
        () => undefined,
      ),
    );
    return next;
  }

  private executeShellCommand(
    key: string,
    cmdString: string,
    directory: string | undefined,
    timeout: number,
    sudoPassword?: string,
  ): Promise<string> {
    const stream = this.shellStreams.get(key);
    if (!stream || this.shellReady.get(key) !== true) {
      throw new ToolError(
        "SSH_CONNECTION_FAILED",
        `Shell transport for [${key}] is not ready`,
        true,
      );
    }

    const commandId = this.generateMarkerId("command");
    const config = this.getConfig(key);
    const script = this.buildShellCommandScript(
      commandId,
      cmdString,
      directory,
      config,
      sudoPassword,
    );

    const maxOutputBytes = this.getMaxOutputBytes(config);

    return new Promise<string>((resolve, reject) => {
      let settled = false;
      let timeoutId: NodeJS.Timeout;
      const scanState: ShellScanState = {
        outputStartIndex: -1,
        tail: "",
        // Whatever the previous command left behind cannot hold this command's
        // markers, so the scan starts past it.
        tailStart: (this.shellBuffers.get(key) || "").length,
        countedOutputEndIndex: -1,
        capturedOutputBytes: 0,
      };

      const cleanup = () => {
        if (timeoutId) {
          clearTimeout(timeoutId);
        }
        stream.off("data", onData);
        stream.off("close", onClose);
        stream.off("error", onError);
      };

      const finish = (error?: ToolError, output?: string) => {
        if (settled) {
          return;
        }
        settled = true;
        cleanup();

        if (error) {
          reject(error);
          return;
        }

        resolve(output || "");
      };

      const resolveIfComplete = () => {
        const matched = this.extractShellCommandResult(
          key,
          commandId,
          scanState,
        );

        if (
          maxOutputBytes > 0 &&
          scanState.capturedOutputBytes > maxOutputBytes
        ) {
          // The shell channel is shared by every command on this connection,
          // so it cannot simply be closed like an exec channel: the command
          // would keep writing into the buffer. Drop the connection instead.
          this.invalidateConnection(key);
          finish(
            new ToolError(
              "OUTPUT_LIMIT_EXCEEDED",
              `[truncated] Output exceeded maxOutputBytes=${maxOutputBytes}; the command was aborted.`,
              false,
            ),
          );
          return;
        }

        if (!matched) {
          return;
        }

        this.shellBuffers.set(key, matched.remainder);
        const output = this.stripLeadingBeginMarker(
          this.cleanShellOutput(matched.output),
          commandId,
        ).trimEnd();

        if (matched.exitCode !== 0) {
          finish(
            new ToolError(
              "COMMAND_EXECUTION_ERROR",
              this.formatCommandFailure(output, "", matched.exitCode) ||
                `Command failed with exit code ${matched.exitCode}`,
              false,
            ),
          );
          return;
        }

        finish(undefined, output);
      };

      const onData = (chunk: Buffer) => {
        scanState.tail += this.appendShellBuffer(key, chunk);
        resolveIfComplete();
      };

      const onClose = () => {
        finish(
          new ToolError(
            "COMMAND_EXECUTION_ERROR",
            "Shell channel closed during command execution",
            true,
          ),
        );
      };

      const onError = (error: Error) => {
        finish(
          new ToolError(
            "COMMAND_EXECUTION_ERROR",
            `Shell channel error during command execution: ${error.message}`,
            true,
          ),
        );
      };

      stream.on("data", onData);
      stream.on("close", onClose);
      stream.on("error", onError);

      timeoutId = setTimeout(() => {
        this.invalidateConnection(key);
        finish(
          new ToolError(
            "COMMAND_TIMEOUT",
            `[timeout] Command timed out after ${timeout}ms`,
            true,
          ),
        );
      }, timeout);

      stream.write(script);
      resolveIfComplete();
    });
  }

  private buildShellCommandScript(
    commandId: string,
    cmdString: string,
    directory: string | undefined,
    config: SSHConfig,
    sudoPassword?: string,
  ): string {
    const beginMarker = `__MCP_BEGIN__${commandId}__`;
    const endMarker = `__MCP_END__${commandId}__RC__`;
    let commandBody = directory
      ? `cd -- ${shellQuote(directory)} && { ${cmdString}; }`
      : `{ ${cmdString}; }`;

    if (sudoPassword) {
      commandBody = this.buildSudoCommand(config, commandBody);
    }

    if (config.commandTemplate) {
      commandBody = applyCommandTemplate(config.commandTemplate, commandBody);
    }

    return [
      `printf '${beginMarker}\\n'`,
      commandBody,
      // `sudo -S` reads the password from the same stdin the shell reads this
      // script from, so the line has to follow the command directly. `-k`
      // forces the prompt, which is what guarantees the line is consumed here
      // instead of being executed as the next command.
      ...(sudoPassword ? [sudoPassword] : []),
      "__mcp_rc=$?",
      `printf '\\n${endMarker}%s__\\n' "$__mcp_rc"`,
      "",
    ].join("\n");
  }

  /**
   * Drop the part of the tail that can no longer start a marker: a marker only
   * straddles the boundary of the chunk that just arrived, so keeping the last
   * `markerLength - 1` characters is enough.
   */
  private trimShellScanTail(
    scanState: ShellScanState,
    markerLength: number,
  ): void {
    this.advanceShellScanTail(
      scanState,
      scanState.tail.length - Math.min(scanState.tail.length, markerLength - 1),
    );
  }

  private advanceShellScanTail(
    scanState: ShellScanState,
    offset: number,
  ): void {
    if (offset <= 0) {
      return;
    }
    scanState.tailStart += offset;
    scanState.tail = scanState.tail.slice(offset);
  }

  /**
   * Locate a finished command, scanning only the freshly arrived tail. The
   * accumulated buffer is read once, after the whole end marker is in hand.
   */
  private extractShellCommandResult(
    key: string,
    commandId: string,
    scanState: ShellScanState,
  ): ShellCommandMatch | null {
    if (scanState.outputStartIndex === -1) {
      const beginMarker = `__MCP_BEGIN__${commandId}__`;
      const beginIndex = scanState.tail.indexOf(beginMarker);
      if (beginIndex === -1) {
        this.trimShellScanTail(scanState, beginMarker.length);
        return null;
      }

      const beginLineEndIndex = scanState.tail.indexOf("\n", beginIndex);
      if (beginLineEndIndex === -1) {
        this.advanceShellScanTail(scanState, beginIndex);
        return null;
      }

      this.advanceShellScanTail(scanState, beginLineEndIndex + 1);
      scanState.outputStartIndex = scanState.tailStart;
      scanState.countedOutputEndIndex = scanState.tailStart;
    }

    // Search the fixed prefix rather than the whole pattern: its length is
    // known, which is what makes the retained overlap provably sufficient. The
    // exit code is then parsed from the short slice that follows it.
    const endPrefix = `__MCP_END__${commandId}__RC__`;
    const endIndex = scanState.tail.indexOf(endPrefix);
    if (endIndex === -1) {
      // Keep the marker overlap plus CRLF immediately before it. The command
      // wrapper emits that newline as framing, so it must not count against the
      // user's output limit.
      this.trimShellScanTail(scanState, endPrefix.length + 2);
      this.countShellOutputThrough(key, scanState, scanState.tailStart);
      return null;
    }

    const absoluteEndIndex = scanState.tailStart + endIndex;
    const buffer = this.shellBuffers.get(key) || "";
    let outputEndIndex = absoluteEndIndex;
    if (buffer[outputEndIndex - 1] === "\n") {
      outputEndIndex -= 1;
      if (buffer[outputEndIndex - 1] === "\r") {
        outputEndIndex -= 1;
      }
    }
    this.countShellOutputThrough(key, scanState, outputEndIndex);

    const exitCodeStart = endIndex + endPrefix.length;
    const matched = SHELL_EXIT_CODE_PATTERN.exec(
      scanState.tail.slice(
        exitCodeStart,
        exitCodeStart + SHELL_EXIT_CODE_MAX_LENGTH,
      ),
    );
    if (!matched) {
      // The prefix arrived but the exit code has not; resume from here.
      this.advanceShellScanTail(scanState, endIndex);
      return null;
    }

    const consumedEndIndex =
      absoluteEndIndex + endPrefix.length + matched[0].length;

    return {
      output: buffer.slice(scanState.outputStartIndex, absoluteEndIndex),
      exitCode: Number.parseInt(matched[1], 10),
      remainder: buffer.slice(consumedEndIndex),
    };
  }

  private countShellOutputThrough(
    key: string,
    scanState: ShellScanState,
    endIndex: number,
  ): void {
    if (
      scanState.outputStartIndex === -1 ||
      endIndex <= scanState.countedOutputEndIndex
    ) {
      return;
    }

    const buffer = this.shellBuffers.get(key) || "";
    scanState.capturedOutputBytes += Buffer.byteLength(
      buffer.slice(scanState.countedOutputEndIndex, endIndex),
      "utf8",
    );
    scanState.countedOutputEndIndex = endIndex;
  }

  /** Appends the decoded chunk and returns just that text. */
  private appendShellBuffer(key: string, chunk: Buffer): string {
    let decoder = this.shellDecoders.get(key);
    if (!decoder) {
      decoder = new StringDecoder("utf8");
      this.shellDecoders.set(key, decoder);
    }

    // Concatenation alone stays cheap; it is reading the result that forces the
    // rope to flatten, so nothing here may inspect the accumulated buffer.
    const text = decoder.write(chunk);
    const current = this.shellBuffers.get(key) || "";
    this.shellBuffers.set(key, current + text);
    return text;
  }

  private cleanShellOutput(output: string): string {
    return output
      .replace(ANSI_OSC_PATTERN, "")
      .replace(ANSI_CSI_PATTERN, "")
      .replace(/\r\n/g, "\n")
      .replace(/\r/g, "\n");
  }

  private stripLeadingBeginMarker(output: string, commandId: string): string {
    const beginPrefix = `__MCP_BEGIN__${commandId}__`;
    if (!output.startsWith(beginPrefix)) {
      return output;
    }

    const newlineIndex = output.indexOf("\n");
    if (newlineIndex === -1) {
      return "";
    }

    return output.slice(newlineIndex + 1);
  }

  private generateMarkerId(prefix: string): string {
    // Unpredictable on purpose: the markers delimit command output, and remote
    // output that could guess one could cut its own result short.
    return `${prefix}_${Date.now()}_${randomBytes(6).toString("hex")}`;
  }

  private cleanupShellState(key: string, closeStream: boolean = false): void {
    const stream = this.shellStreams.get(key);
    if (closeStream && stream) {
      try {
        stream.close();
      } catch {
        // Ignore shell close errors during cleanup.
      }
    }

    this.shellStreams.delete(key);
    this.shellReady.delete(key);
    this.shellQueues.delete(key);
    this.shellBuffers.delete(key);
    this.shellDecoders.delete(key);
  }

  private clearConnectionState(key: string): void {
    const pendingStatusCollection = this.pendingStatusCollections.get(key);
    if (pendingStatusCollection) {
      clearTimeout(pendingStatusCollection);
      this.pendingStatusCollections.delete(key);
    }

    this.cleanupShellState(key);
    this.connected.set(key, false);
    this.clients.delete(key);
    this.pendingConnections.delete(key);
    this.closeJumpClients(key);

    for (const listener of this.connectionCloseListeners) {
      try {
        listener(key);
      } catch (error) {
        Logger.log(
          `Connection close listener failed for [${key}]: ${(error as Error).message}`,
          "error",
        );
      }
    }
  }

  private invalidateConnection(key: string): void {
    const client = this.clients.get(key);
    this.clearConnectionState(key);
    if (client) {
      try {
        client.end();
      } catch {
        // Ignore client close errors during invalidation.
      }
    }
  }
}
