import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { SSHConnectionManager } from "../services/ssh-connection-manager.js";
import { CommandLineParser } from "../cli/command-line-parser.js";
import { Logger } from "../utils/logger.js";
import { registerAllTools } from "../tools/index.js";
import { SERVER_CONFIG } from "../config/server.js";
import { TunnelManager } from "../services/tunnel-manager.js";
import type { ParsedArgs, SSHConfig } from "../models/types.js";
import { describeGuard } from "../guards/guard-rules.js";
import { AuditLog } from "../utils/audit-log.js";

const LOOPBACK_ADDRESSES = ["127.0.0.1", "::1", "localhost"];

/**
 * MCP Server class
 */
export class SshMcpServer {
  private server: McpServer;
  private sshManager: SSHConnectionManager;
  private tunnelManager: TunnelManager;
  private shutdownHandlersRegistered = false;
  private shutdownPromise?: Promise<void>;

  constructor() {
    this.server = new McpServer(SERVER_CONFIG);

    this.sshManager = SSHConnectionManager.getInstance();
    this.tunnelManager = TunnelManager.getInstance();
  }

  /**
   * Register tools
   */
  private registerTools(parsedArgs: ParsedArgs): void {
    registerAllTools(this.server, {
      sshConfigHosts: parsedArgs.dynamicHosts.enabled,
      tunnels: parsedArgs.tunnelPolicy.enabled,
      upload: parsedArgs.enableUpload,
    });
  }

  private async shutdown(reason: string, exitCode?: number): Promise<void> {
    if (!this.shutdownPromise) {
      this.shutdownPromise = (async () => {
        Logger.log(`Received ${reason}, shutting down SSH MCP server...`, "info");

        this.tunnelManager.closeAll();
        this.sshManager.disconnect();

        try {
          await this.server.close();
        } catch (error) {
          Logger.log(
            `Failed to close MCP server cleanly: ${(error as Error).message}`,
            "error",
          );
        }
      })();
    }

    await this.shutdownPromise;

    if (exitCode !== undefined) {
      process.exit(exitCode);
    }
  }

  private registerShutdownHandlers(): void {
    if (this.shutdownHandlersRegistered) {
      return;
    }

    const handleSignal = (signal: NodeJS.Signals) => {
      void this.shutdown(signal, 0);
    };

    process.once("SIGINT", handleSignal);
    process.once("SIGTERM", handleSignal);
    process.stdin.resume();
    process.stdin.once("end", () => void this.shutdown("stdin end", 0));
    process.stdin.once("close", () => void this.shutdown("stdin close", 0));

    this.shutdownHandlersRegistered = true;
  }

  /**
   * Run the server
   */
  public async run(): Promise<void> {
    // Initialize SSH configuration
    const parsedArgs = CommandLineParser.parseArgs();
    const audit = AuditLog.getInstance();
    audit.configure(parsedArgs.auditLog);
    audit.setRedactions(
      Array.from(
        new Set(
          [
            ...Object.values(parsedArgs.configs),
            parsedArgs.dynamicHosts.template,
          ]
            .map((config) => config.sudoPasswordEnv || "SSH_MCP_SUDO_PASSWORD")
            .map((variable) => process.env[variable])
            .filter((value): value is string => Boolean(value)),
        ),
      ),
    );
    this.sshManager.setConfig(parsedArgs.configs);
    this.sshManager.setDynamicHosts(parsedArgs.dynamicHosts);
    this.tunnelManager.configure(parsedArgs.tunnelPolicy, (connectionName) =>
      this.sshManager.getConnectedClient(connectionName),
    );
    this.sshManager.onConnectionClosed((key) =>
      this.tunnelManager.closeForConnection(key),
    );
    this.registerShutdownHandlers();

    // Register tools before accepting MCP requests.
    this.registerTools(parsedArgs);

    // Create transport instance and connect.
    const transport = new StdioServerTransport();
    await this.server.connect(transport);

    Logger.log("MCP server connection established");

    if (parsedArgs.dynamicHosts.enabled) {
      const allowPatterns = parsedArgs.dynamicHosts.allowPatterns;
      Logger.log(
        `SSH config hosts enabled (${
          allowPatterns ? `allowed: ${allowPatterns.join(", ")}` : "all aliases"
        }); guards: ${describeGuard(
          this.sshManager.getGuardForTemplate(parsedArgs.dynamicHosts.template),
        )}`,
        "info"
      );
    }

    if (parsedArgs.enableUpload) {
      Logger.log(
        "WARNING: upload is enabled. A file the guards cannot read can be put on the host and executed; keep allowedRemotePaths tight.",
        "info"
      );
    }

    if (parsedArgs.tunnelPolicy.enabled) {
      Logger.log(
        `Tunnels enabled on ${parsedArgs.tunnelPolicy.bindAddress}${
          parsedArgs.tunnelPolicy.allowedPorts
            ? ` (ports: ${parsedArgs.tunnelPolicy.allowedPorts.join(", ")})`
            : ""
        }`,
        "info"
      );

      if (!LOOPBACK_ADDRESSES.includes(parsedArgs.tunnelPolicy.bindAddress)) {
        Logger.log(
          `WARNING: Tunnels bind ${parsedArgs.tunnelPolicy.bindAddress}, which is not loopback. The SOCKS proxy has no authentication, so anyone who reaches that address reaches everything the SSH targets can reach.`,
          "info"
        );
      }
    }

    // Security warning
    const allConfigs: Array<Partial<SSHConfig>> = Object.values(
      parsedArgs.configs,
    );
    if (parsedArgs.dynamicHosts.enabled) {
      allConfigs.push(parsedArgs.dynamicHosts.template);
    }
    if (
      allConfigs.some(
        (c) =>
          (!c.commandWhitelist || c.commandWhitelist.length === 0) &&
          (!c.guardProfile || c.guardProfile === "off")
      )
    ) {
      Logger.log(
        "WARNING: Running without a command whitelist or a guard profile is strongly discouraged. Only the forbidden core is enforced; configure --guards-profile safe or a whitelist to restrict the commands that can be executed.",
        "info"
      );
    }
    if (
      allConfigs.some(
        (c) =>
          (c.transportMode || "exec") === "exec" &&
          (!c.allowedRemotePaths || c.allowedRemotePaths.length === 0)
      )
    ) {
      Logger.log(
        "WARNING: Running without allowedRemotePaths is strongly discouraged. SFTP upload/download can read or write any path on the remote server. Configure allowedRemotePaths to restrict the SFTP surface.",
        "info"
      );
    }

    // Pre-connect to all servers if flag is set
    if (parsedArgs.preConnect) {
      Logger.log("Pre-connecting to all configured SSH servers...", "info");
      void this.sshManager
        .connectAll()
        .then(() => {
          Logger.log("Successfully pre-connected to all SSH servers", "info");
        })
        .catch((error) => {
          Logger.log(
            `Warning: Some SSH connections failed during pre-connect: ${(error as Error).message}`,
            "error"
          );
        });
    }
  }
}
