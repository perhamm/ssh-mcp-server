import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { TunnelManager, TunnelInfo } from "../services/tunnel-manager.js";
import { SSHConnectionManager } from "../services/ssh-connection-manager.js";
import { Logger } from "../utils/logger.js";
import { ToolError, toToolError } from "../utils/tool-error.js";

export function formatTunnel(tunnel: TunnelInfo): string {
  const target =
    tunnel.type === "socks5"
      ? "any host reachable from the server"
      : `${tunnel.remoteHost}:${tunnel.remotePort}`;

  return [
    `[${tunnel.id}] ${tunnel.type} on ${tunnel.bindAddress}:${tunnel.localPort}`,
    `via [${tunnel.connectionName}] to ${target}`,
    `streams active=${tunnel.activeStreams} total=${tunnel.totalStreams} failed=${tunnel.failedStreams}`,
  ].join(" | ");
}

export function formatTunnelList(tunnels: TunnelInfo[]): string {
  if (tunnels.length === 0) {
    return "No open tunnels.";
  }

  return [
    "Open tunnels:",
    ...tunnels.map(formatTunnel),
    "",
    "Raw JSON:",
    JSON.stringify(tunnels),
  ].join("\n");
}

function toolFailure(error: unknown, context: string) {
  const toolError = toToolError(error, "UNKNOWN_ERROR");
  Logger.handleError(toolError, context);
  return {
    content: [
      {
        type: "text" as const,
        text: JSON.stringify(
          {
            code: toolError.code,
            message: toolError.message,
            retriable: toolError.retriable,
          },
          null,
          2,
        ),
      },
    ],
    isError: true,
  };
}

/**
 * Register tunnel tools
 */
export function registerTunnelTools(server: McpServer): void {
  const tunnelManager = TunnelManager.getInstance();

  server.registerTool(
    "open-tunnel",
    {
      description:
        "Open a local listener that forwards traffic through the SSH connection. Use type 'socks5' to get a SOCKS5 proxy (the equivalent of ssh -D) that reaches every host and DNS name the server can reach, or type 'local' to forward one local port to one remote address (the equivalent of ssh -L).",
      inputSchema: {
        type: z
          .enum(["socks5", "local"])
          .describe("socks5 for a SOCKS5 proxy, local for a single port forward"),
        localPort: z
          .number()
          .int()
          .min(0)
          .max(65535)
          .optional()
          .describe("Local port to bind, 0 or omitted lets the OS pick a free port"),
        remoteHost: z
          .string()
          .optional()
          .describe("Target host, required for type 'local'"),
        remotePort: z
          .number()
          .int()
          .min(1)
          .max(65535)
          .optional()
          .describe("Target port, required for type 'local'"),
        connectionName: z
          .string()
          .optional()
          .describe("SSH connection name or SSH config host alias to tunnel through"),
        proxyJump: z
          .string()
          .optional()
          .describe(
            "Comma separated jump hosts to reach this connection through, overriding the chain of the SSH config. Every hop has to be an alias listed by list-ssh-hosts. Use it when a host is only reachable through a bastion the SSH config does not name.",
          ),
      },
    },
    async ({ type, localPort, remoteHost, remotePort, connectionName, proxyJump }) => {
      try {
        const tunnel = await tunnelManager.openTunnel({
          type,
          localPort,
          remoteHost,
          remotePort,
          connectionName: SSHConnectionManager.getInstance().resolveConnection(
            connectionName,
            proxyJump,
          ),
        });

        const usage =
          tunnel.type === "socks5"
            ? `Point clients at socks5h://${tunnel.bindAddress}:${tunnel.localPort}, for example: curl --socks5-hostname ${tunnel.bindAddress}:${tunnel.localPort} http://service.internal/`
            : `Reach ${tunnel.remoteHost}:${tunnel.remotePort} at ${tunnel.bindAddress}:${tunnel.localPort}`;

        return {
          content: [
            { type: "text", text: [formatTunnel(tunnel), usage].join("\n") },
          ],
        };
      } catch (error: unknown) {
        return toolFailure(error, "Failed to open tunnel");
      }
    },
  );

  server.registerTool(
    "close-tunnel",
    {
      description: "Close a tunnel opened by open-tunnel",
      inputSchema: {
        id: z.string().describe("Tunnel id, as reported by open-tunnel or list-tunnels"),
      },
    },
    async ({ id }) => {
      if (!tunnelManager.closeTunnel(id)) {
        return toolFailure(
          new ToolError("TUNNEL_NOT_FOUND", `No open tunnel with id '${id}'`, false),
          "Failed to close tunnel",
        );
      }

      return {
        content: [{ type: "text", text: `Closed tunnel ${id}` }],
      };
    },
  );

  server.registerTool(
    "list-tunnels",
    {
      description: "List the tunnels currently open on this server",
    },
    async () => ({
      content: [{ type: "text", text: formatTunnelList(tunnelManager.list()) }],
    }),
  );
}
