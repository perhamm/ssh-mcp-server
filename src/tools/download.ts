import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { SSHConnectionManager } from "../services/ssh-connection-manager.js";
import { Logger } from "../utils/logger.js";
import { toToolError } from "../utils/tool-error.js";

/**
 * Register file download tool
 */
export function registerDownloadTool(server: McpServer): void {
  const sshManager = SSHConnectionManager.getInstance();

  server.registerTool(
    "download",
    {
      description: "Download file from connected server",
      inputSchema: {
        remotePath: z.string().describe("Remote path"),
        localPath: z.string().describe("Local path"),
        connectionName: z.string().optional().describe("SSH connection name (optional, default is 'default')"),
        proxyJump: z
          .string()
          .optional()
          .describe(
            "Comma separated jump hosts to reach this connection through, overriding the chain of the SSH config. Every hop has to be an alias listed by list-ssh-hosts. Use it when a host is only reachable through a bastion the SSH config does not name.",
          ),
      },
    },
    async ({ remotePath, localPath, connectionName, proxyJump }) => {
      try {
        const result = await sshManager.download(
          remotePath,
          localPath,
          sshManager.resolveConnection(connectionName, proxyJump),
        );
        return {
          content: [{ type: "text", text: result }],
        };
      } catch (error: unknown) {
        const toolError = toToolError(error, "UNKNOWN_ERROR");
        Logger.handleError(toolError, "Failed to download file");
        return {
          content: [{
            type: "text",
            text: JSON.stringify(
              {
                code: toolError.code,
                message: toolError.message,
                retriable: toolError.retriable,
              },
              null,
              2,
            ),
          }],
          isError: true,
        };
      }
    }
  );
} 
