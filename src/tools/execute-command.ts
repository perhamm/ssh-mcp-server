import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { SSHConnectionManager } from "../services/ssh-connection-manager.js";
import { Logger } from "../utils/logger.js";
import { toToolError } from "../utils/tool-error.js";

/**
 * Register execute command tool
 */
export function registerExecuteCommandTool(server: McpServer): void {
  const sshManager = SSHConnectionManager.getInstance();

  server.registerTool(
    "execute-command",
    {
      description: "Execute command on connected server and get output result",
      inputSchema: {
        cmdString: z.string().describe("Command to execute"),
        directory: z.string().optional().describe("Working directory for command execution"),
        connectionName: z
          .string()
          .optional()
          .describe(
            "SSH connection name or SSH config host alias (optional, default is the first configured connection). Call list-ssh-hosts to see the aliases this server can resolve.",
          ),
        timeout: z
          .number()
          .int()
          .positive()
          .optional()
          .describe(
            "Command execution timeout in milliseconds (optional; overrides the connection's commandTimeoutMs or shellCommandTimeoutMs, which defaults to 30000ms)",
          ),
        sudo: z
          .boolean()
          .optional()
          .describe(
            "Run the command through sudo. The password is read from the server environment and is never part of this call or of the output.",
          ),
        proxyJump: z
          .string()
          .optional()
          .describe(
            "Comma separated jump hosts to reach this connection through, overriding the chain of the SSH config. Every hop has to be an alias listed by list-ssh-hosts. Use it when a host is only reachable through a bastion the SSH config does not name.",
          ),
      },
    },
    async ({ cmdString, directory, connectionName, timeout, sudo, proxyJump }) => {
      try {
        const result = await sshManager.executeCommand(
          cmdString,
          directory,
          sshManager.resolveConnection(connectionName, proxyJump),
          {
            timeout,
            sudo,
          },
        );
        return {
          content: [{ type: "text", text: result }],
        };
      } catch (error: unknown) {
        const toolError = toToolError(error, "UNKNOWN_ERROR");
        Logger.handleError(toolError, "Failed to execute command");
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
    },
  );
}
