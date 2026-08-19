import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { registerExecuteCommandTool } from "./execute-command.js";
import { registerUploadTool } from "./upload.js";
import { registerDownloadTool } from "./download.js";
import { registerListServersTool } from "./list-servers.js";
import { registerListSshHostsTool } from "./list-ssh-hosts.js";
import { registerTunnelTools } from "./tunnel.js";

export interface RegisterToolsOptions {
  sshConfigHosts?: boolean;
  tunnels?: boolean;
  upload?: boolean;
}

/**
 * Register all tools
 * @param server MCP server instance
 * @param options Which optional tool groups this server exposes
 */
export function registerAllTools(server: McpServer, options: RegisterToolsOptions = {}): void {
  registerExecuteCommandTool(server);
  registerDownloadTool(server);

  // Uploading is off unless it is asked for: a file the guards cannot read is
  // a way to put code on the host and then run it.
  if (options.upload) {
    registerUploadTool(server);
  }

  registerListServersTool(server);

  if (options.sshConfigHosts) {
    registerListSshHostsTool(server);
  }

  if (options.tunnels) {
    registerTunnelTools(server);
  }
} 