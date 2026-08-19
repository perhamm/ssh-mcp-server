import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { SSHConnectionManager } from "../services/ssh-connection-manager.js";
import type { SshConfigHost } from "../utils/ssh-config-parser.js";

const DEFAULT_HOST_LIMIT = 100;

/**
 * An SSH config of a few thousand aliases is common on a jump box, and the
 * whole list would cost more context than it is worth, so the tool filters and
 * caps it and says what it left out.
 */
export function filterSshHosts(
  hosts: SshConfigHost[],
  filter?: string,
): SshConfigHost[] {
  if (!filter) {
    return hosts;
  }

  const needle = filter.toLowerCase();
  const regex = /[*?]/.test(filter)
    ? new RegExp(
        `^${needle
          .replace(/[.+^${}()|[\]\\]/g, "\\$&")
          .replace(/\*/g, ".*")
          .replace(/\?/g, ".")}$`,
      )
    : undefined;

  return hosts.filter((host) => {
    const haystack = [host.alias, host.hostName || ""].join(" ").toLowerCase();
    return regex ? regex.test(host.alias.toLowerCase()) : haystack.includes(needle);
  });
}

export function formatSshHostList(
  hosts: SshConfigHost[],
  options: { filter?: string; limit?: number; total?: number } = {},
): string {
  if (hosts.length === 0) {
    return options.total
      ? `No SSH config host alias matches '${options.filter}'. The config has ${options.total} aliases.`
      : "No SSH config host aliases are available. Start the server with --ssh-config-hosts to enable them.";
  }

  const limit = options.limit ?? DEFAULT_HOST_LIMIT;
  const shown = hosts.slice(0, limit);
  const omitted = hosts.length - shown.length;

  const summary = shown.map((host) => {
    const parts = [host.alias];

    if (host.hostName) {
      parts.push(`hostname=${host.hostName}`);
    }
    if (host.user) {
      parts.push(`user=${host.user}`);
    }
    if (host.port) {
      parts.push(`port=${host.port}`);
    }
    if (host.proxyJump) {
      parts.push(`proxyJump=${host.proxyJump}`);
    }

    return parts.join(" | ");
  });

  return [
    `SSH config host aliases available as connectionName (showing ${shown.length} of ${hosts.length}):`,
    ...summary,
    ...(omitted > 0
      ? [
          "",
          `${omitted} more aliases are not listed. Narrow the list with the filter argument, for example filter="prod".`,
        ]
      : []),
    "",
    "Raw JSON:",
    JSON.stringify(shown),
  ].join("\n");
}

/**
 * Register list-ssh-hosts tool
 */
export function registerListSshHostsTool(server: McpServer): void {
  server.registerTool(
    "list-ssh-hosts",
    {
      description:
        "List the SSH config host aliases this server can connect to. Pass an alias as connectionName to any other tool; the connection is established on first use with the credentials from the local SSH config. Large configs are truncated, so pass a filter when you are looking for a specific host.",
      inputSchema: {
        filter: z
          .string()
          .optional()
          .describe(
            "Substring of the alias or hostname, or a glob such as 'prod-*'",
          ),
        limit: z
          .number()
          .int()
          .positive()
          .max(1000)
          .optional()
          .describe("How many aliases to list, default 100"),
      },
    },
    async ({ filter, limit }) => {
      const sshManager = SSHConnectionManager.getInstance();
      const hosts = sshManager.getSshConfigHosts();
      return {
        content: [
          {
            type: "text",
            text: formatSshHostList(filterSshHosts(hosts, filter), {
              filter,
              limit,
              total: hosts.length,
            }),
          },
        ],
      };
    },
  );
}
