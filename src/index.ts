#!/usr/bin/env node

import { SshMcpServer } from "./core/mcp-server.js";
import { SERVER_CONFIG } from "./config/server.js";
import { Logger } from "./utils/logger.js";

const HELP_TEXT = `Usage: ssh-mcp-server [options] [host port username password]

Options:
  --config-file <path>             Load SSH server configs from a JSON file
  --ssh-config-file <path>         Read host aliases from SSH config (default: ~/.ssh/config)
  --ssh <config>                   Add an SSH config as JSON or legacy key=value pairs (repeatable)
  -h, --host <host>                SSH host or SSH config alias for single-host mode
  -p, --port <port>                SSH port for single-host mode
  -u, --username <name>            SSH username for single-host mode
  -w, --password <password>        SSH password for single-host mode
  -k, --privateKey <path>          SSH private key path for single-host mode
  -P, --passphrase <passphrase>    SSH private key passphrase
  -a, --agent <path>               SSH agent socket path or pageant on Windows
  -W, --whitelist <patterns>       Command whitelist regexes, comma-separated
  -B, --blacklist <patterns>       Command blacklist regexes, comma-separated
  --proxy <url>                    Proxy URL (SOCKS5, HTTP, or HTTPS)
  -s, --socksProxy <url>           Legacy SOCKS5 proxy URL
  --allowed-local-paths <paths>    Extra allowed local paths, comma-separated
  --allowed-remote-paths <paths>   Allowed remote POSIX absolute paths, comma-separated
  --transport-mode <mode>          SSH transport mode: exec or shell (default: exec)
  --shell-ready-timeout <ms>       Shell readiness probe timeout (default: 10000)
  --command-template <template>    Wrap commands with <command> or <quotedCommand>
  --pty                           Allocate pseudo-tty for exec mode commands (default: true)
  --try-keyboard                  Enable keyboard-interactive authentication
  --pre-connect                   Pre-connect to all SSH servers on startup
  --ssh-config-hosts              Let tools connect to any host alias of the SSH config on demand
  --allowed-hosts <patterns>      Host alias globs that may be used, comma-separated
  --proxy-jump <chain>            ProxyJump chain, comma-separated [user@]host[:port]
  --guards-profile <name>         Built-in command guards: off, safe or readonly (default: off)
  --guards-file <path>            Extra guard ruleset merged on top of the bundled one
  --sudo-password-env <var>       Env var holding the sudo password (default: SSH_MCP_SUDO_PASSWORD)
  --sudo-user <user>              Target user for sudo (default: root)
  --host-key-checking <mode>      known_hosts verification: strict, accept-new or off (default: strict)
  --known-hosts-file <paths>      known_hosts files to check, comma-separated
  --host-key-algorithms <list>    Accepted host key algorithms, comma-separated (default: ed25519 first)
  --enable-upload                 Expose the upload tool (off by default)
  --audit-log <path|off>          Audit log path (default: XDG state dir, 'off' disables)
  --audit-max-size <bytes>        Rotate the audit log at this size, 0 disables rotation (default: 10485760)
  --audit-keep <count>            Gzipped audit archives to keep (default: 10)
  --disable-tunnels               Do not expose the tunnel tools
  --tunnel-bind-address <addr>    Address tunnels listen on (default: 127.0.0.1)
  --allowed-tunnel-ports <ports>  Tunnel ports that may be bound, comma-separated
  --max-tunnels <count>           Maximum number of open tunnels (default: 8)
  --version, -v                   Print package version
  --help                          Print this help message`;

function hasArg(...names: string[]): boolean {
  return process.argv.slice(2).some((arg) => names.includes(arg));
}

/**
 * Main program entry
 */
async function main(): Promise<void> {
  if (hasArg("--help")) {
    console.log(HELP_TEXT);
    return;
  }

  if (hasArg("--version", "-v")) {
    console.log(SERVER_CONFIG.version);
    return;
  }

  const sshMcpServer = new SshMcpServer();
  await sshMcpServer.run();
}

main().catch((error) => Logger.handleError(error, "【SSH MCP Server Error】", true));
