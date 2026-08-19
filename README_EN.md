<div align="center">

# ssh-mcp-server

[![CI](https://github.com/perhamm/ssh-mcp-server/actions/workflows/ci.yml/badge.svg)](https://github.com/perhamm/ssh-mcp-server/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/%40perhamm%2Fssh-mcp-server?label=%40perhamm%2Fssh-mcp-server)](https://www.npmjs.com/package/@perhamm/ssh-mcp-server)

SSH-based MCP (Model Context Protocol) server that allows remote execution of SSH commands via the MCP protocol.

[Русский](README.md) | English

</div>

## 📝 Project Overview

ssh-mcp-server is a bridging tool that enables AI assistants and other applications supporting the MCP protocol to execute remote SSH commands through a standardized interface. This allows AI assistants to safely operate remote servers, execute commands, and retrieve results without directly exposing SSH credentials to AI models.

## ✨ Key Features

- **🔒 Secure Connections**: Supports multiple secure SSH connection methods, including password authentication and private key authentication (with passphrase support)
- **🛡️ Command Security Control**: Precisely control the range of allowed commands through flexible blacklist and whitelist mechanisms to prevent dangerous operations
- **🔄 Standardized Interface**: Complies with MCP protocol specifications for seamless integration with AI assistants supporting the protocol
- **🚇 Dual Transport Modes**: Supports both `exec` and `shell` transport modes for direct SSH hosts and bastion or jump-host scenarios
- **📂 File Transfer**: Supports bidirectional file transfers, uploading local files to servers or downloading files from servers
- **🔑 Credential Isolation**: SSH credentials are managed entirely locally and never exposed to AI models, enhancing security
- **🚀 Ready to Use**: Can be run directly using NPX without global installation, making it convenient and quick to deploy
- **🗂️ SSH Config Hosts**: One server instance reaches every host alias of `~/.ssh/config`, including `ProxyJump` chains, resolved on first use
- **⛔ Forbidden Core**: Account changes, cron and systemd persistence, sudoers and SSH configuration edits and mass deletion never run, in any profile, with sudo or over SFTP
- **🛡️ Guard Profiles**: A versioned, updatable ruleset (`safe`, `readonly`) that inspects every part of a command line before it is sent
- **🔐 sudo Without Exposing the Password**: The password comes from the server environment, goes to the remote side over stdin and is redacted from the output
- **🧦 Tunnels**: A SOCKS5 proxy (`ssh -D`) or a single port forward (`ssh -L`) on any local port
- **🔎 Host Key Verification**: `known_hosts` is checked by default, on the target and on every ProxyJump hop
- **🔐 Modern Crypto**: Ed25519 first, no SHA-1, CBC or DSA in the negotiated algorithms
- **📓 Audit Log**: Every call is appended as JSON, with built-in rotation and gzipped archives
- **🚫 No File Uploads**: `upload` is not published unless asked for; a file the guards cannot read is a way to put code on the host

## 📦 Repository and Credits

GitHub: [https://github.com/perhamm/ssh-mcp-server](https://github.com/perhamm/ssh-mcp-server)

NPM: [https://www.npmjs.com/package/@perhamm/ssh-mcp-server](https://www.npmjs.com/package/@perhamm/ssh-mcp-server)

This project started as a fork of [classfang/ssh-mcp-server](https://github.com/classfang/ssh-mcp-server) by junki.cn and keeps its ISC license. Parts of the guard ruleset follow ideas from [tufantunc/ssh-mcp](https://github.com/tufantunc/ssh-mcp) (MIT).

## 🛠️ Tools List

| Tool | Name | Description |
|---------|-----------|----------|
| execute-command | Command Execution Tool | Execute SSH commands on remote servers and get results |
| download | File Download Tool | Download files from remote servers to local specified locations |
| list-servers | List Servers Tool | List all available SSH server configurations |
| list-ssh-hosts | SSH Config Hosts Tool | List the SSH config aliases usable as `connectionName` (needs `--ssh-config-hosts`) |
| open-tunnel | Tunnel Tool | Open a SOCKS5 proxy or a local port forward through a connection |
| close-tunnel | Tunnel Tool | Close a tunnel |
| list-tunnels | Tunnel Tool | List the open tunnels and their stream counters |

## 📚 Usage

### 0. 🤖 Quick Setup via AI Skill (Recommended)

If you are using an AI coding assistant that supports skills (such as Claude Code), you can use the built-in **ssh-mcp-helper** skill to complete the installation and configuration interactively — no need to manually edit JSON files.

**How to use:**

1. Install the skill from this repository's `skills/` directory
2. Tell your AI assistant: "Help me set up ssh-mcp-server" or "Configure SSH MCP for my remote server"
3. The skill will guide you step by step: check Node.js environment → choose MCP client → select authentication method → collect connection parameters → generate and write configuration

The skill supports all scenarios covered below (password, private key, SSH config reuse, SOCKS proxy, bastion hosts, multi-connection, 2FA, command restrictions, etc.) and automatically produces correctly formatted configuration.

---

The sections below are arranged from the simplest entry point (username + password) to more advanced scenarios. Pick the case that matches yours and copy the `mcp.json` snippet directly into your MCP client configuration.

> **⚠️ Important**: In MCP configuration files, each command line argument and its value must be separate elements in the `args` array. Do NOT combine them with spaces. For example, use `"--host", "192.168.1.1"` instead of `"--host 192.168.1.1"`.

### 1. 🔑 Username + Password (simplest)

```json
{
  "mcpServers": {
    "ssh-mcp-server": {
      "command": "npx",
      "args": [
        "-y",
        "@perhamm/ssh-mcp-server",
        "--host", "192.168.1.1",
        "--port", "22",
        "--username", "root",
        "--password", "pwd123456"
      ]
    }
  }
}
```

### 2. 🔐 Username + Private Key

```json
{
  "mcpServers": {
    "ssh-mcp-server": {
      "command": "npx",
      "args": [
        "-y",
        "@perhamm/ssh-mcp-server",
        "--host", "192.168.1.1",
        "--port", "22",
        "--username", "root",
        "--privateKey", "~/.ssh/id_rsa"
      ]
    }
  }
}
```

### 3. 🔏 Private Key with Passphrase

```json
{
  "mcpServers": {
    "ssh-mcp-server": {
      "command": "npx",
      "args": [
        "-y",
        "@perhamm/ssh-mcp-server",
        "--host", "192.168.1.1",
        "--port", "22",
        "--username", "root",
        "--privateKey", "~/.ssh/id_rsa",
        "--passphrase", "pwd123456"
      ]
    }
  }
}
```

### 4. 📋 Reuse `~/.ssh/config`

If you already have a host alias in `~/.ssh/config`, the server reads connection parameters directly from it — no need to repeat them in `mcp.json`.

```json
{
  "mcpServers": {
    "ssh-mcp-server": {
      "command": "npx",
      "args": [
        "-y",
        "@perhamm/ssh-mcp-server",
        "--host", "myserver"
      ]
    }
  }
}
```

Assuming your `~/.ssh/config` contains:

```
Host myserver
    HostName 192.168.1.1
    Port 22
    User root
    IdentityFile ~/.ssh/id_rsa
```

You can also specify a custom SSH config file path:

```json
{
  "mcpServers": {
    "ssh-mcp-server": {
      "command": "npx",
      "args": [
        "-y",
        "@perhamm/ssh-mcp-server",
        "--host", "myserver",
        "--ssh-config-file", "/path/to/custom/ssh_config"
      ]
    }
  }
}
```

**Note**: Command-line parameters take precedence over SSH config values. For example, if you specify `--port 2222`, it will override the port from SSH config.

### 5. 🌐 Connecting Through a Proxy

When the target host is only reachable through a proxy, use `--proxy` with a SOCKS5, HTTP, or HTTPS proxy.

```json
{
  "mcpServers": {
    "ssh-mcp-server": {
      "command": "npx",
      "args": [
        "-y",
        "@perhamm/ssh-mcp-server",
        "--host", "192.168.1.1",
        "--port", "22",
        "--username", "root",
        "--password", "pwd123456",
        "--proxy", "http://username:password@proxy-host:proxy-port"
      ]
    }
  }
}
```

Supported URL formats:

```text
socks://username:password@proxy-host:1080
socks5://username:password@proxy-host:1080
http://username:password@proxy-host:8080
https://username:password@proxy-host:8443
```

HTTP and HTTPS proxies use the `CONNECT` method to tunnel to the SSH server, with optional Basic proxy authentication. HTTP and HTTPS default to ports `80` and `443`; SOCKS5 requires an explicit port. HTTPS proxy certificates are verified using the default Node.js trust store.

The existing `socksProxy` configuration and `--socksProxy` option remain supported for backward compatibility, but only accept `socks://` and `socks5://`. Do not configure both `proxy` and `socksProxy`.

### 6. 📝 Restricting Commands With Whitelist / Blacklist

Use `--whitelist` and `--blacklist` to limit which commands the server is allowed to run. Patterns are comma-separated regular expressions. **Strongly recommended** for any production use.

Whitelist example (only allow read-only inspection commands):

```json
{
  "mcpServers": {
    "ssh-mcp-server": {
      "command": "npx",
      "args": [
        "-y",
        "@perhamm/ssh-mcp-server",
        "--host", "192.168.1.1",
        "--port", "22",
        "--username", "root",
        "--password", "pwd123456",
        "--whitelist", "^ls( .*)?,^cat .*,^df.*"
      ]
    }
  }
}
```

Blacklist example (block destructive commands):

```json
{
  "mcpServers": {
    "ssh-mcp-server": {
      "command": "npx",
      "args": [
        "-y",
        "@perhamm/ssh-mcp-server",
        "--host", "192.168.1.1",
        "--port", "22",
        "--username", "root",
        "--password", "pwd123456",
        "--blacklist", "^rm .*,^shutdown.*,^reboot.*"
      ]
    }
  }
}
```

> Note: If both whitelist and blacklist are specified, the command must pass both checks (whitelist first, then blacklist) to be executed.

### 7. 🧩 Wrapping Commands With a Template

`commandTemplate` wraps every executed command in a template — useful for switching user via `su`, running inside a container, or jumping through another host. Use `<quotedCommand>` when the command is passed as a shell argument, or `<command>` for raw insertion. The template is applied **after** the working-directory `cd` is prepended, so the entire `cd ... && <actual command>` chain gets wrapped.

```json
{
  "mcpServers": {
    "ssh-mcp-server": {
      "command": "npx",
      "args": [
        "-y",
        "@perhamm/ssh-mcp-server",
        "--host", "10.0.0.1",
        "--port", "22",
        "--username", "deploy",
        "--password", "xxx",
        "--command-template", "su root -c <quotedCommand>"
      ]
    }
  }
}
```

Executing `ls /app` with directory `/data` actually sends:

```
su root -c 'cd -- '\''/data'\'' && ls /app'
```

Other useful templates:

```text
sudo bash -c <quotedCommand>
docker exec -i mycontainer sh -c <quotedCommand>
ssh jumphost <quotedCommand>
```

### 8. 🚇 Bastion / Jump Host (`transportMode: shell`)

`transportMode` defaults to `exec`. Switch to `shell` when:

- SSH login succeeds but `exec` command execution fails
- The remote side requires shell startup scripts, banners, or environment initialization first
- The target effectively exposes only an interactive shell (bastion hosts, jump hosts, network devices)

Behavior differences:

- `exec`: supports `execute-command`, `upload`, and `download`
- `shell`: runs commands through a persistent shell session with an internal command queue, but does **not** support `upload` / `download` because SFTP is unavailable in this mode

```json
{
  "mcpServers": {
    "ssh-mcp-server": {
      "command": "npx",
      "args": [
        "-y",
        "@perhamm/ssh-mcp-server",
        "--host", "bastion.example.com",
        "--port", "22",
        "--username", "ops",
        "--password", "pwd123456",
        "--transport-mode", "shell",
        "--shell-ready-timeout", "15000"
      ]
    }
  }
}
```

In JSON config files you can also set `shellCommandTimeoutMs` to override the default per-command timeout for shell-backed connections.

### 9. 🔐 Multi-Factor Authentication (2FA / MFA)

When the SSH server requires multi-factor authentication (password + private key + 2FA verification code), enable `tryKeyboard`. The password and private key are auto-supplied. For non-password prompts, set `SSH_MCP_2FA_CODE` in the server environment before connecting.

```json
{
  "mcpServers": {
    "ssh-mcp-server": {
      "command": "npx",
      "args": [
        "-y",
        "@perhamm/ssh-mcp-server",
        "--host", "example.com",
        "--port", "22",
        "--username", "user",
        "--password", "your_password",
        "--privateKey", "/path/to/key",
        "--try-keyboard"
      ]
    }
  }
}
```

**Authentication flow:**
1. Private key authentication (if provided)
2. Password authentication (if provided)
3. Keyboard-interactive for 2FA code via `SSH_MCP_2FA_CODE`

### 10. 🧩 Managing Multiple SSH Connections

When you need to expose more than one SSH target through the same MCP server, register them under unique connection names and select the target at call time via `connectionName`. There are three ways to configure them:

#### 📄 Method 1: Using Config File (Recommended)

Create a JSON configuration file (e.g., `ssh-config.json`):

**Array Format:**
```json
[
  {
    "name": "dev",
    "host": "1.2.3.4",
    "port": 22,
    "username": "alice",
    "password": "{abc=P100s0}",
    "socksProxy": "socks://127.0.0.1:10808",
    "commandTimeoutMs": 120000,
    "maxOutputBytes": 10485760
  },
  {
    "name": "bastion",
    "host": "9.9.9.9",
    "port": 22,
    "username": "ops",
    "password": "pwd123456",
    "transportMode": "shell",
    "shellReadyTimeoutMs": 15000,
    "shellCommandTimeoutMs": 45000,
    "connectionTimeoutMs": 30000,
    "keepaliveIntervalMs": 10000,
    "keepaliveCountMax": 3
  },
  {
    "name": "prod",
    "host": "5.6.7.8",
    "port": 22,
    "username": "bob",
    "password": "yyy",
    "socksProxy": "socks://127.0.0.1:10808"
  },
  {
    "name": "secure-server",
    "host": "secure.example.com",
    "port": 22,
    "username": "admin",
    "password": "your_password",
    "privateKey": "/path/to/private/key",
    "tryKeyboard": true
  }
]
```

**Object Format:**
```json
{
  "dev": {
    "host": "1.2.3.4",
    "port": 22,
    "username": "alice",
    "password": "{abc=P100s0}",
    "socksProxy": "socks://127.0.0.1:10808",
    "commandTimeoutMs": 120000,
    "maxOutputBytes": 10485760
  },
  "bastion": {
    "host": "9.9.9.9",
    "port": 22,
    "username": "ops",
    "password": "pwd123456",
    "transportMode": "shell",
    "shellReadyTimeoutMs": 15000,
    "shellCommandTimeoutMs": 45000
  },
  "prod": {
    "host": "5.6.7.8",
    "port": 22,
    "username": "bob",
    "password": "yyy",
    "socksProxy": "socks://127.0.0.1:10808"
  }
}
```

Then use the `--config-file` parameter:

```json
{
  "mcpServers": {
    "ssh-mcp-server": {
      "command": "npx",
      "args": [
        "-y",
        "@perhamm/ssh-mcp-server",
        "--config-file", "ssh-config.json"
      ]
    }
  }
}
```

#### 🔧 Method 2: Using JSON Format with --ssh Parameter

You can pass JSON-formatted configuration strings directly:

```json
{
  "mcpServers": {
    "ssh-mcp-server": {
      "command": "npx",
      "args": [
        "-y",
        "@perhamm/ssh-mcp-server",
        "--ssh", "{\"name\":\"dev\",\"host\":\"1.2.3.4\",\"port\":22,\"username\":\"alice\",\"password\":\"{abc=P100s0}\",\"socksProxy\":\"socks://127.0.0.1:10808\"}",
        "--ssh", "{\"name\":\"bastion\",\"host\":\"9.9.9.9\",\"port\":22,\"username\":\"ops\",\"password\":\"pwd123456\",\"transportMode\":\"shell\",\"shellReadyTimeoutMs\":15000}",
        "--ssh", "{\"name\":\"prod\",\"host\":\"5.6.7.8\",\"port\":22,\"username\":\"bob\",\"password\":\"yyy\",\"socksProxy\":\"socks://127.0.0.1:10808\"}"
      ]
    }
  }
}
```

#### 📝 Method 3: Legacy Comma-Separated Format (Backward Compatible)

For simple cases without special characters in passwords, you can still use the legacy format:

```bash
npx @perhamm/ssh-mcp-server \
  --ssh "name=dev,host=1.2.3.4,port=22,user=alice,password=xxx" \
  --ssh "name=prod,host=5.6.7.8,port=22,user=bob,password=yyy"
```

> **⚠️ Note**: The legacy format may have issues with passwords containing special characters like `=`, `,`, `{`, `}`. Use Method 1 or Method 2 for passwords with special characters.

In MCP tool calls, specify the connection name via the `connectionName` parameter. If omitted, the default connection is used.

Example (execute command on 'prod' connection):

```json
{
  "tool": "execute-command",
  "params": {
    "cmdString": "ls -al",
    "connectionName": "prod"
  }
}
```

Example (execute command with timeout options):

```json
{
  "tool": "execute-command",
  "params": {
    "cmdString": "ping -c 10 127.0.0.1",
    "connectionName": "prod",
    "timeout": 5000
  }
}
```

### 11. 🗂️ One Server for Every Host of `~/.ssh/config`

With `--ssh-config-hosts` the server stops needing a host up front. Any alias of the SSH config becomes a `connectionName`, and the connection is established the first time a tool uses it.

```json
{
  "mcpServers": {
    "ssh": {
      "command": "npx",
      "args": [
        "-y",
        "@perhamm/ssh-mcp-server",
        "--ssh-config-hosts",
        "--allowed-hosts", "prod-*,stage-*",
        "--guards-profile", "safe"
      ],
      "env": {
        "SSH_MCP_SUDO_PASSWORD": "..."
      }
    }
  }
}
```

The agent calls `list-ssh-hosts` (with a `filter` such as `prod-*` when the config is large; the listing is capped at 100 entries), picks an alias and passes it as `connectionName`. `HostName`, `Port`, `User`, `IdentityFile` and `ProxyJump` come from the SSH config; the key file is read by the server, so only its path ever exists in the conversation. Without an `IdentityFile` the agent socket from `SSH_AUTH_SOCK` is used, and an alias without a `HostName` is connected to by its own name, the way `ssh` does it. Only an alias declared by its own `Host` block is reachable: a `Host *` block provides defaults, it does not turn an arbitrary name into a host.

`--allowed-hosts` restricts which aliases may be reached (`*` and `?` globs). An alias outside the list is refused with `SSH_HOST_NOT_ALLOWED`.

A `ProxyJump` in the SSH config is followed automatically: each hop is connected through the channel of the previous one, the way `ssh -J` does it, up to five hops. `--proxy-jump "bastion,gateway:2222"` sets the same thing from the command line. `--proxy` and `--proxy-jump` cannot be combined.

### 12. 🛡️ Guard Profiles

Guards are a versioned ruleset, shipped in [`guards/default-guards.json`](guards/default-guards.json), that inspects every command before it leaves the server.

| Profile | Behaviour |
|---|---|
| `off` | Profile rules disabled, the forbidden core still applies. The default |
| `safe` | Adds the destructive-command rules, allows everything else |
| `readonly` | Allows read-only diagnostics only, inherits every deny rule of `safe` |

Part of the ruleset is a **forbidden core** that no profile, no `sudo: true` and no local ruleset can lift, and that covers SFTP as well:

| Category | What is closed |
|---|---|
| Interpreters | `python`, `perl`, `ruby`, `node`, `php`, `lua`, `Rscript`, and running a script by file: `bash /tmp/x.sh`, `sh -s`, `source`. An inline `bash -c "..."` still works, because its contents are parsed and checked |
| Accounts | `useradd`, `usermod`, `userdel`, `groupadd`, `passwd`, `chpasswd`, `chage`, `vipw`, and writes to `/etc/passwd`, `/etc/shadow`, `/etc/group` |
| sudo policy | Writes to `/etc/sudoers` and `/etc/sudoers.d`, `visudo` |
| Scheduling | `crontab` except `crontab -l`, writes to `/etc/cron*`, `/var/spool/cron`, `/etc/anacrontab`, the `at` and `batch` commands |
| systemd | Unit and timer writes under `/etc/systemd`, `/lib/systemd`, `/usr/lib/systemd`, `systemctl edit`, `systemd-run` |
| SSH | Edits of `/etc/ssh/*`, `~/.ssh/*`, `authorized_keys`, `sshd_config`, plus `ssh-keygen`, `ssh-copy-id`, `ssh-add` |
| Mass deletion | `rm -r` of a top-level or system directory, `rm -r` driven by a wildcard, `find -delete`, deletion through `xargs rm`, `--no-preserve-root` |
| Disks and secrets | `mkfs`, `wipefs`, `dd of=/dev/`, writes to `/dev/sd*`, fork bombs, reads of `/etc/shadow` and private keys |

Ordinary work is untouched: `crontab -l`, `cat /etc/ssh/sshd_config`, `systemctl restart nginx` and `rm -rf /var/lib/myapp/cache/tmp` all pass. `download` refuses to fetch `/etc/shadow` or anything under `~/.ssh`, whatever `allowedRemotePaths` says, and the local side is covered too, so a download cannot land in your own `~/.ssh`. Uploading is off entirely: the `upload` tool is only published with `--enable-upload`, and the `readonly` profile refuses it even then. There is no flag that turns the core off; a server that is meant to create users or edit crontabs has to have the core edited in the fork on purpose.

```json
"args": ["-y", "@perhamm/ssh-mcp-server", "--ssh-config-hosts", "--guards-profile", "safe"]
```

On top of the core, `safe` blocks `shutdown` and `reboot`, firewall flushes, stopping sshd or kubelet, `kubectl delete`, `helm uninstall`, `docker system prune`, package removal, `DROP DATABASE`, `curl | sh`, `git push --force`, log destruction, kernel module changes and interactive editors. `readonly` additionally requires every part of the command to be on an allow list, and blocks `sudo`, `su`, `doas` and `pkexec` outright.

The command line is split on `;`, `|`, `&&`, `||`, `&`, newlines and `$(...)` substitutions, honouring quotes, and every part is checked on its own, so `ls; rm -rf /` is refused although the line starts with an allowed `ls`. Wrappers (`sudo`, `env`, `timeout 5`, `LC_ALL=C`) are stripped before matching, the script inside `bash -c "..."` is parsed and checked by the same rules, and a command is capped at 5000 characters.

Guards catch agent mistakes rather than a determined bypass: an interpreter carrying arbitrary code, such as `python -c`, is beyond what rules can read. Where a bypass is unacceptable, restrict the rights of the SSH user itself.

Keeping the rules current:

1. Merge upstream into your fork. The ruleset carries a `version` that is reported by `list-servers` and in every refusal.
2. Keep your own file and point `--guards-file /etc/ssh-mcp/guards.json` at it. Its rules are added to the bundled ones and the version becomes `2026.08.19+local-1`.
3. Refresh that file from cron: `node scripts/update-guards.js https://example.com/guards.json /etc/ssh-mcp/guards.json`. The download is parsed and every pattern compiled before the file is replaced, so a broken fetch leaves the working ruleset in place.

```json
{
  "version": "local-1",
  "profiles": {
    "safe": {
      "deny": [
        { "id": "no-ansible", "pattern": "^ansible-playbook\\b", "reason": "deploys are done from CI" }
      ]
    }
  }
}
```

`scope: "command"` makes a rule match the whole command instead of each part. A local file may add rules to the `forbidden` block, but it cannot remove the bundled ones: the lists are concatenated. `--whitelist` and `--blacklist` still work and are checked before the guards.

### 13. 🔐 sudo Without Exposing the Password

The sudo password lives in the environment of the server process. The agent asks for elevation with `sudo: true` and never sees the password, neither in the call nor in the output.

```json
{
  "tool": "execute-command",
  "params": {
    "cmdString": "systemctl restart nginx",
    "connectionName": "prod-master",
    "sudo": true
  }
}
```

The command is sent as `sudo -S -k -p '' -u root -- /bin/sh -c '<command>'` and the password is written to the channel's stdin, so it stays out of the command line, out of `ps` and out of the shell history. The pseudo-tty is switched off for those commands, because a tty would echo the password back into the captured output, and the password is redacted from output and error messages anyway.

`--sudo-password-env` changes the variable name (default `SSH_MCP_SUDO_PASSWORD`), `--sudo-user` the target user (default `root`). An empty variable fails the call with `SUDO_PASSWORD_MISSING` before any connection is made, and the `readonly` profile refuses sudo entirely.

In `shell` mode the password is sent as the line right after the command, since sudo reads the same stdin the shell reads its script from; `-k` guarantees the prompt, so the line is always consumed by sudo. `exec` mode is the better transport for sudo.

### 14. 🧦 Tunnels

`open-tunnel` binds a local listener and carries its traffic through the SSH connection, which is how services that are only reachable from the target host become reachable locally.

```json
{
  "tool": "open-tunnel",
  "params": { "type": "socks5", "localPort": 8777, "connectionName": "prod-master" }
}
```

```sh
curl --socks5-hostname 127.0.0.1:8777 http://prometheus.monitoring.svc:9090/api/v1/query?query=up
```

Names are resolved on the remote side, so hosts that only exist in the cluster's DNS work. A single port forward is the other type:

```json
{
  "tool": "open-tunnel",
  "params": { "type": "local", "localPort": 15432, "remoteHost": "pg-master.internal", "remotePort": 5432 }
}
```

Without `localPort` the OS picks a free port and the answer reports it. Tunnels live until `close-tunnel`, until the SSH connection drops or until the server stops.

| Flag | Default | Effect |
|---|---|---|
| `--tunnel-bind-address` | `127.0.0.1` | Address the listeners bind to |
| `--allowed-tunnel-ports` | unrestricted | Ports that may be bound |
| `--max-tunnels` | 8 | How many tunnels can be open at once |
| `--disable-tunnels` | off | Removes the tunnel tools |

Listeners bind to loopback by default. Any wider address exposes the proxy to your network, so change it deliberately.

### 15. 🔎 Host Key Verification

The host key is checked against `known_hosts` on every connection, jump hops included. The default mode is `strict`: a host that is not in `known_hosts` is refused.

| Mode | Behaviour |
|---|---|
| `strict` | The default. Only hosts recorded in `known_hosts` are reachable |
| `accept-new` | An unknown host is recorded on first sight; a key that contradicts the record is still refused |
| `off` | No verification, the upstream behaviour |

`~/.ssh/known_hosts`, `~/.ssh/known_hosts2` and `/etc/ssh/ssh_known_hosts` are read, or the `UserKnownHostsFile` of the alias when the SSH config names one. `--known-hosts-file` sets the list explicitly. Hashed entries, patterns, the `[host]:port` form and the `@revoked` marker are all understood.

A refusal comes back as `SSH_HOST_KEY_REJECTED` with the fingerprint to compare:

```text
Host key of prod.example.com is not in known_hosts (~/.ssh/known_hosts): ssh-ed25519 SHA256:xxxx.
Verify that fingerprint, add the host to known_hosts, or start the server with --host-key-checking accept-new.
```

A key that contradicts `known_hosts` is refused in every mode, including `accept-new`. For onboarding a fleet, run once with `--host-key-checking accept-new` and go back to `strict` afterwards.

### 16. 📓 Audit Log

Every call is appended as one JSON line: the command, the connection, the sudo flag, the guard verdict, the duration and the size of the output. The output itself is never logged and the sudo password is redacted.

```json
{"time":"2026-08-19T08:12:44.101Z","pid":8123,"event":"command","result":"blocked","connection":"prod-master","command":"useradd deploy","sudo":true,"code":"COMMAND_VALIDATION_FAILED"}
{"time":"2026-08-19T08:12:51.880Z","pid":8123,"event":"command","result":"ok","connection":"prod-master","command":"systemctl status nginx","durationMs":412,"bytes":1840}
```

The events are `connect`, `command`, `download`, `upload`, `tunnel-open`, `tunnel-close` and `host-key`. The default path is `$XDG_STATE_HOME/ssh-mcp-server/audit.jsonl` (usually `~/.local/state/ssh-mcp-server/audit.jsonl`), mode `0600`.

| Flag | Default | Effect |
|---|---|---|
| `--audit-log <path>` | XDG state directory | Log path; `off` disables logging |
| `--audit-max-size <bytes>` | 10485760 | Rotate at this size; `0` disables the built-in rotation |
| `--audit-keep <count>` | 10 | How many gzipped archives to keep |

Rotation is built in: at the limit the current file becomes `audit.jsonl.1.gz`, older archives shift up and anything past `--audit-keep` is deleted. If logrotate already owns the file, pass `--audit-max-size 0` and rotate it with `copytruncate`. A write failure never fails the command; the server reports it once on stderr.

### 17. 🔐 Negotiated Algorithms

The defaults put Ed25519 first and drop everything that rests on SHA-1, CBC or DSA:

- host keys: `ssh-ed25519`, `ecdsa-sha2-nistp256/384/521`, `rsa-sha2-512`, `rsa-sha2-256`
- kex: `curve25519-sha256` first, no `diffie-hellman-group1-sha1` or `-sha1` variants
- ciphers: `chacha20-poly1305`, AES-GCM, AES-CTR; no CBC, no 3DES
- MACs: the ETM SHA-2 family; no `hmac-sha1`, no `hmac-md5`

`--host-key-algorithms ssh-ed25519` pins the host key list to Ed25519 alone. The `algorithms` object of a connection config still replaces whatever categories it names.

### ⏱️ Command Execution Timeout

The `execute-command` tool supports timeout options to prevent commands from hanging indefinitely:

- **timeout**: Per-call command execution timeout in milliseconds (optional); when provided, it overrides the connection setting, otherwise the connection setting or its 30000ms default is used
- Set `commandTimeoutMs` per connection in the JSON config file to change that default, so callers do not have to pass `timeout` on every call (`exec` mode)
- The `shell` mode equivalent is `shellCommandTimeoutMs`
- A `timeout` passed with the call always takes precedence over both settings
- Connections use SSH keepalives by default (`keepaliveIntervalMs`: 10000, `keepaliveCountMax`: 3) and respect `connectionTimeoutMs` for connection setup
- SFTP open and transfer operations respect `sftpTimeoutMs` (default 300000ms)
- Error responses include stable `code`, `message`, and `retriable` fields for easier agent-side handling

This is particularly useful for commands like `ping`, `tail -f`, or other long-running processes that might block execution.

### 📦 Command Output Limit

The combined captured `stdout` and `stderr` for each command is limited to protect the MCP server from large files or unbounded output:

- Set `maxOutputBytes` in a JSON connection configuration; the default is `10485760` bytes (10 MiB)
- `maxOutputBytes` must be a non-negative integer; `0` disables the limit, which is not recommended for untrusted commands
- When output exceeds the limit, the remote command is aborted and the tool returns an `OUTPUT_LIMIT_EXCEEDED` error with the captured, truncated output instead of reporting success
- With `pty: false`, warnings and progress written to `stderr` by successful commands are preserved in a `[stderr]` section
- The limit applies to both `exec` and `shell` mode. `exec` mode closes just that command's channel, whereas the `shell` channel is shared by every command on the connection and the remote keeps writing after an abort, so the connection is dropped instead — the same way a shell mode command timeout behaves

### 🗂️ List All SSH Servers

You can use the MCP tool `list-servers` to get all available SSH server configurations:

Example call:

```json
{
  "tool": "list-servers",
  "params": {}
}
```

Example response:

```json
[
  { "name": "dev", "host": "1.2.3.4", "port": 22, "username": "alice" },
  { "name": "prod", "host": "5.6.7.8", "port": 22, "username": "bob" }
]
```

### ⚙️ Command Line Options Reference

```text
Options:
  --config-file       JSON configuration file path (recommended for multiple servers)
  --ssh-config-file   SSH config file path (default: ~/.ssh/config)
  --ssh               SSH connection configuration (can be JSON string or legacy format)
  -h, --host          SSH server host address or alias from SSH config
  -p, --port          SSH server port
  -u, --username      SSH username
  -w, --password      SSH password
  -k, --privateKey    SSH private key file path
  -P, --passphrase    Private key passphrase (if any)
  -a, --agent         SSH agent socket path
  --try-keyboard      Enable keyboard-interactive authentication for 2FA/MFA (default: false)
  -W, --whitelist     Command whitelist, comma-separated regular expressions
  -B, --blacklist     Command blacklist, comma-separated regular expressions
  --proxy             Proxy URL supporting SOCKS5, HTTP, and HTTPS
  -s, --socksProxy    Legacy SOCKS5 proxy URL
  --allowed-local-paths   Additional allowed local paths for upload/download, comma-separated
  --allowed-remote-paths  Allowed remote (POSIX, absolute) paths for SFTP upload/download, comma-separated
  --transport-mode    SSH transport mode: exec or shell (default: exec)
  --shell-ready-timeout   Shell readiness probe timeout in milliseconds (default: 10000)
  --command-template  Command template, use <quotedCommand> for shell arguments or <command> for raw insertion
  --pty               Allocate pseudo-tty for command execution (default: true)
  --pre-connect       Pre-connect to all configured SSH servers on startup
  --ssh-config-hosts  Let tools connect to any host alias of the SSH config on demand
  --allowed-hosts     Host alias globs that may be used, comma-separated
  --proxy-jump        ProxyJump chain, comma-separated [user@]host[:port]
  --guards-profile    Built-in command guards: off, safe or readonly (default: off)
  --guards-file       Extra guard ruleset merged on top of the bundled one
  --sudo-password-env Env var holding the sudo password (default: SSH_MCP_SUDO_PASSWORD)
  --sudo-user         Target user for sudo (default: root)
  --host-key-checking known_hosts verification: strict, accept-new or off (default: strict)
  --known-hosts-file  known_hosts files to check, comma-separated
  --enable-upload     Expose the upload tool (off by default)
  --audit-log         Audit log path, 'off' disables (default: XDG state dir)
  --audit-max-size    Rotate the audit log at this size, 0 disables rotation (default: 10485760)
  --audit-keep        Gzipped audit archives to keep (default: 10)
  --host-key-algorithms   Accepted host key algorithms, comma-separated
  --disable-tunnels   Do not expose the tunnel tools
  --tunnel-bind-address   Address tunnels listen on (default: 127.0.0.1)
  --allowed-tunnel-ports  Tunnel ports that may be bound, comma-separated
  --max-tunnels       Maximum number of open tunnels (default: 8)
  --version, -v       Print package version
  --help              Print this help message
```

## 🛡️ Security Considerations

This server provides powerful capabilities to execute commands and transfer files on remote servers. To ensure it is used securely, please consider the following:

- **Command Whitelisting**: It is *strongly recommended* to use the `--whitelist` option to restrict the set of commands that can be executed. Without a whitelist, any command can be executed on the remote server, which can be a significant security risk.
- **Private Key Security**: The server reads the SSH private key into memory. Ensure that the machine running the `ssh-mcp-server` is secure. Do not expose the server to untrusted networks.
- **Denial of Service (DoS)**: The server does not have built-in rate limiting. An attacker could potentially launch a DoS attack by flooding the server with connection requests or large file transfers. It is recommended to run the server behind a firewall or reverse proxy with rate-limiting capabilities.
- **Path Traversal**: The server has built-in protection against path traversal attacks on the local filesystem. However, it is still important to be mindful of the paths used in `upload` and `download` commands.
- **Local Transfer Scope**: By default, local file transfers are restricted to the current working directory. Use `--allowed-local-paths` or `allowedLocalPaths` in config only for explicitly trusted directories.
- **Uploads**: Off by default. Turning them on with `--enable-upload` gives the agent a way to place a file the guards cannot read and then run it, so keep `allowedRemotePaths` tight if you do.
- **Audit Log**: On by default. It records commands verbatim, so a command that carries a secret in its arguments carries it into the log as well.
- **Guard Profiles**: `--guards-profile safe` is the baseline for production work, `readonly` for incident triage. With `off` only the forbidden core is left, everything else runs and the server logs a warning.
- **Host Keys**: Verified against `known_hosts` in `strict` mode by default. `--host-key-checking off` is a lab setting, not a production one.
- **Tunnels**: Listeners bind to loopback. The SOCKS5 proxy has no authentication, so a listener bound to `0.0.0.0` hands your internal network to anyone who can reach the port; the server logs a warning when that is configured.
- **Remote Transfer Scope**: SFTP upload/download accepts only absolute POSIX paths. If `allowedRemotePaths` (or `--allowed-remote-paths`) is not configured, any remote path is accepted and the server prints a startup warning. Configure `allowedRemotePaths` to whitelist a small set of remote directories; this is strongly recommended to prevent prompt-injection-driven reads or writes of files like `~/.ssh/authorized_keys` or `/etc/sshd_config`.


