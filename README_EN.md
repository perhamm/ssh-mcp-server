<div align="center">

# ssh-mcp-server

[![CI](https://github.com/perhamm/ssh-mcp-server/actions/workflows/ci.yml/badge.svg)](https://github.com/perhamm/ssh-mcp-server/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/%40perhamm%2Fssh-mcp-server?label=%40perhamm%2Fssh-mcp-server)](https://www.npmjs.com/package/@perhamm/ssh-mcp-server)

An MCP server on top of SSH: the agent runs commands on remote machines while the keys, the passwords and the sudo password stay on our side.

A fork of [classfang/ssh-mcp-server](https://github.com/classfang/ssh-mcp-server) under ISC.

[Русский](README.md) | English

</div>

## What this is

ssh-mcp-server is a bridge between an MCP client (Claude Code, Cursor, Cline) and SSH. The agent calls a tool, the server connects to the machine and returns the output. The model never sees the private key, the password or the sudo password: all of that is read from a local config and from the environment of the server process.

One server handles any number of hosts. The host is picked on the fly by its alias in `~/.ssh/config`, so there is no need to spell out every machine in the MCP client config.

## What this fork adds

| Feature | Why |
|---|---|
| Hosts from `~/.ssh/config` on the fly | One MCP for the whole fleet. The alias goes in `connectionName` and the connection comes up on first use |
| ProxyJump | A host behind a bastion is reachable by its alias, the `ProxyJump` chain is read from the SSH config |
| sudo from the environment | The agent asks for `sudo: true`, the server supplies the password and strips it from the output |
| Forbidden core | A list of operations that never run: not under sudo, not in any profile, not through SFTP |
| Guard profiles | A ready set of denials in `safe` and a whitelist in `readonly`, versioned and updatable |
| Tunnels | SOCKS5 (the equivalent of `ssh -D`) and port forwarding (the equivalent of `ssh -L`) on any local port |
| Host key verification | `known_hosts` is checked by default, a key that is not on the list means the connection is refused |
| Modern cryptography | Ed25519 first in the list, no SHA-1, no CBC, no DSA |
| Audit log | Every call is written to JSONL with rotation and gzip archives |
| No file uploads | `upload` is not published by default: a file the guards cannot read is a way to smuggle code onto the host |

## Tools

| Tool | What it does |
|---|---|
| `execute-command` | Runs a command, supports `sudo` and an arbitrary `connectionName` |
| `download` | Fetches a file from the server |
| `list-servers` | Shows the configured connections, their status and the active guard profile |
| `list-ssh-hosts` | Shows the SSH config aliases available as `connectionName` |
| `open-tunnel` | Opens a SOCKS5 proxy or a port forward over a connection |
| `close-tunnel` | Closes a tunnel |
| `list-tunnels` | Shows the open tunnels and their connection counters |

`list-ssh-hosts` only appears with `--ssh-config-hosts`, and the tunnel tools are removed by `--disable-tunnels`. There is no `upload` in the list: it is published only with `--enable-upload`.

## Host facts without extra commands

On connect the server takes a snapshot of the machine once: name, addresses, OS, kernel, uptime, disk, memory, process count. All probes are merged behind markers into a single command, so this is one ssh round trip rather than six.

The server caches the result and returns it from `list-servers`:

```
[connected] prod-1 | deploy@10.0.0.5:22 | hostname=prod-1 | os=Linux | updated=2026-08-19T18:14:23Z

Raw JSON:
[{"name":"prod-1","connected":true,"guards":"guards=safe ruleset=2026.08.19 ...",
  "status":{"reachable":true,"osVersion":"Ubuntu 24.04.1 LTS","kernelVersion":"6.8.0-51-generic",
  "uptime":"12 days","diskSpace":{"free":"9.8G","total":"229.6G"},
  "memory":{"free":"5.6G","total":"15.5G"},"processes":{"running":214}}}]
```

So `uname -a`, `df -h`, `free -h` and `uptime` are already answered. The agent calls `list-servers` once and reads the status from there.

The probes go through the guards one by one. With a whitelist in force only the allowed fields remain in the status. A partial status does not mean the host is unreachable.

A command that succeeds without printing anything returns `[exit code] 0` instead of an empty string. A model reads an empty result as an unclear outcome and goes back to check with `echo $?`, which costs another round trip and more tokens.

## Quick start: one server for the whole fleet

The MCP client config:

```json
{
  "mcpServers": {
    "ssh": {
      "command": "npx",
      "args": [
        "-y",
        "@perhamm/ssh-mcp-server",
        "--ssh-config-hosts",
        "--guards-profile", "safe"
      ],
      "env": {
        "SSH_MCP_SUDO_PASSWORD": "..."
      }
    }
  }
}
```

From there the agent works like this:

1. Calls `list-ssh-hosts` and finds the alias it needs, say `prod-master`. The list is truncated for large configs, so the agent passes `filter`: a substring or a pattern such as `prod-*`.
2. Calls `execute-command` with `connectionName: "prod-master"`.
3. The server reads the alias from `~/.ssh/config`, takes `HostName`, `User`, `Port`, `IdentityFile` and `ProxyJump` from it, brings the connection up and runs the command.

The key never leaves the machine: the server reads the file itself and only the path from the SSH config reaches the conversation. When `IdentityFile` is absent, the ssh-agent from `SSH_AUTH_SOCK` is used. An alias without `HostName` connects by its own name, exactly as `ssh` does.

Only an alias declared by its own `Host` block is reachable. A `Host *` block provides defaults, it does not turn an arbitrary name into a reachable host.

The list of aliases can be narrowed:

```json
"args": [
  "-y", "@perhamm/ssh-mcp-server",
  "--ssh-config-hosts",
  "--allowed-hosts", "prod-*,*-stage-*",
  "--ssh-config-file", "/home/user/.ssh/config_work"
]
```

Patterns support `*` and `?`. An alias that matches none of the patterns never gets a connection and the agent receives `SSH_HOST_NOT_ALLOWED`.

## Safe mode and guards

Guards are a versioned ruleset that checks every command before it is sent to the server. The rules live in [`guards/default-guards.json`](guards/default-guards.json) and are updated together with the repository.

### Profiles

| Profile | Behaviour |
|---|---|
| `off` | The profile rules are disabled, only the forbidden core applies. This is the default |
| `safe` | Adds a denial of destructive commands, allows the rest |
| `readonly` | Allows reads and diagnostics only, inherits every denial of `safe` |

```json
"args": ["-y", "@perhamm/ssh-mcp-server", "--ssh-config-hosts", "--guards-profile", "safe"]
```

What `safe` catches beyond the core: `shutdown` and `reboot`, flushing the firewall, stopping sshd and kubelet, `kubectl delete`, `helm uninstall`, `docker system prune`, removing packages, `DROP DATABASE`, `curl | sh`, `git push --force`, truncating logs, unloading kernel modules, interactive editors. The full list with the reasons is in the JSON.

`readonly` additionally requires every part of the command to be on a whitelist: `ls`, `cat`, `grep`, `find`, `ps`, `ss`, `df`, `journalctl`, `systemctl status`, `kubectl get/describe/logs`, `docker ps/logs` and the like. sudo is denied outright in this profile, together with `su`, `doas` and `pkexec`.

### The forbidden core

Some operations never run: not in the `off` profile, not under sudo, not through a custom guards file, not through SFTP behind the back of the command checks. The list lives in the `forbidden` block.

| Category | What is closed |
|---|---|
| Accounts | `useradd`, `usermod`, `userdel`, `groupadd`, `passwd`, `chpasswd`, `chage`, `vipw`, and writes to `/etc/passwd`, `/etc/shadow`, `/etc/group` |
| sudo | Writes to `/etc/sudoers` and `/etc/sudoers.d`, `visudo` |
| Schedules | `crontab` except `crontab -l`, writes to `/etc/cron*`, `/var/spool/cron`, `/etc/anacrontab`, the `at` and `batch` commands |
| systemd | Writing units and timers into `/etc/systemd`, `/lib/systemd`, `/usr/lib/systemd`, `systemctl edit`, `systemd-run` |
| SSH | Editing `/etc/ssh/*`, `~/.ssh/*`, `authorized_keys`, `sshd_config`, and also `ssh-keygen`, `ssh-copy-id`, `ssh-add` |
| Interpreters | `python`, `perl`, `ruby`, `node`, `php`, `lua`, `Rscript` and running a script from a file: `bash /tmp/x.sh`, `sh -s`, `source`. The guards do not read someone else's code, so this whole route is closed |
| Mass deletion | `rm -r` of a top level or a system directory, `rm -r` by glob, `find -delete`, deletion through `xargs rm`, the `--no-preserve-root` flag |
| Disks and secrets | `mkfs`, `wipefs`, `dd of=/dev/`, writes to `/dev/sd*`, a fork bomb, reading `/etc/shadow` and private keys |

Ordinary work still goes through: `crontab -l`, `cat /etc/ssh/sshd_config`, `systemctl restart nginx` and `rm -rf /var/lib/myapp/cache/tmp` all pass. A parseable `bash -c "..."` works too: its contents are checked by the same rules.

The core covers the file tools as well. `download` will not fetch `/etc/shadow` or the contents of `~/.ssh`, and `allowedRemotePaths` cannot allow any of it back. The local side is protected too: `download` will not drop a file into our own `~/.ssh`.

File uploads are off entirely. The `upload` tool is not published until `--enable-upload` is passed, and the `readonly` profile rejects uploads even with that flag.

If the server is needed precisely to create users or edit cron, the core has to be edited in a fork deliberately: there is no flag that lifts it.

### Why a semicolon does not get around it

A command is split on `;`, `|`, `&&`, `||`, `&`, newlines and `$(...)` substitutions, and every part is checked separately. Quoting is honoured while splitting. So `ls; rm -rf /` passes in no profile, even though the whole string starts with an allowed `ls`.

Wrappers are peeled off before the check: `sudo`, `env`, `timeout 5`, `nohup` and assignments such as `LC_ALL=C` do not hide a command from the rules. A script inside `bash -c "..."` is parsed separately and checked by the same rules. Command length is capped at 5000 characters.

Guards cover mistakes made by an agent, not a deliberate bypass. An interpreter carrying arbitrary code, such as `python -c`, is not something the rules can parse. Where a bypass is unacceptable, restrict the rights of the SSH user itself.

### Updating the rules

Three ways to keep the rules current:

1. Merge upstream into your fork. The ruleset file carries a `version` field, and that version shows up in `list-servers` and in the text of every refusal.
2. Keep your own file and point at it with `--guards-file /etc/ssh-mcp/guards.json`. Its rules are added to the built-in ones and the version becomes `2026.08.19+local-1`.
3. Refresh the file on a schedule:

```sh
node scripts/update-guards.js https://example.com/guards.json /etc/ssh-mcp/guards.json
```

The script validates the JSON and compiles every regular expression before it replaces the file. A broken download does not break a working ruleset.

The format of your own file:

```json
{
  "version": "local-1",
  "profiles": {
    "safe": {
      "deny": [
        { "id": "no-ansible", "pattern": "^ansible-playbook\\b", "reason": "deploys run from CI" }
      ]
    }
  }
}
```

A `scope: "command"` field makes a rule check the whole command instead of its parts. That is how the `curl | sh` and SQL rules work. The `forbidden` block of your own file can carry extra denials, but it cannot remove the built-in ones: the lists are merged.

The older `--whitelist` and `--blacklist` are still there and are checked before the guards.

## sudo without the password in the conversation

The sudo password sits in the environment of the server process. The agent passes `sudo: true` and never sees the password itself, neither in the call arguments nor in the output.

```json
{
  "mcpServers": {
    "ssh": {
      "command": "npx",
      "args": ["-y", "@perhamm/ssh-mcp-server", "--ssh-config-hosts", "--guards-profile", "safe"],
      "env": {
        "SSH_MCP_SUDO_PASSWORD": "..."
      }
    }
  }
}
```

The tool call:

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

The command reaches the server as `sudo -S -k -p '' -u root -- /bin/sh -c '<command>'` and the password is written into the stdin of the channel. It never appears on the command line, so it stays out of `ps` and out of the shell history. The pseudo terminal is disabled for such commands, otherwise the tty would echo the input back into the output. As a safety net the password is stripped from the output and from the text of any error.

The name of the variable and of the target user are set by `--sudo-password-env` and `--sudo-user`. An empty variable fails the call with `SUDO_PASSWORD_MISSING` before the connection is even made. The `readonly` profile forbids sudo entirely.

In `shell` mode the password is written on a separate line right after the command, because sudo reads the same stdin as the shell itself. The `-k` flag guarantees that the password is always asked for and that the line is not executed as a command. For sudo the `exec` mode is the better choice.

## Tunnels

`open-tunnel` opens a local listener and pushes the traffic through the SSH connection. Useful when there is no direct route to the services of a cluster but there is one to a node.

SOCKS5 on port 8777:

```json
{
  "tool": "open-tunnel",
  "params": {
    "type": "socks5",
    "localPort": 8777,
    "connectionName": "prod-master"
  }
}
```

Any client then goes through the proxy, with names resolved on the remote side:

```sh
curl --socks5-hostname 127.0.0.1:8777 http://prometheus.monitoring.svc:9090/api/v1/query?query=up
kubectl --request-timeout=30s ... # through HTTPS_PROXY=socks5h://127.0.0.1:8777
```

A single port forward, the equivalent of `ssh -L`:

```json
{
  "tool": "open-tunnel",
  "params": {
    "type": "local",
    "localPort": 15432,
    "remoteHost": "pg-master.internal",
    "remotePort": 5432
  }
}
```

With no `localPort` the system picks the port and returns it in the response. Tunnels live until `close-tunnel`, until the SSH connection drops, or until the server stops.

The limits are set by flags:

| Flag | Default | What it does |
|---|---|---|
| `--tunnel-bind-address` | `127.0.0.1` | The address the tunnels listen on |
| `--allowed-tunnel-ports` | no limit | The list of ports that may be taken |
| `--max-tunnels` | 8 | How many tunnels are held at once |
| `--disable-tunnels` | off | Removes the tunnel tools from the list |

The listener binds to loopback by default. An address wider than loopback opens the proxy into your network, so change it deliberately.

## Host key verification

The server key is checked against `known_hosts` on every connection, including the intermediate hosts of a `ProxyJump` chain. The default mode is `strict`: a host missing from `known_hosts` means a refusal.

| Mode | Behaviour |
|---|---|
| `strict` | The default. We connect only to hosts listed in `known_hosts` |
| `accept-new` | An unknown host is recorded on first connect, a key mismatch is still a refusal |
| `off` | No verification, the upstream behaviour |

`~/.ssh/known_hosts`, `~/.ssh/known_hosts2` and `/etc/ssh/ssh_known_hosts` are consulted, and for an alias carrying `UserKnownHostsFile` the file named in the SSH config. A custom list is given by `--known-hosts-file`. Hashed entries, patterns, the `[host]:port` form and the `@revoked` marker are all understood.

The refusal arrives as `SSH_HOST_KEY_REJECTED` with the fingerprint in the text:

```text
Host key of prod.example.com is not in known_hosts (~/.ssh/known_hosts): ssh-ed25519 SHA256:xxxx.
Verify that fingerprint, add the host to known_hosts, or start the server with --host-key-checking accept-new.
```

A key mismatch is never accepted, in any mode: the server refuses to connect and says that the host was either rebuilt or someone is sitting in the middle.

For the first pass over a fleet it is convenient to run once with `--host-key-checking accept-new` and then go back to `strict`.

## Audit log

Every call is written as a JSON line: the command, the connection, the sudo flag, the guard verdict, the duration, the size of the output. The output itself never reaches the log and the sudo password is stripped.

```json
{"time":"2026-08-19T08:12:44.101Z","pid":8123,"event":"command","result":"blocked","connection":"prod-master","command":"useradd deploy","sudo":true,"code":"COMMAND_VALIDATION_FAILED","reason":"Blocked by the forbidden core ..."}
{"time":"2026-08-19T08:12:51.880Z","pid":8123,"event":"command","result":"ok","connection":"prod-master","command":"systemctl status nginx","sudo":false,"durationMs":412,"bytes":1840}
```

The events written are `connect`, `command`, `download`, `upload`, `tunnel-open`, `tunnel-close` and `host-key`.

By default the file lives in `$XDG_STATE_HOME/ssh-mcp-server/audit.jsonl`, which usually means `~/.local/state/ssh-mcp-server/audit.jsonl`, with mode `0600`.

| Flag | Default | What it does |
|---|---|---|
| `--audit-log <path>` | the XDG state directory | The path to the log, the value `off` disables writing |
| `--audit-max-size <bytes>` | 10485760 | The size at which the file is rotated. `0` disables the built-in rotation |
| `--audit-keep <count>` | 10 | How many gzip archives are kept |

Rotation is built in: once the limit is reached the current file moves to `audit.jsonl.1.gz`, the older archives shift along, and everything beyond `--audit-keep` is removed. Ten archives of 10 MiB each is on the order of a hundred megabytes uncompressed and noticeably less after gzip.

If logrotate already manages the logs, set `--audit-max-size 0` and configure rotation in `copytruncate` mode.

A write failure does not fail the command: the server reports it to stderr once and keeps working.

## Ways to connect

The scenarios below go from simple to complex. In `args` every flag and its value are two separate elements of the array: `"--host", "192.168.1.1"`, not `"--host 192.168.1.1"`.

### Login and password

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

### Private key

```json
"args": [
  "-y", "@perhamm/ssh-mcp-server",
  "--host", "192.168.1.1",
  "--username", "root",
  "--privateKey", "~/.ssh/id_rsa",
  "--passphrase", "pwd123456"
]
```

The passphrase can stay out of the config and live in `SSH_MCP_PASSPHRASE` instead.

### A single alias from `~/.ssh/config`

```json
"args": ["-y", "@perhamm/ssh-mcp-server", "--host", "myserver"]
```

The server reads `HostName`, `Port`, `User`, `IdentityFile` and `ProxyJump` from the `Host myserver` block, including `Include` directives and patterns. Command line flags win: `--port 2222` overrides the port from the config.

### Bastion and ProxyJump

When an alias carries `ProxyJump`, the chain comes up on its own:

```
Host prod-master
    HostName 10.20.30.40
    User ops
    ProxyJump bastion
    IdentityFile ~/.ssh/prod_key
```

Every next hop connects through the channel of the previous one, exactly as `ssh -J` does. The chain can also be given by hand: `--proxy-jump "bastion,gateway:2222"`. Chain depth is capped at five hops.

The form `ProxyCommand ssh bastion -W %h:%p` is read as the equivalent of `ProxyJump bastion`: that is what ssh expands the short form into, and generated configs carry it far more often. The `-l` and `-p` flags of the hop are honoured and `%r` is substituted with the user of the target. Every other `ProxyCommand` is ignored: the server runs no subprocess of its own.

When a host is only reachable through a hop the SSH config does not name, the chain comes from the call itself. `execute-command`, `download` and `open-tunnel` take a `proxyJump` argument that overrides the chain of the config. This is what a generated SSH config needs: editing it is pointless, the next rollout overwrites the edit.

```json
{
  "tool": "execute-command",
  "params": {
    "cmdString": "hostname",
    "connectionName": "legacy-master",
    "proxyJump": "prod-master-0"
  }
}
```

Such a connection lives under a name of its own, `alias via chain`, so one alias reached two different ways stays two connections and shows up as two lines in `list-servers`. Every hop has to be an alias from the config, otherwise the caller could point the server at an arbitrary address. An unknown hop comes back as `SSH_JUMP_NOT_ALLOWED`.

### Proxy

```json
"args": [
  "-y", "@perhamm/ssh-mcp-server",
  "--host", "192.168.1.1",
  "--username", "root",
  "--password", "pwd123456",
  "--proxy", "socks5://user:pwd@proxy-host:1080"
]
```

`socks://`, `socks5://`, `http://` and `https://` are supported. HTTP and HTTPS go through the `CONNECT` method with Basic authentication, on the default ports 80 and 443. For SOCKS5 the port is mandatory. `--proxy` and `--proxy-jump` are not used together.

### A jump host with an interactive shell

`transportMode` is `exec` by default. Switch to `shell` when commands do not run after a successful login, or when the appliance only offers an interactive session:

```json
"args": [
  "-y", "@perhamm/ssh-mcp-server",
  "--host", "bastion.example.com",
  "--username", "ops",
  "--password", "pwd123456",
  "--transport-mode", "shell",
  "--shell-ready-timeout", "15000"
]
```

In `shell` mode commands run one after another through a single persistent session, and `upload` and `download` do not work: SFTP is disabled there.

### Two-factor authentication

The `--try-keyboard` flag enables keyboard-interactive. The password and the key are supplied automatically, and the second factor code is read from `SSH_MCP_2FA_CODE`.

### Several connections in one server

Besides the SSH config aliases the older approach remains: a file describing the connections.

```json
[
  {
    "name": "dev",
    "host": "1.2.3.4",
    "port": 22,
    "username": "alice",
    "privateKey": "~/.ssh/dev_key",
    "guardProfile": "safe",
    "commandTimeoutMs": 120000
  },
  {
    "name": "prod",
    "host": "5.6.7.8",
    "port": 22,
    "username": "bob",
    "privateKey": "~/.ssh/prod_key",
    "guardProfile": "readonly",
    "allowedRemotePaths": ["/var/log", "/tmp"]
  }
]
```

```json
"args": ["-y", "@perhamm/ssh-mcp-server", "--config-file", "/abs/path/ssh-config.json"]
```

The object form, where the key is the connection name, is supported as well. The connection is picked by `connectionName`, and without it the first one is used.

## Command and path restrictions

### Whitelist and blacklist

```json
"args": [
  "-y", "@perhamm/ssh-mcp-server",
  "--host", "192.168.1.1",
  "--username", "root",
  "--privateKey", "~/.ssh/id_rsa",
  "--whitelist", "^ls( .*)?,^cat .*,^df.*",
  "--blacklist", "^rm .*,^shutdown.*"
]
```

The patterns are comma separated regular expressions. A command is checked against the whitelist first, then the blacklist, then the guard profile, and it has to pass all three.

### Command template

`--command-template` wraps every command. `<quotedCommand>` inserts the command as an escaped argument, `<command>` inserts it verbatim. The template is applied after the working directory is substituted.

```
su root -c <quotedCommand>
docker exec -i mycontainer sh -c <quotedCommand>
```

### Paths for file operations

`--allowed-local-paths` extends the list of local directories available to `upload` and `download` (by default only the current directory). `--allowed-remote-paths` restricts the remote paths and takes comma separated absolute POSIX paths. Without that flag SFTP sees the whole filesystem of the host, which the server warns about at startup.

## Timeouts and the output limit

| Setting | Default | What it limits |
|---|---|---|
| `timeout` in the tool call | none | A single command, overrides the connection settings |
| `commandTimeoutMs` | 30000 | A command in `exec` mode |
| `shellCommandTimeoutMs` | 30000 | A command in `shell` mode |
| `connectionTimeoutMs` | 30000 | Establishing the connection and the handshake |
| `sftpTimeoutMs` | 300000 | SFTP operations |
| `maxOutputBytes` | 10485760 | The captured output of one command |
| `keepaliveIntervalMs` | 10000 | The keepalive interval |

Past the output limit the command is aborted and the tool returns `OUTPUT_LIMIT_EXCEEDED` together with the piece already collected. Errors arrive as a structure of `code`, `message` and `retriable`.

## Command line flags

```text
  --config-file <path>             File describing the connections
  --ssh-config-file <path>         Path to the SSH config (defaults to ~/.ssh/config)
  --ssh <config>                   A connection as JSON or as key=value pairs
  -h, --host <host>                Host or SSH config alias
  -p, --port <port>                Port
  -u, --username <name>            User
  -w, --password <password>        Password
  -k, --privateKey <path>          Path to the private key
  -P, --passphrase <passphrase>    Passphrase of the key
  -a, --agent <path>               ssh-agent socket
  -W, --whitelist <patterns>       Command whitelist, comma separated
  -B, --blacklist <patterns>       Command blacklist, comma separated
  --proxy <url>                    SOCKS5, HTTP or HTTPS proxy
  -s, --socksProxy <url>           Legacy flag, SOCKS5 only
  --allowed-local-paths <paths>    Local directories for upload and download
  --allowed-remote-paths <paths>   Remote directories for SFTP
  --transport-mode <mode>          exec or shell (defaults to exec)
  --shell-ready-timeout <ms>       Shell readiness timeout (defaults to 10000)
  --command-template <template>    Template carrying <command> or <quotedCommand>
  --pty                            Pseudo terminal for exec (on by default)
  --try-keyboard                   Keyboard-interactive for 2FA
  --pre-connect                    Connect to every host at startup
  --ssh-config-hosts               Allow SSH config hosts on the fly
  --allowed-hosts <patterns>       Patterns of allowed aliases, comma separated
  --proxy-jump <chain>             ProxyJump chain, comma separated
  --guards-profile <name>          off, safe or readonly (defaults to off)
  --guards-file <path>             A custom ruleset on top of the built-in one
  --sudo-password-env <var>        The variable holding the sudo password
  --sudo-user <user>               The user for sudo (defaults to root)
  --host-key-checking <mode>       strict, accept-new or off (defaults to strict)
  --known-hosts-file <paths>       Custom known_hosts files, comma separated
  --host-key-algorithms <list>     Host key algorithms, comma separated
  --enable-upload                  Publish the upload tool (off by default)
  --audit-log <path|off>           Path to the audit log (defaults to the XDG state directory)
  --audit-max-size <bytes>         Rotation threshold, 0 disables it (defaults to 10485760)
  --audit-keep <count>             How many archives to keep (defaults to 10)
  --disable-tunnels                Remove the tunnel tools
  --tunnel-bind-address <addr>     Address for the tunnels (defaults to 127.0.0.1)
  --allowed-tunnel-ports <ports>   Allowed tunnel ports, comma separated
  --max-tunnels <count>            Limit of simultaneous tunnels (defaults to 8)
  --version, -v                    Package version
  --help                           This help message
```

## Security

- For production turn on `--guards-profile safe`, and `readonly` fits an on-call incident review. With `off` only the forbidden core is left: everything else runs, which the server warns about in the log.
- The key, its passphrase and the sudo password are read from files and from the environment. The MCP client config holds the path to the key, not the key itself.
- Tunnels listen on loopback. SOCKS5 has no authentication, so a proxy on `0.0.0.0` opens the internal network to anyone who can reach the port, and the server warns about it at startup.
- Without `--allowed-remote-paths` SFTP can read and write any path on the host, `~/.ssh/authorized_keys` included.
- The host key is checked against `known_hosts` in `strict` mode. Turning the check off with `--host-key-checking off` is a lab-only move.
- There is no rate limiting.

## Development

```sh
npm install
npm run build
npm test
```

The tests run on the built-in Node.js runner and live in [`test/`](test/).

## Upstream and licence

The project grew out of [classfang/ssh-mcp-server](https://github.com/classfang/ssh-mcp-server) by junki.cn, licensed ISC. The upstream copyright is kept in [LICENSE](LICENSE) along with a link to the original repository.

The guard ruleset is partly built on ideas from [tufantunc/ssh-mcp](https://github.com/tufantunc/ssh-mcp) (MIT).

The package on NPM: [@perhamm/ssh-mcp-server](https://www.npmjs.com/package/@perhamm/ssh-mcp-server).
