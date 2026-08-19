---
name: ssh-mcp-helper
description: Use when the user wants to install, configure or extend an ssh-mcp-server MCP connection ("set up ssh-mcp-server for me", "add an SSH MCP to Cursor/Claude Code", "add another remote host to my MCP", "how do I write the mcp.json for ssh-mcp-server", "give the agent sudo on that box", "open a SOCKS proxy into that cluster"). The skill collects hosts, authentication, guards, sudo and tunnel settings through a short interview and writes the resulting mcpServers JSON into the client's config file.
---

# ssh-mcp-helper

## Overview

Set up `@perhamm/ssh-mcp-server` in an MCP client through an interview instead of hand-edited JSON. The skill never types credentials on the user's behalf: it confirms the authentication method, the connection parameters and the safety policy, then produces an `mcpServers` snippet that can be written straight into the client's config file.

**Core rule:** every enumerable choice (MCP client, authentication method, transport mode, yes/no switches, guard profile) goes through AskUserQuestion. Only values that cannot be enumerated (host, username, key path, password, custom regexes) are asked as free text.

**Second rule:** secrets belong in `env`, not in `args`. The sudo password, the key passphrase and the 2FA code are environment variables of the server process; the key itself is referenced by path.

## When to use

- The user wants to install, configure or extend ssh-mcp-server
- The user wants an SSH MCP in Cursor, Claude Code, Cline or Continue
- The user wants to add a host to an existing `mcpServers` entry
- The user asks how to write the `mcp.json` for ssh-mcp-server
- The user wants the agent to run sudo commands, or to reach a cluster's services through a tunnel

## When not to use

- The user wants to change the ssh-mcp-server source: edit the code, skip the interview
- The user just wants a command run: call the existing ssh-mcp-server tools
- The user asks about the SSH protocol itself: explain, no workflow needed

## Workflow

```dot
digraph ssh_mcp_helper {
    "0. Check the environment" [shape=box];
    "1. Pick the MCP client" [shape=box];
    "2. Fleet or single host" [shape=diamond];
    "3. Pick authentication" [shape=box];
    "4. Collect connection parameters" [shape=box];
    "5. Safety: guards, sudo, paths" [shape=box];
    "6. Tunnels" [shape=box];
    "7. Build the JSON snippet" [shape=box];
    "8. Merge into the config" [shape=box];
    "9. Restart and verify" [shape=doublecircle];

    "0. Check the environment" -> "1. Pick the MCP client";
    "1. Pick the MCP client" -> "2. Fleet or single host";
    "2. Fleet or single host" -> "3. Pick authentication" [label="single host"];
    "2. Fleet or single host" -> "5. Safety: guards, sudo, paths" [label="fleet via ~/.ssh/config"];
    "3. Pick authentication" -> "4. Collect connection parameters";
    "4. Collect connection parameters" -> "5. Safety: guards, sudo, paths";
    "5. Safety: guards, sudo, paths" -> "6. Tunnels";
    "6. Tunnels" -> "7. Build the JSON snippet";
    "7. Build the JSON snippet" -> "8. Merge into the config";
    "8. Merge into the config" -> "9. Restart and verify";
}
```

### Step 0: check the environment

- Run `node -v` and `npx --version`; Node.js v18 or newer is required
- If `~/.ssh/config` exists, read the host aliases out of it: they decide whether step 2 has a fleet option worth offering
- Missing Node.js means the user installs it first

### Step 1: pick the MCP client (AskUserQuestion)

| Client | Default config location |
|---|---|
| Claude Code (global) | `mcpServers` in `~/.claude.json` |
| Claude Code (project) | `.mcp.json` in the project root |
| Cursor | `~/.cursor/mcp.json` |
| Cline / Continue / other | ask for the path |

### Step 2: fleet or single host (AskUserQuestion)

- **Fleet from `~/.ssh/config` (recommended when the user has aliases):** one server, `--ssh-config-hosts`, no host in the config at all. The agent calls `list-ssh-hosts` and passes an alias as `connectionName`. Offer `--allowed-hosts` to restrict which aliases are reachable, and confirm the pattern list with the user.
- **Single host:** the classic `--host` / `--port` / `--username` set.
- **Several fixed hosts:** write `ssh-config.json` and pass `--config-file`.

Aliases with a `ProxyJump` work in fleet mode without extra settings; the chain is followed automatically. A jump host that is not in the SSH config is passed as `--proxy-jump "bastion,gateway:2222"`.

### Step 3: pick authentication (AskUserQuestion)

- `ssh-config` - reuse an alias from `~/.ssh/config` (only `--host <alias>`, optionally `--ssh-config-file`)
- `privateKey` - username plus key path; ask separately whether there is a passphrase, and put it in `SSH_MCP_PASSPHRASE` rather than in `args`
- `ssh-agent` - `--agent` pointing at the socket, or nothing at all when `SSH_AUTH_SOCK` is set
- `password` - username plus password
- `2fa` - password plus key plus `--try-keyboard`, with the code in `SSH_MCP_2FA_CODE`

In fleet mode authentication comes from the SSH config: `IdentityFile` first, the agent socket as the fallback. Do not ask for a password there.

### Step 4: connection parameters (free text)

- host / port / username, `--port` can be omitted when it is 22
- whatever step 3 implies: key path, agent socket, and so on

### Step 5: safety (AskUserQuestion per item)

1. Guard profile: `safe` (recommended for anything that touches production), `readonly` (incident triage, read-only), `off` (profile rules disabled). Passed as `--guards-profile`.
   Whatever the answer, tell the user what the forbidden core already blocks and that no profile, no sudo and no SFTP call gets around it: account management (`useradd`, `passwd`, ...), writes to `/etc/sudoers*`, `/etc/cron*`, `/var/spool/cron` and systemd unit directories, `crontab` other than `crontab -l`, `at`, edits of `/etc/ssh/*`, `~/.ssh/*` and `authorized_keys`, `ssh-keygen`, mass deletion (`rm -r` of a top-level or system directory, wildcards, `find -delete`, `xargs rm`), disk destruction and reads of private keys. If the user needs one of those from the agent, the answer is to edit the fork's ruleset deliberately, not to look for a flag.
2. Custom ruleset: if the user maintains one, add `--guards-file <abs path>`; its rules are merged on top of the bundled ones.
3. Uploads: the `upload` tool is not published unless `--enable-upload` is passed. Offer it only when the user actually needs to place files, and say why it is off: a file the guards cannot read can be run afterwards. `readonly` refuses uploads even with the flag.
4. Audit log: on by default in the XDG state directory, rotated at 10 MiB with 10 gzipped archives. Offer `--audit-log <path>` when the user has a place for it, `--audit-max-size 0` when logrotate owns the file, `--audit-log off` only if they insist.
5. sudo: if the agent needs elevation, put the password into `env.SSH_MCP_SUDO_PASSWORD` and tell the user that the agent asks for it with `sudo: true` and never sees the value. `--sudo-user` when the target is not root. `readonly` blocks sudo, so those two answers conflict and the user has to pick one.
6. Command whitelist and blacklist: still available through `--whitelist` and `--blacklist`, checked before the guards.
7. Command template: `--command-template` with a `<quotedCommand>` or `<command>` placeholder.
8. Transport mode: `exec` by default; `shell` for a bastion or a device that only offers an interactive shell, together with `--shell-ready-timeout`. Note that `shell` disables SFTP and is a worse fit for sudo.
9. Path limits: `--allowed-local-paths` and `--allowed-remote-paths`. Recommend the remote one whenever download or upload will be used.
10. Host key checking: `strict` by default, which refuses any host missing from `known_hosts`. If the user has not connected to those hosts with `ssh` before, offer a one-off `--host-key-checking accept-new` for onboarding and tell them to drop back to `strict`. `--known-hosts-file` points at a custom list.
11. Pre-connect at startup: `--pre-connect`.
12. Host key algorithms: Ed25519 comes first by default and SHA-1, CBC and DSA are gone. `--host-key-algorithms ssh-ed25519` pins the list for a fleet that is fully on Ed25519.

### Step 6: tunnels (AskUserQuestion)

Tunnels are on by default and bound to `127.0.0.1`. Ask only what changes that:

- Fixed ports the user wants to reserve: `--allowed-tunnel-ports 8777,9050`
- A bind address wider than loopback: `--tunnel-bind-address`, and say plainly that this exposes the proxy to the network
- No tunnels at all: `--disable-tunnels`

Tell the user how the SOCKS5 tunnel is consumed once open: `curl --socks5-hostname 127.0.0.1:8777 http://service.internal/`, or `HTTPS_PROXY=socks5h://127.0.0.1:8777` for tools that read the environment.

### Step 7: build the JSON snippet

- `command` is always `"npx"`
- `args` starts with `"-y"` and `"@perhamm/ssh-mcp-server"`
- **Every flag and its value are two separate elements of `args`**, never `"--host 192.168.1.1"`
- Secrets go into `env`, not into `args`
- Several fixed hosts go into `ssh-config.json` (array or object form) and the client config only carries `--config-file <abs path>`

### Step 8: merge into the config

- Read the target JSON file first
- Merge into the existing `mcpServers`; if the key already exists, use AskUserQuestion to choose overwrite, rename or cancel
- Show the final snippet before writing
- Print the absolute path of the file that was written

### Step 9: wrap up

- The user restarts the MCP client
- Verification: call `list-servers`, or `list-ssh-hosts` in fleet mode, then run `execute-command` with `whoami`
- If sudo was configured, verify it with `execute-command` `id` and `sudo: true`
- After an upgrade, say plainly that the MCP client has to restart the server before the new version is in play

## Using a configured server

The interview is only half the job. Once the server is running, these are the habits that keep an agent from burning a context window on a machine it has already been told about.

**Read the host facts instead of collecting them.** On every connection the server runs one command that gathers hostname, IP addresses, OS name and version, kernel, uptime, disk, memory and a process count, all probes merged behind markers into a single ssh round trip. The result is cached and returned by `list-servers`:

```
[connected] prod-1 | deploy@10.0.0.5:22 | hostname=prod-1 | os=Linux | updated=2026-08-19T18:14:23Z

Raw JSON:
[{"name":"prod-1","connected":true,"guards":"guards=safe ruleset=2026.08.19 ...",
  "status":{"reachable":true,"osVersion":"Ubuntu 24.04.1 LTS","kernelVersion":"6.8.0-51-generic",
  "uptime":"12 days","diskSpace":{"free":"9.8G","total":"229.6G"},
  "memory":{"free":"5.6G","total":"15.5G"},"processes":{"running":214}}}]
```

So `uname -a`, `df -h`, `free -h`, `uptime` and `hostname -I` are already answered before the first `execute-command`. Call `list-servers` once and read them from there.

**Trust the exit code.** A command that succeeds without printing anything returns `[exit code] 0`, not an empty string. There is no reason to follow `mkdir -p` or `systemctl restart` with `echo $?`.

**Read the failure, do not re-run it.** A non-zero exit comes back with `isError: true` and a JSON body carrying `code`, `message` and `retriable`. The message already holds stderr and `[exit code] N`. Only `retriable: true` is worth a second attempt.

**Refusals are not failures.** `COMMAND_VALIDATION_FAILED` names the rule and the blocked fragment. The forbidden core is not overridable by sudo, by a profile or by a custom ruleset, so rephrasing the command is wasted effort. Report the refusal and ask the user how to proceed.

**The guard profile is visible.** `list-servers` reports `guards=safe ruleset=... allow=N deny=N forbidden=N sudo=allowed upload=allowed` per connection. Read it before planning a chain of commands rather than discovering the limits one refusal at a time.

**A host behind an unnamed bastion.** `SSH_CONNECTION_TIMEOUT` on an alias that `list-ssh-hosts` does list usually means the route, not the host: part of a fleet sits behind a hop the SSH config does not name. Pass `proxyJump` on the call itself, naming hops that `list-ssh-hosts` shows. Do not edit the user's `~/.ssh/config` to fix this, it is generated more often than not.

**A tool on a node is not always on PATH.** `command not found` from a host that clearly runs the thing usually means the binary sits outside PATH, and sudo sanitises PATH further. Look for it before reporting it as absent, and call it by absolute path once found. The same goes for a config the tool needs: a cluster admin kubeconfig is normally root-only, so it is read under sudo and passed explicitly.

**`Unauthorized` is not `no access`.** A personal credential on a host can simply have expired. That is a different problem from having no route to the API at all, and it is often solved by falling back to the administrative credential under sudo rather than by giving up.

**`SUDO_PASSWORD_MISSING` is not retryable.** It means the environment variable named by `--sudo-password-env` is absent from the environment of the MCP server process, not that the password is wrong. Nothing the agent does over SSH can fix it: the variable has to reach the server process, either from the environment the MCP client was started in or from the `env` block of its config. Say that and stop, do not retry.

**Take the route that needs no credentials.** Before reaching for a production password, ask whether the question has an answer that does not need one. The size of a database is on disk and can be read with `du` over its data directory, without a single query against a live server and without touching a secret. Least privilege is also the cheapest and the safest path, not a compromise.

**A refusal from the host policy is not a puzzle to solve.** A call blocked by the MCP client's own permission layer, as opposed to by the guards of this server, is a decision made by the user's setup. Do not rephrase the command to slip past it. Report what was blocked, why it was needed, and what the alternative is.

**Probes obey the guards.** With a whitelist in force, only the allowed probes run, so `status` may be partial. Partial status still means the host is reachable; it is not a connection problem.

## Cheat sheet

| Scenario | Key flags |
|---|---|
| Whole fleet from `~/.ssh/config` | `--ssh-config-hosts [--allowed-hosts "prod-*"] [--ssh-config-file <path>]` |
| Single alias from the SSH config | `--host <alias>` |
| Username and password | `--host --port --username --password` |
| Private key | `--host --port --username --privateKey` plus `SSH_MCP_PASSPHRASE` in `env` |
| ssh-agent | `--agent /path/to/socket` (or nothing when `SSH_AUTH_SOCK` is set) |
| Bastion from the SSH config | nothing: `ProxyJump` is followed automatically |
| Bastion given by hand | `--proxy-jump "bastion,gateway:2222"` |
| Bastion for one call only | `proxyJump` argument of `execute-command`, `download`, `open-tunnel` |
| SOCKS or HTTP proxy | `--proxy socks5://user:pwd@host:1080` |
| Interactive-only jump host | `--transport-mode shell --shell-ready-timeout 15000` |
| Several fixed hosts | `--config-file /abs/path/ssh-config.json` |
| 2FA / MFA | `--try-keyboard` plus `SSH_MCP_2FA_CODE` in `env` |
| Production guards | `--guards-profile safe` |
| Never-allowed operations | forbidden core, always on, no flag |
| File uploads | `--enable-upload` (off by default) |
| Audit log | on by default, `--audit-log <path|off>`, `--audit-max-size`, `--audit-keep` |
| Pin host key algorithms | `--host-key-algorithms ssh-ed25519` |
| Read-only guards | `--guards-profile readonly` |
| Local ruleset | `--guards-file /etc/ssh-mcp/guards.json` |
| sudo | `SSH_MCP_SUDO_PASSWORD` in `env`, optionally `--sudo-user` |
| Reserved tunnel ports | `--allowed-tunnel-ports 8777` |
| No tunnels | `--disable-tunnels` |
| Host key checking | `--host-key-checking strict` (default), `accept-new`, `off` |
| Custom known_hosts | `--known-hosts-file /path/to/known_hosts` |
| Command whitelist | `--whitelist "^ls( .*)?,^cat .*"` |
| Command blacklist | `--blacklist "^rm .*,^shutdown.*"` |
| Command template | `--command-template "su root -c <quotedCommand>"` |
| Path limits | `--allowed-local-paths` / `--allowed-remote-paths` |

## Common mistakes

- Writing `"--host 192.168.1.1"` as one `args` element. Split it into `"--host", "192.168.1.1"`.
- Putting the sudo password, the passphrase or the 2FA code into `args`. They belong in `env`, otherwise they show up in the process list.
- Pasting the private key itself into the config. The config holds the path; the key stays on disk.
- Pointing at production with `--guards-profile off` and no whitelist. Say out loud what that means before writing it: only the forbidden core is left.
- Promising the user that sudo or a custom guards file will let the agent add a user or install a cron job. It will not; the forbidden core is not overridable.
- Planning a workflow around `python -c` or around uploading a script and running it. Interpreters are in the forbidden core and uploads are off by default.
- Combining `readonly` with sudo. The profile refuses every escalation, so the pair is a contradiction.
- Combining `--proxy` with `--proxy-jump`. The server rejects that configuration.
- Expecting `upload` or `download` in `shell` mode. SFTP is disabled there, switch back to `exec`.
- Overwriting an existing `mcpServers` key. Read, merge, and confirm before writing.
- Binding tunnels to `0.0.0.0` without saying what it opens up: the SOCKS proxy has no authentication.
- Blaming a first connection failure on the credentials when the real answer is `SSH_HOST_KEY_REJECTED`: the host is simply not in `known_hosts` yet.
- Registering the server as `npx -y @perhamm/ssh-mcp-server` for a user who works inside a checkout of that same package. The MCP client starts the server with the project as its working directory, npm sees a local `package.json` of the same name, resolves the bin locally and fails with `command not found`; the client reports a closed connection. Install the package globally and register it by command name.
- Leaving the version unpinned for a server that reaches a whole fleet over SSH. `@latest` pulls a new build silently on a tool that holds production access.
- Promising that a fresh release takes effect right away. The MCP client holds one long-lived server process, so upgrading the package changes nothing until the client restarts it.
- Editing the user's `~/.ssh/config` to add a route. It is generated by tooling more often than not, the edit is lost on the next run, and the same job is done by the `proxyJump` argument of the call.

## Output examples

Fleet mode with guards and sudo, the recommended default:

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
        "--guards-profile", "safe",
        "--allowed-tunnel-ports", "8777"
      ],
      "env": {
        "SSH_MCP_SUDO_PASSWORD": "..."
      }
    }
  }
}
```

Single host with a key and a whitelist:

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
        "--guards-profile", "safe",
        "--whitelist", "^ls( .*)?,^cat .*"
      ],
      "env": {
        "SSH_MCP_PASSPHRASE": "..."
      }
    }
  }
}
```

Several fixed hosts:

```json
{
  "mcpServers": {
    "ssh-mcp-server": {
      "command": "npx",
      "args": ["-y", "@perhamm/ssh-mcp-server", "--config-file", "/abs/path/ssh-config.json"]
    }
  }
}
```
