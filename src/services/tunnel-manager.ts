import net from "node:net";
import type { Duplex } from "node:stream";
import { AuditLog } from "../utils/audit-log.js";
import { Logger } from "../utils/logger.js";
import { ToolError } from "../utils/tool-error.js";

export type TunnelType = "socks5" | "local";

/**
 * The subset of the ssh2 client the tunnels need. Keeping it to the one method
 * that matters lets the forwarding logic be exercised without an SSH server.
 */
export interface SshForwarder {
  forwardOut(
    srcIP: string,
    srcPort: number,
    dstIP: string,
    dstPort: number,
    callback: (err: Error | undefined, stream: Duplex) => void,
  ): void;
}

export type ForwarderProvider = (
  connectionName?: string,
) => Promise<SshForwarder>;

export interface TunnelPolicy {
  enabled: boolean;
  bindAddress: string;
  allowedPorts?: number[];
  maxTunnels: number;
}

export interface OpenTunnelOptions {
  type: TunnelType;
  connectionName?: string;
  localPort?: number;
  remoteHost?: string;
  remotePort?: number;
}

export interface TunnelInfo {
  id: string;
  type: TunnelType;
  connectionName: string;
  bindAddress: string;
  localPort: number;
  remoteHost?: string;
  remotePort?: number;
  activeStreams: number;
  totalStreams: number;
  failedStreams: number;
  createdAt: string;
}

interface Tunnel extends TunnelInfo {
  server: net.Server;
  sockets: Set<net.Socket>;
}

export const DEFAULT_TUNNEL_POLICY: TunnelPolicy = {
  enabled: true,
  bindAddress: "127.0.0.1",
  maxTunnels: 8,
};

const SOCKS_VERSION = 5;
const SOCKS_CMD_CONNECT = 1;
const SOCKS_REPLY_SUCCESS = 0x00;
const SOCKS_REPLY_GENERAL_FAILURE = 0x01;
const SOCKS_REPLY_HOST_UNREACHABLE = 0x04;
const SOCKS_REPLY_COMMAND_NOT_SUPPORTED = 0x07;
const SOCKS_REPLY_ADDRESS_NOT_SUPPORTED = 0x08;
const SOCKS_HANDSHAKE_MAX_BYTES = 4096;
const SOCKS_HANDSHAKE_TIMEOUT_MS = 10000;

export class TunnelManager {
  private static instance: TunnelManager;
  private tunnels: Map<string, Tunnel> = new Map();
  private policy: TunnelPolicy = DEFAULT_TUNNEL_POLICY;
  private audit = AuditLog.getInstance();
  private forwarderProvider?: ForwarderProvider;

  private constructor() {}

  public static getInstance(): TunnelManager {
    if (!TunnelManager.instance) {
      TunnelManager.instance = new TunnelManager();
    }
    return TunnelManager.instance;
  }

  public configure(policy: TunnelPolicy, provider: ForwarderProvider): void {
    this.policy = policy;
    this.forwarderProvider = provider;
  }

  public getPolicy(): TunnelPolicy {
    return this.policy;
  }

  public async openTunnel(options: OpenTunnelOptions): Promise<TunnelInfo> {
    if (!this.policy.enabled) {
      throw new ToolError(
        "TUNNEL_DISABLED",
        "Tunnels are disabled on this server (--disable-tunnels)",
        false,
      );
    }

    if (!this.forwarderProvider) {
      throw new ToolError(
        "TUNNEL_NOT_CONFIGURED",
        "Tunnel manager has no SSH connection provider",
        false,
      );
    }

    if (this.tunnels.size >= this.policy.maxTunnels) {
      throw new ToolError(
        "TUNNEL_LIMIT_REACHED",
        `Tunnel limit reached (${this.policy.maxTunnels}); close a tunnel before opening another`,
        false,
      );
    }

    const requestedPort = options.localPort ?? 0;
    this.validatePort(requestedPort);

    if (options.type === "local") {
      if (!options.remoteHost || !options.remotePort) {
        throw new ToolError(
          "TUNNEL_INVALID_TARGET",
          "A local forward requires remoteHost and remotePort",
          false,
        );
      }
    }

    // Fail before binding a local port if the SSH connection cannot be used.
    const connectionName = options.connectionName;
    await this.forwarderProvider(connectionName);

    const server = net.createServer();
    const tunnel: Tunnel = {
      id: "",
      type: options.type,
      connectionName: connectionName || "default",
      bindAddress: this.policy.bindAddress,
      localPort: requestedPort,
      remoteHost: options.remoteHost,
      remotePort: options.remotePort,
      activeStreams: 0,
      totalStreams: 0,
      failedStreams: 0,
      createdAt: new Date().toISOString(),
      server,
      sockets: new Set(),
    };

    server.on("connection", (socket) => {
      tunnel.sockets.add(socket);
      socket.on("close", () => tunnel.sockets.delete(socket));
      socket.on("error", () => socket.destroy());

      if (tunnel.type === "socks5") {
        this.handleSocksConnection(tunnel, socket);
      } else {
        void this.forwardSocket(
          tunnel,
          socket,
          tunnel.remoteHost as string,
          tunnel.remotePort as number,
        );
      }
    });

    await new Promise<void>((resolve, reject) => {
      const onError = (error: Error) => {
        server.removeListener("listening", onListening);
        reject(
          new ToolError(
            "TUNNEL_BIND_FAILED",
            `Failed to bind ${this.policy.bindAddress}:${requestedPort}: ${error.message}`,
            false,
          ),
        );
      };
      const onListening = () => {
        server.removeListener("error", onError);
        resolve();
      };
      server.once("error", onError);
      server.once("listening", onListening);
      server.listen(requestedPort, this.policy.bindAddress);
    });

    const address = server.address();
    tunnel.localPort =
      typeof address === "object" && address ? address.port : requestedPort;
    tunnel.id = `${tunnel.type}-${tunnel.localPort}`;

    server.on("error", (error) => {
      Logger.log(`Tunnel ${tunnel.id} error: ${error.message}`, "error");
    });

    this.tunnels.set(tunnel.id, tunnel);
    this.audit.record({
      event: "tunnel-open",
      result: "ok",
      connection: tunnel.connectionName,
      tunnel: tunnel.id,
      host: tunnel.remoteHost,
      port: tunnel.remotePort,
    });
    Logger.log(
      `Opened ${tunnel.type} tunnel ${tunnel.id} on ${tunnel.bindAddress}:${tunnel.localPort} via [${tunnel.connectionName}]`,
      "info",
    );

    return this.toInfo(tunnel);
  }

  public closeTunnel(id: string): boolean {
    const tunnel = this.tunnels.get(id);
    if (!tunnel) {
      return false;
    }

    this.destroyTunnel(tunnel);
    this.tunnels.delete(id);
    this.audit.record({
      event: "tunnel-close",
      result: "ok",
      connection: tunnel.connectionName,
      tunnel: id,
    });
    Logger.log(`Closed tunnel ${id}`, "info");
    return true;
  }

  public closeForConnection(connectionName: string): void {
    for (const [id, tunnel] of this.tunnels) {
      if (tunnel.connectionName === connectionName) {
        this.destroyTunnel(tunnel);
        this.tunnels.delete(id);
        Logger.log(
          `Closed tunnel ${id}: SSH connection [${connectionName}] went away`,
          "info",
        );
      }
    }
  }

  public closeAll(): void {
    for (const [id, tunnel] of this.tunnels) {
      this.destroyTunnel(tunnel);
      this.tunnels.delete(id);
    }
  }

  public list(): TunnelInfo[] {
    return Array.from(this.tunnels.values()).map((tunnel) =>
      this.toInfo(tunnel),
    );
  }

  private toInfo(tunnel: Tunnel): TunnelInfo {
    const { server, sockets, ...info } = tunnel;
    return { ...info };
  }

  private destroyTunnel(tunnel: Tunnel): void {
    for (const socket of tunnel.sockets) {
      socket.destroy();
    }
    tunnel.sockets.clear();
    try {
      tunnel.server.close();
    } catch {
      // Ignore close errors: the listener is being discarded anyway.
    }
  }

  private validatePort(port: number): void {
    if (!Number.isInteger(port) || port < 0 || port > 65535) {
      throw new ToolError(
        "TUNNEL_INVALID_PORT",
        `localPort must be between 0 and 65535, got: ${port}`,
        false,
      );
    }

    const allowedPorts = this.policy.allowedPorts;
    if (!allowedPorts || allowedPorts.length === 0) {
      return;
    }

    if (port === 0) {
      throw new ToolError(
        "TUNNEL_PORT_NOT_ALLOWED",
        `This server only binds the configured tunnel ports: ${allowedPorts.join(", ")}. Ask for one of them explicitly.`,
        false,
      );
    }

    if (!allowedPorts.includes(port)) {
      throw new ToolError(
        "TUNNEL_PORT_NOT_ALLOWED",
        `Port ${port} is not in the allowed tunnel ports: ${allowedPorts.join(", ")}`,
        false,
      );
    }
  }

  private async forwardSocket(
    tunnel: Tunnel,
    socket: net.Socket,
    remoteHost: string,
    remotePort: number,
    onReady?: (stream: Duplex) => void,
    onFailure?: (error: Error) => void,
  ): Promise<void> {
    try {
      const forwarder = await (this.forwarderProvider as ForwarderProvider)(
        tunnel.connectionName,
      );

      const stream = await new Promise<Duplex>((resolve, reject) => {
        forwarder.forwardOut(
          socket.remoteAddress || "127.0.0.1",
          socket.remotePort || 0,
          remoteHost,
          remotePort,
          (err, forwarded) => (err ? reject(err) : resolve(forwarded)),
        );
      });

      tunnel.totalStreams++;
      tunnel.activeStreams++;

      const done = () => {
        tunnel.activeStreams = Math.max(0, tunnel.activeStreams - 1);
      };

      stream.once("close", done);
      stream.on("error", () => socket.destroy());
      socket.on("close", () => stream.destroy());

      onReady?.(stream);
      socket.pipe(stream).pipe(socket);
    } catch (error) {
      tunnel.failedStreams++;
      Logger.log(
        `Tunnel ${tunnel.id} failed to reach ${remoteHost}:${remotePort}: ${
          (error as Error).message
        }`,
        "error",
      );
      if (onFailure) {
        onFailure(error as Error);
      } else {
        socket.destroy();
      }
    }
  }

  /**
   * Minimal SOCKS5 server: no authentication, CONNECT only, IPv4, IPv6 and
   * domain targets. Names are resolved on the remote side, so `curl
   * --socks5-hostname` reaches hosts that only exist in the cluster's DNS.
   */
  private handleSocksConnection(tunnel: Tunnel, socket: net.Socket): void {
    let stage: "greeting" | "request" | "streaming" = "greeting";
    let buffer = Buffer.alloc(0);

    // A client that connects and says nothing would otherwise hold the socket
    // open for as long as the tunnel lives.
    const handshakeTimeout = setTimeout(() => {
      if (stage !== "streaming") {
        socket.destroy();
      }
    }, SOCKS_HANDSHAKE_TIMEOUT_MS);
    handshakeTimeout.unref();
    socket.once("close", () => clearTimeout(handshakeTimeout));

    const onData = (chunk: Buffer) => {
      if (stage === "streaming") {
        return;
      }

      buffer = Buffer.concat([buffer, chunk]);
      if (buffer.length > SOCKS_HANDSHAKE_MAX_BYTES) {
        socket.destroy();
        return;
      }

      if (stage === "greeting") {
        if (buffer.length < 2) {
          return;
        }
        if (buffer[0] !== SOCKS_VERSION) {
          socket.destroy();
          return;
        }
        const methodCount = buffer[1];
        if (buffer.length < 2 + methodCount) {
          return;
        }
        buffer = buffer.subarray(2 + methodCount);
        stage = "request";
        socket.write(Buffer.from([SOCKS_VERSION, 0x00]));
      }

      if (stage === "request") {
        const request = parseSocksRequest(buffer);
        if (request === "incomplete") {
          return;
        }
        if (request === "invalid") {
          writeSocksReply(socket, SOCKS_REPLY_ADDRESS_NOT_SUPPORTED);
          socket.destroy();
          return;
        }
        if (request.command !== SOCKS_CMD_CONNECT) {
          writeSocksReply(socket, SOCKS_REPLY_COMMAND_NOT_SUPPORTED);
          socket.destroy();
          return;
        }

        stage = "streaming";
        clearTimeout(handshakeTimeout);
        socket.removeListener("data", onData);
        const pending = buffer.subarray(request.length);
        buffer = Buffer.alloc(0);

        void this.forwardSocket(
          tunnel,
          socket,
          request.host,
          request.port,
          (stream) => {
            writeSocksReply(socket, SOCKS_REPLY_SUCCESS);
            if (pending.length > 0) {
              stream.write(pending);
            }
          },
          (error) => {
            writeSocksReply(
              socket,
              /refused|unreachable|not found/i.test(error.message)
                ? SOCKS_REPLY_HOST_UNREACHABLE
                : SOCKS_REPLY_GENERAL_FAILURE,
            );
            socket.destroy();
          },
        );
      }
    };

    socket.on("data", onData);
  }
}

type ParsedSocksRequest =
  | { command: number; host: string; port: number; length: number }
  | "incomplete"
  | "invalid";

export function parseSocksRequest(buffer: Buffer): ParsedSocksRequest {
  if (buffer.length < 4) {
    return "incomplete";
  }
  if (buffer[0] !== SOCKS_VERSION) {
    return "invalid";
  }

  const command = buffer[1];
  const addressType = buffer[3];
  let host: string;
  let offset: number;

  if (addressType === 0x01) {
    if (buffer.length < 10) {
      return "incomplete";
    }
    host = Array.from(buffer.subarray(4, 8)).join(".");
    offset = 8;
  } else if (addressType === 0x03) {
    const hostLength = buffer[4];
    if (buffer.length < 5 + hostLength + 2) {
      return "incomplete";
    }
    host = buffer.subarray(5, 5 + hostLength).toString("utf8");
    offset = 5 + hostLength;
  } else if (addressType === 0x04) {
    if (buffer.length < 22) {
      return "incomplete";
    }
    const groups: string[] = [];
    for (let index = 4; index < 20; index += 2) {
      groups.push(buffer.readUInt16BE(index).toString(16));
    }
    host = groups.join(":");
    offset = 20;
  } else {
    return "invalid";
  }

  return {
    command,
    host,
    port: buffer.readUInt16BE(offset),
    length: offset + 2,
  };
}

function writeSocksReply(socket: net.Socket, reply: number): void {
  socket.write(
    Buffer.from([SOCKS_VERSION, reply, 0x00, 0x01, 0, 0, 0, 0, 0, 0]),
  );
}
