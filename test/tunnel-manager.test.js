import { describe, it, before, after, beforeEach } from 'node:test';
import assert from 'node:assert';
import net from 'node:net';
import { TunnelManager, parseSocksRequest } from '../build/services/tunnel-manager.js';

const LOOPBACK_POLICY = {
  enabled: true,
  bindAddress: '127.0.0.1',
  maxTunnels: 4,
};

/**
 * Stands in for the SSH client: every forwarded channel is a plain TCP
 * connection to the echo server, which is what an ssh2 channel behaves like.
 */
function createLocalForwarder() {
  return {
    forwardOut(srcIP, srcPort, dstIP, dstPort, callback) {
      let settled = false;
      const socket = net.connect(dstPort, dstIP === 'localhost' ? '127.0.0.1' : dstIP);
      socket.once('connect', () => {
        settled = true;
        callback(undefined, socket);
      });
      socket.once('error', (error) => {
        if (!settled) {
          settled = true;
          callback(error);
        }
      });
    },
  };
}

function socksRequest(port, host, targetPort, payload) {
  return new Promise((resolve, reject) => {
    const client = net.connect(port, '127.0.0.1');
    const chunks = [];
    let stage = 'greeting';

    client.on('error', reject);
    client.on('connect', () => client.write(Buffer.from([0x05, 0x01, 0x00])));
    client.on('data', (chunk) => {
      if (stage === 'greeting') {
        assert.deepStrictEqual([...chunk.subarray(0, 2)], [0x05, 0x00]);
        stage = 'request';
        const hostBuffer = Buffer.from(host, 'utf8');
        const request = Buffer.concat([
          Buffer.from([0x05, 0x01, 0x00, 0x03, hostBuffer.length]),
          hostBuffer,
          Buffer.from([targetPort >> 8, targetPort & 0xff]),
        ]);
        client.write(request);
        return;
      }

      if (stage === 'request') {
        if (chunk[1] !== 0x00) {
          client.destroy();
          reject(new Error(`SOCKS reply ${chunk[1]}`));
          return;
        }
        stage = 'streaming';
        const rest = chunk.subarray(10);
        if (rest.length > 0) {
          chunks.push(rest);
        }
        client.write(payload);
        return;
      }

      chunks.push(chunk);
      client.end();
    });

    client.on('close', () => resolve(Buffer.concat(chunks).toString('utf8')));
  });
}

function plainRequest(port, payload) {
  return new Promise((resolve, reject) => {
    const client = net.connect(port, '127.0.0.1');
    const chunks = [];
    client.on('error', reject);
    client.on('connect', () => client.write(payload));
    client.on('data', (chunk) => {
      chunks.push(chunk);
      client.end();
    });
    client.on('close', () => resolve(Buffer.concat(chunks).toString('utf8')));
  });
}

describe('SOCKS request parsing', () => {
  it('reports an incomplete request', () => {
    assert.strictEqual(parseSocksRequest(Buffer.from([0x05, 0x01])), 'incomplete');
    assert.strictEqual(
      parseSocksRequest(Buffer.from([0x05, 0x01, 0x00, 0x01, 10, 0, 0])),
      'incomplete',
    );
  });

  it('parses an IPv4 target', () => {
    const request = parseSocksRequest(
      Buffer.from([0x05, 0x01, 0x00, 0x01, 10, 0, 0, 7, 0x1f, 0x90]),
    );

    assert.strictEqual(request.host, '10.0.0.7');
    assert.strictEqual(request.port, 8080);
    assert.strictEqual(request.command, 1);
    assert.strictEqual(request.length, 10);
  });

  it('parses a domain target', () => {
    const host = Buffer.from('svc.internal', 'utf8');
    const request = parseSocksRequest(
      Buffer.concat([
        Buffer.from([0x05, 0x01, 0x00, 0x03, host.length]),
        host,
        Buffer.from([0x00, 0x50]),
      ]),
    );

    assert.strictEqual(request.host, 'svc.internal');
    assert.strictEqual(request.port, 80);
  });

  it('rejects an unknown address type', () => {
    assert.strictEqual(
      parseSocksRequest(Buffer.from([0x05, 0x01, 0x00, 0x09, 1, 2, 3, 4, 5, 6])),
      'invalid',
    );
  });
});

describe('TunnelManager', () => {
  let echoServer;
  let echoPort;
  let manager;

  before(async () => {
    echoServer = net.createServer((socket) => socket.pipe(socket));
    await new Promise((resolve) => echoServer.listen(0, '127.0.0.1', resolve));
    echoPort = echoServer.address().port;
  });

  after(async () => {
    manager.closeAll();
    await new Promise((resolve) => echoServer.close(resolve));
  });

  beforeEach(() => {
    manager = TunnelManager.getInstance();
    manager.closeAll();
    manager.configure(LOOPBACK_POLICY, async () => createLocalForwarder());
  });

  it('carries traffic through a SOCKS5 proxy', async () => {
    const tunnel = await manager.openTunnel({ type: 'socks5' });

    assert.strictEqual(tunnel.type, 'socks5');
    assert.strictEqual(tunnel.bindAddress, '127.0.0.1');
    assert.ok(tunnel.localPort > 0);
    assert.strictEqual(tunnel.id, `socks5-${tunnel.localPort}`);

    const answer = await socksRequest(tunnel.localPort, 'localhost', echoPort, 'ping');
    assert.strictEqual(answer, 'ping');
  });

  it('binds the requested port', async () => {
    const tunnel = await manager.openTunnel({ type: 'socks5', localPort: 18777 });

    assert.strictEqual(tunnel.localPort, 18777);
    assert.strictEqual(
      await socksRequest(18777, '127.0.0.1', echoPort, 'hello'),
      'hello',
    );
  });

  it('carries traffic through a local forward', async () => {
    const tunnel = await manager.openTunnel({
      type: 'local',
      remoteHost: '127.0.0.1',
      remotePort: echoPort,
    });

    assert.strictEqual(await plainRequest(tunnel.localPort, 'forwarded'), 'forwarded');
  });

  it('counts the streams of a tunnel', async () => {
    const tunnel = await manager.openTunnel({ type: 'socks5' });
    await socksRequest(tunnel.localPort, '127.0.0.1', echoPort, 'x');

    const [listed] = manager.list();
    assert.strictEqual(listed.id, tunnel.id);
    assert.strictEqual(listed.totalStreams, 1);
  });

  it('requires a target for a local forward', async () => {
    await assert.rejects(
      () => manager.openTunnel({ type: 'local' }),
      /requires remoteHost and remotePort/,
    );
  });

  it('closes a tunnel and frees the port', async () => {
    const tunnel = await manager.openTunnel({ type: 'socks5' });

    assert.strictEqual(manager.closeTunnel(tunnel.id), true);
    assert.deepStrictEqual(manager.list(), []);
    assert.strictEqual(manager.closeTunnel(tunnel.id), false);
  });

  it('closes the tunnels of a connection that went away', async () => {
    await manager.openTunnel({ type: 'socks5', connectionName: 'prod' });
    await manager.openTunnel({ type: 'socks5', connectionName: 'dev' });

    manager.closeForConnection('prod');

    assert.deepStrictEqual(
      manager.list().map((tunnel) => tunnel.connectionName),
      ['dev'],
    );
  });

  it('enforces the tunnel limit', async () => {
    manager.configure({ ...LOOPBACK_POLICY, maxTunnels: 1 }, async () => createLocalForwarder());
    await manager.openTunnel({ type: 'socks5' });

    await assert.rejects(() => manager.openTunnel({ type: 'socks5' }), /Tunnel limit reached/);
  });

  it('enforces the allowed ports', async () => {
    manager.configure(
      { ...LOOPBACK_POLICY, allowedPorts: [18778] },
      async () => createLocalForwarder(),
    );

    await assert.rejects(
      () => manager.openTunnel({ type: 'socks5', localPort: 9999 }),
      /not in the allowed tunnel ports/,
    );
    await assert.rejects(
      () => manager.openTunnel({ type: 'socks5' }),
      /Ask for one of them explicitly/,
    );

    const tunnel = await manager.openTunnel({ type: 'socks5', localPort: 18778 });
    assert.strictEqual(tunnel.localPort, 18778);
  });

  it('refuses to open a tunnel when tunnels are disabled', async () => {
    manager.configure({ ...LOOPBACK_POLICY, enabled: false }, async () => createLocalForwarder());

    await assert.rejects(() => manager.openTunnel({ type: 'socks5' }), /Tunnels are disabled/);
  });

  it('fails the SOCKS request when the target refuses the connection', async () => {
    const tunnel = await manager.openTunnel({ type: 'socks5' });

    await assert.rejects(
      () => socksRequest(tunnel.localPort, '127.0.0.1', 1, 'x'),
      /SOCKS reply/,
    );
    assert.strictEqual(manager.list()[0].failedStreams, 1);
  });
});
