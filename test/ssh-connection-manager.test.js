import { describe, it, before, afterEach } from 'node:test';
import assert from 'node:assert';
import { EventEmitter } from 'node:events';
import http from 'node:http';
import https from 'node:https';
import { Readable, Writable } from 'node:stream';
import { setTimeout as delay } from 'node:timers/promises';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { SocksClient } from 'socks';
import { SSHConnectionManager } from '../build/services/ssh-connection-manager.js';
import { ToolError } from '../build/utils/tool-error.js';
import { Logger } from '../build/utils/logger.js';

class FakeExecStream extends EventEmitter {
  constructor() {
    super();
    this.stderr = new EventEmitter();
  }

  close() {
    this.emit('close');
  }
}

class FakeProxySocket extends EventEmitter {
  constructor() {
    super();
    this.destroyed = false;
    this.unshifted = [];
  }

  destroy() {
    this.destroyed = true;
  }

  unshift(data) {
    this.unshifted.push(data);
  }
}

function createConnectRequest(options, { statusCode = 200, head = Buffer.alloc(0) } = {}) {
  const request = new EventEmitter();
  const socket = new FakeProxySocket();
  request.options = options;
  request.socket = socket;
  request.timeoutMs = undefined;
  request.timeoutCalls = [];
  request.setTimeout = (timeoutMs, callback) => {
    request.timeoutMs = timeoutMs;
    request.timeoutCalls.push(timeoutMs);
    request.timeoutCallback = callback;
    return request;
  };
  request.destroy = (error) => {
    if (error) {
      request.emit('error', error);
    }
  };
  request.end = () => {
    queueMicrotask(() => {
      request.emit('connect', { statusCode }, socket, head);
    });
  };
  return request;
}

class FakeShellChannel extends EventEmitter {
  constructor() {
    super();
    this.stderr = new EventEmitter();
    this.writes = [];
  }

  write(data) {
    this.writes.push(data);
    this.emit('write', data);
    return true;
  }

  close() {
    this.emit('close');
  }
}

class FakeSftp extends EventEmitter {
  end() {
    this.emit('end');
  }
}

function fakeStats(size, { isFile = true } = {}) {
  return { size, isFile: () => isFile, isDirectory: () => !isFile };
}

/**
 * SFTP double that records which transfer path the manager picked
 * (fastGet/fastPut vs the sequential stream) and serves remote content.
 */
class FakeTransferSftp extends EventEmitter {
  constructor(handlers = {}) {
    super();
    this.handlers = handlers;
    this.statCalls = [];
    this.fastGetCalls = [];
    this.fastPutCalls = [];
    this.readStreamCalls = [];
    this.writeStreamCalls = [];
    this.uploadedChunks = [];
  }

  end() {
    this.emit('end');
  }

  stat(remotePath, callback) {
    this.statCalls.push(remotePath);
    const size = this.handlers.statSizes.length > 1
      ? this.handlers.statSizes.shift()
      : this.handlers.statSizes[0];
    setImmediate(() => callback(undefined, fakeStats(size, this.handlers)));
  }

  fastGet(remotePath, localPath, options, callback) {
    this.fastGetCalls.push({ remotePath, localPath, options });
    const content = this.handlers.remoteContent.subarray(
      0,
      this.handlers.fastGetBytes ?? this.handlers.remoteContent.length,
    );
    fs.writeFileSync(localPath, content);
    setImmediate(() => callback());
  }

  fastPut(localPath, remotePath, options, callback) {
    this.fastPutCalls.push({ localPath, remotePath, options });
    setImmediate(() => callback());
  }

  createReadStream(remotePath, options = {}) {
    this.readStreamCalls.push({ remotePath, options });
    return Readable.from([
      this.handlers.remoteContent.subarray(options.start ?? 0),
    ]);
  }

  createWriteStream(remotePath, options = {}) {
    this.writeStreamCalls.push({ remotePath, options });
    const chunks = this.uploadedChunks;
    return new Writable({
      write(chunk, _encoding, callback) {
        chunks.push(Buffer.from(chunk));
        callback();
      },
    });
  }
}

class FakeClient extends EventEmitter {
  constructor(handlers = {}) {
    super();
    this.handlers = handlers;
    this.connectCalls = [];
    this.execCalls = [];
    this.shellCalls = [];
    this.endCalls = 0;
  }

  connect(config) {
    this.connectCalls.push(config);
    this.handlers.onConnect?.(config, this);
  }

  exec(command, optionsOrCallback, maybeCallback) {
    const hasOptions = typeof optionsOrCallback !== 'function';
    const options = hasOptions ? optionsOrCallback : undefined;
    const callback = hasOptions ? maybeCallback : optionsOrCallback;
    this.execCalls.push({ command, options });
    this.handlers.onExec?.({ command, options, callback }, this);
  }

  shell(options, callback) {
    this.shellCalls.push(options);
    this.handlers.onShell?.({ options, callback }, this);
  }

  sftp(callback) {
    this.handlers.onSftp?.(callback, this);
  }

  end() {
    this.endCalls += 1;
    this.emit('close');
  }

  destroy() {
    this.endCalls += 1;
    this.emit('close');
  }
}

function createPasswordConfig(overrides = {}) {
  return {
    name: 'shell',
    host: '192.168.1.100',
    port: 22,
    username: 'devuser',
    password: 'devpass',
    ...overrides,
  };
}

function extractMarkerId(payload, prefix) {
  const match = payload.match(new RegExp(`${prefix}(.+?)__`));
  return match?.[1];
}

function shellQuoteForTest(value) {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

function emitShellCommandResult(channel, commandId, output, exitCode) {
  channel.emit(
    'data',
    Buffer.from(
      `noise\r\n__MCP_BEGIN__${commandId}__\r\n${output}\n__MCP_END__${commandId}__RC__${exitCode}__\r\n$ `,
    ),
  );
}

describe('SSH Connection Manager', () => {
  let manager;
  let originalCreateClient;
  let originalScheduleStatusCollection;

  before(() => {
    manager = SSHConnectionManager.getInstance();
    originalCreateClient = manager.createClient;
    originalScheduleStatusCollection = manager.scheduleStatusCollection;
  });

  afterEach(() => {
    manager.disconnect();
    manager.createClient = originalCreateClient;
    manager.scheduleStatusCollection = originalScheduleStatusCollection;
  });

  describe('config management', () => {
    it('initialises and stores the config', () => {
      const configs = {
        dev: createPasswordConfig({ name: 'dev' }),
      };

      manager.setConfig(configs);
      const config = manager.getConfig('dev');
      assert.strictEqual(config.host, '192.168.1.100');
      assert.strictEqual(config.username, 'devuser');
    });

    it('returns the info of every server', () => {
      const configs = {
        dev: createPasswordConfig({ name: 'dev' }),
        prod: createPasswordConfig({
          name: 'prod',
          host: '10.0.0.50',
          username: 'produser',
          password: 'prodpass',
        }),
      };

      manager.setConfig(configs);
      const allInfos = manager.getAllServerInfos();

      assert.strictEqual(allInfos.length, 2);
      assert.ok(allInfos.find((c) => c.name === 'dev'));
      assert.ok(allInfos.find((c) => c.name === 'prod'));
    });

    it('returns a config by name', () => {
      manager.setConfig({
        dev: createPasswordConfig({ name: 'dev' }),
      });

      const config = manager.getConfig('dev');
      assert.strictEqual(config.name, 'dev');
      assert.strictEqual(config.host, '192.168.1.100');
    });

    it('throws when the requested config does not exist', () => {
      manager.setConfig({});
      assert.throws(() => {
        manager.getConfig('nonexistent');
      }, /not set/);
    });

    it('throws at config time on an invalid command regexp', () => {
      assert.throws(() => {
        manager.setConfig({
          dev: createPasswordConfig({
            name: 'dev',
            commandWhitelist: ['[invalid'],
          }),
        });
      }, /Invalid whitelist pattern/);
    });
  });

  describe('server info', () => {
    it('starts out disconnected', () => {
      manager.setConfig({
        dev: createPasswordConfig({ name: 'dev' }),
      });

      const infos = manager.getAllServerInfos();
      const devInfo = infos.find((info) => info.name === 'dev');

      assert.ok(devInfo);
      assert.strictEqual(devInfo.connected, false);
    });

    it('reports the connection parameters', () => {
      manager.setConfig({
        dev: createPasswordConfig({
          name: 'dev',
          port: 2222,
        }),
      });

      const infos = manager.getAllServerInfos();
      const devInfo = infos.find((info) => info.name === 'dev');

      assert.strictEqual(devInfo.host, '192.168.1.100');
      assert.strictEqual(devInfo.port, 2222);
      assert.strictEqual(devInfo.username, 'devuser');
    });

    it('allows the configured local paths for transfers', () => {
      const allowedRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ssh-mcp-allowed-'));

      try {
        manager.setConfig({
          dev: createPasswordConfig({
            name: 'dev',
            allowedLocalPaths: [allowedRoot],
          }),
        });

        const insidePath = path.join(allowedRoot, 'test.txt');
        assert.strictEqual(manager.validateLocalPath(insidePath, 'dev'), insidePath);
        assert.throws(
          () => manager.validateLocalPath(path.resolve(path.sep, 'etc', 'passwd'), 'dev'),
          ToolError,
        );
      } finally {
        fs.rmSync(allowedRoot, { recursive: true, force: true });
      }
    });

    it('keeps the allowed local paths per connection', () => {
      const firstRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ssh-mcp-first-'));
      const secondRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ssh-mcp-second-'));

      try {
        manager.setConfig({
          first: createPasswordConfig({
            name: 'first',
            allowedLocalPaths: [firstRoot],
          }),
          second: createPasswordConfig({
            name: 'second',
            allowedLocalPaths: [secondRoot],
          }),
        });

        const firstPath = path.join(firstRoot, 'file.txt');
        assert.strictEqual(manager.validateLocalPath(firstPath, 'first'), firstPath);
        assert.throws(
          () => manager.validateLocalPath(firstPath, 'second'),
          (err) => err instanceof ToolError && err.code === 'LOCAL_PATH_NOT_ALLOWED',
        );
      } finally {
        fs.rmSync(firstRoot, { recursive: true, force: true });
        fs.rmSync(secondRoot, { recursive: true, force: true });
      }
    });

    // The caller cannot see the working directory of the MCP server, so "must be inside the
    // working directory" alone gives them nothing to act on.
    it('names the resolved path and the allowed roots when a local path is rejected', () => {
      const allowedRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ssh-mcp-allowed-'));

      try {
        manager.setConfig({
          dev: createPasswordConfig({
            name: 'dev',
            allowedLocalPaths: [allowedRoot],
          }),
        });

        assert.throws(
          () => manager.validateLocalPath(path.resolve(path.sep, 'etc', 'passwd'), 'dev'),
          (error) => {
            assert.strictEqual(error.code, 'LOCAL_PATH_NOT_ALLOWED');
            assert.match(error.message, /Allowed local paths for this connection:/);
            assert.ok(error.message.includes(fs.realpathSync.native(allowedRoot)));
            assert.ok(error.message.includes(fs.realpathSync.native(process.cwd())));
            assert.match(error.message, /resolved to:/);
            return true;
          },
        );
      } finally {
        fs.rmSync(allowedRoot, { recursive: true, force: true });
      }
    });

    it('rejects a local path that escapes the allowed directory through a symlink', (t) => {
      const allowedRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ssh-mcp-allowed-'));
      const outsideRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ssh-mcp-outside-'));
      const outsideFile = path.join(outsideRoot, 'secret.txt');
      const symlinkPath = path.join(allowedRoot, 'link');

      try {
        fs.writeFileSync(outsideFile, 'secret');
        try {
          fs.symlinkSync(outsideRoot, symlinkPath, 'dir');
        } catch (error) {
          // Windows only allows this for administrators or with developer
          // mode enabled; the assertion below is meaningless without a symlink.
          if (error.code !== 'EPERM' && error.code !== 'EACCES') {
            throw error;
          }
          t.skip('creating symlinks requires elevated privileges here');
          return;
        }

        manager.setConfig({
          dev: createPasswordConfig({
            name: 'dev',
            allowedLocalPaths: [allowedRoot],
          }),
        });

        assert.throws(
          () => manager.validateLocalPath(path.join(symlinkPath, 'secret.txt'), 'dev'),
          (err) => err instanceof ToolError && err.code === 'LOCAL_PATH_NOT_ALLOWED',
        );
      } finally {
        fs.rmSync(allowedRoot, { recursive: true, force: true });
        fs.rmSync(outsideRoot, { recursive: true, force: true });
      }
    });

    it('lets validateRemotePath pass any absolute path when allowedRemotePaths is unset', () => {
      manager.setConfig({
        dev: createPasswordConfig({ name: 'dev' }),
      });

      assert.strictEqual(manager.validateRemotePath('/tmp/a.txt', 'dev'), '/tmp/a.txt');
    });

    it('makes validateRemotePath reject a relative path', () => {
      manager.setConfig({
        dev: createPasswordConfig({ name: 'dev' }),
      });

      assert.throws(
        () => manager.validateRemotePath('tmp/a.txt', 'dev'),
        (err) => err instanceof ToolError && err.code === 'REMOTE_PATH_NOT_ALLOWED',
      );
    });

    it('makes validateRemotePath reject an empty string and a null byte', () => {
      manager.setConfig({
        dev: createPasswordConfig({ name: 'dev' }),
      });

      assert.throws(
        () => manager.validateRemotePath('', 'dev'),
        (err) => err instanceof ToolError && err.code === 'REMOTE_PATH_NOT_ALLOWED',
      );
      assert.throws(
        () => manager.validateRemotePath('/tmp/\0evil', 'dev'),
        (err) => err instanceof ToolError && err.code === 'REMOTE_PATH_NOT_ALLOWED',
      );
    });

    it('allows only prefix matching paths once allowedRemotePaths is set', () => {
      manager.setConfig({
        dev: createPasswordConfig({
          name: 'dev',
          allowedRemotePaths: ['/home/ops/inbox', '/var/log'],
        }),
      });

      assert.strictEqual(
        manager.validateRemotePath('/home/ops/inbox/file', 'dev'),
        '/home/ops/inbox/file',
      );
      assert.strictEqual(
        manager.validateRemotePath('/var/log', 'dev'),
        '/var/log',
      );
      assert.throws(
        () => manager.validateRemotePath('/etc/passwd', 'dev'),
        (err) => err instanceof ToolError && err.code === 'REMOTE_PATH_NOT_ALLOWED',
      );
      // prefix-string trap: /home/ops/inbox-other must NOT match /home/ops/inbox
      assert.throws(
        () => manager.validateRemotePath('/home/ops/inbox-other/f', 'dev'),
        (err) => err instanceof ToolError && err.code === 'REMOTE_PATH_NOT_ALLOWED',
      );
    });

    it('names the resolved path and the allowed roots when a remote path is rejected', () => {
      manager.setConfig({
        dev: createPasswordConfig({
          name: 'dev',
          allowedRemotePaths: ['/home/ops/inbox', '/var/log'],
        }),
      });

      assert.throws(
        () => manager.validateRemotePath('/home/ops/inbox/../../../etc/passwd', 'dev'),
        (error) => {
          assert.strictEqual(error.code, 'REMOTE_PATH_NOT_ALLOWED');
          // The normalized path is what the check ran against, not the input.
          assert.match(error.message, /Resolved to: \/etc\/passwd\./);
          assert.match(
            error.message,
            /Allowed remote paths for this connection: \/home\/ops\/inbox, \/var\/log\./,
          );
          return true;
        },
      );
    });

    it('makes validateRemotePath normalise .. before checking the boundary', () => {
      manager.setConfig({
        dev: createPasswordConfig({
          name: 'dev',
          allowedRemotePaths: ['/home/ops/inbox'],
        }),
      });

      assert.throws(
        () => manager.validateRemotePath('/home/ops/inbox/../../../etc/passwd', 'dev'),
        (err) => err instanceof ToolError && err.code === 'REMOTE_PATH_NOT_ALLOWED',
      );
    });
  });

  describe('the default connection name', () => {
    it('takes the first config as the default', () => {
      manager.setConfig({
        first: createPasswordConfig({ name: 'first', host: '1.1.1.1', username: 'user1', password: 'pass1' }),
        second: createPasswordConfig({ name: 'second', host: '2.2.2.2', username: 'user2', password: 'pass2' }),
      });

      const config = manager.getConfig();
      assert.strictEqual(config.host, '1.1.1.1');
    });

    it('supports an explicit default connection name', () => {
      manager.setConfig(
        {
          first: createPasswordConfig({ name: 'first', host: '1.1.1.1', username: 'user1', password: 'pass1' }),
          second: createPasswordConfig({ name: 'second', host: '2.2.2.2', username: 'user2', password: 'pass2' }),
        },
        'second',
      );

      const config = manager.getConfig();
      assert.strictEqual(config.host, '2.2.2.2');
    });
  });

  describe('security boundaries', () => {
    it('keeps the status collection command inside the command whitelist', async () => {
      const originalRunCommandInternal = manager.runCommandInternal;
      const seenCalls = [];

      manager.setConfig({
        dev: createPasswordConfig({
          name: 'dev',
          commandWhitelist: ['^hostname$'],
        }),
      });

      manager.runCommandInternal = async (command, directory, name, options) => {
        seenCalls.push({ command, options });
        const validationResult = manager.validateCommand(command, name);
        if (!validationResult.isAllowed) {
          throw new ToolError(
            'COMMAND_VALIDATION_FAILED',
            validationResult.reason,
            false,
          );
        }
        return 'ok';
      };

      try {
        await manager.collectStatusForConnection('dev');
      } finally {
        manager.runCommandInternal = originalRunCommandInternal;
      }

      assert.ok(seenCalls.length > 0);
      assert.ok(
        seenCalls.every(
          (call) => call.options?.prevalidatedInternalCommand === true,
        ),
      );
      assert.ok(seenCalls.every((call) => call.command.includes('hostname')));
      assert.ok(seenCalls.every((call) => !call.command.includes('uname -s')));
      assert.strictEqual(manager.statusCache.get('dev').reachable, true);
    });

    it('passes the credentials to a SOCKS proxy and redacts them in the log', async () => {
      const originalCreateConnection = SocksClient.createConnection;
      const originalLog = Logger.log;
      const logs = [];
      let socksOptions;

      SocksClient.createConnection = async (options) => {
        socksOptions = options;
        return { socket: { mocked: true } };
      };
      Logger.log = (message, level) => {
        logs.push({ message, level });
      };

      try {
        const sshConfig = await manager.buildClientConfig(
          'proxy',
          createPasswordConfig({
            name: 'proxy',
            socksProxy: 'socks://proxy-user:proxy-pass@proxy.local:1080',
          }),
        );

        assert.strictEqual(socksOptions.proxy.userId, 'proxy-user');
        assert.strictEqual(socksOptions.proxy.password, 'proxy-pass');
        assert.strictEqual(socksOptions.proxy.host, 'proxy.local');
        assert.strictEqual(socksOptions.proxy.port, 1080);
        assert.deepStrictEqual(sshConfig.sock, { mocked: true });
        assert.ok(logs.some((entry) => entry.message.includes('proxy.local')));
        assert.ok(logs.every((entry) => !entry.message.includes('proxy-user')));
        assert.ok(logs.every((entry) => !entry.message.includes('proxy-pass')));
      } finally {
        SocksClient.createConnection = originalCreateConnection;
        Logger.log = originalLog;
      }
    });

    it('tunnels through an HTTP proxy with CONNECT and Basic auth', async () => {
      const originalRequest = http.request;
      const originalLog = Logger.log;
      const logs = [];
      let proxyRequest;

      http.request = (options) => {
        proxyRequest = createConnectRequest(options, {
          head: Buffer.from('SSH-2.0-test'),
        });
        return proxyRequest;
      };
      Logger.log = (message, level) => {
        logs.push({ message, level });
      };

      try {
        const sshConfig = await manager.buildClientConfig(
          'http-proxy',
          createPasswordConfig({
            name: 'http-proxy',
            host: 'ssh.internal',
            proxy: 'http://proxy-user:proxy-pass@proxy.local:8080',
          }),
        );

        assert.strictEqual(proxyRequest.options.method, 'CONNECT');
        assert.strictEqual(proxyRequest.options.hostname, 'proxy.local');
        assert.strictEqual(proxyRequest.options.port, 8080);
        assert.strictEqual(proxyRequest.options.path, 'ssh.internal:22');
        assert.strictEqual(proxyRequest.options.headers.Host, 'ssh.internal:22');
        assert.strictEqual(
          proxyRequest.options.headers['Proxy-Authorization'],
          `Basic ${Buffer.from('proxy-user:proxy-pass').toString('base64')}`,
        );
        assert.ok(proxyRequest.timeoutCalls.includes(30000));
        assert.strictEqual(sshConfig.sock, proxyRequest.socket);
        assert.deepStrictEqual(proxyRequest.socket.unshifted, [
          Buffer.from('SSH-2.0-test'),
        ]);
        assert.ok(logs.some((entry) => entry.message.includes('proxy.local')));
        assert.ok(logs.every((entry) => !entry.message.includes('proxy-user')));
        assert.ok(logs.every((entry) => !entry.message.includes('proxy-pass')));
      } finally {
        http.request = originalRequest;
        Logger.log = originalLog;
      }
    });

    it('connects to an HTTPS proxy over TLS on the default port 443', async () => {
      const originalRequest = https.request;
      let proxyRequest;

      https.request = (options) => {
        proxyRequest = createConnectRequest(options);
        return proxyRequest;
      };

      try {
        const sshConfig = await manager.buildClientConfig(
          'https-proxy',
          createPasswordConfig({
            name: 'https-proxy',
            proxy: 'https://proxy.local',
          }),
        );

        assert.strictEqual(proxyRequest.options.hostname, 'proxy.local');
        assert.strictEqual(proxyRequest.options.port, 443);
        assert.strictEqual(sshConfig.sock, proxyRequest.socket);
      } finally {
        https.request = originalRequest;
      }
    });

    it('closes the socket and reports a connection error when HTTP CONNECT does not return 200', async () => {
      const originalRequest = http.request;
      let proxyRequest;

      http.request = (options) => {
        proxyRequest = createConnectRequest(options, { statusCode: 407 });
        return proxyRequest;
      };

      try {
        await assert.rejects(
          manager.buildClientConfig(
            'rejected-proxy',
            createPasswordConfig({
              name: 'rejected-proxy',
              proxy: 'http://proxy.local:8080',
            }),
          ),
          (error) =>
            error instanceof ToolError &&
            error.message.includes('HTTP proxy CONNECT failed with status 407'),
        );
        assert.strictEqual(proxyRequest.socket.destroyed, true);
      } finally {
        http.request = originalRequest;
      }
    });

    it('reports a clear error on an unsupported proxy protocol', async () => {
      await assert.rejects(
        manager.buildClientConfig(
          'invalid-proxy',
          createPasswordConfig({
            name: 'invalid-proxy',
            proxy: 'ftp://proxy.local:21',
          }),
        ),
        (error) =>
          error instanceof ToolError &&
          error.message.includes("Unsupported proxy protocol 'ftp:'"),
      );
    });

    it('makes the legacy socksProxy option reject HTTP and HTTPS URLs', async () => {
      await assert.rejects(
        manager.buildClientConfig(
          'legacy-http-proxy',
          createPasswordConfig({
            name: 'legacy-http-proxy',
            socksProxy: 'http://proxy.local:8080',
          }),
        ),
        (error) =>
          error instanceof ToolError &&
          error.message.includes("'socksProxy' option only supports"),
      );
    });

    it('refuses to connect when both proxy and socksProxy are set', async () => {
      await assert.rejects(
        manager.buildClientConfig(
          'conflicting-proxy',
          createPasswordConfig({
            name: 'conflicting-proxy',
            proxy: 'http://proxy.local:8080',
            socksProxy: 'socks://proxy.local:1080',
          }),
        ),
        (error) =>
          error instanceof ToolError &&
          error.message.includes("cannot use both 'proxy' and 'socksProxy'"),
      );
    });

    it('makes connectAll try every connection before reporting the failures', async () => {
      const originalConnect = manager.connect;
      const attempted = [];

      manager.setConfig({
        good: createPasswordConfig({ name: 'good' }),
        bad: createPasswordConfig({ name: 'bad' }),
      });

      manager.connect = async (name) => {
        attempted.push(name);
        if (name === 'bad') {
          throw new Error('boom');
        }
      };

      try {
        await assert.rejects(
          () => manager.connectAll(),
          (error) => error instanceof ToolError && error.code === 'SSH_CONNECTION_FAILED',
        );
        assert.deepStrictEqual(attempted.sort(), ['bad', 'good']);
      } finally {
        manager.connect = originalConnect;
      }
    });

    it('enables the timeout and keepalive by default', async () => {
      const sshConfig = await manager.buildClientConfig(
        'dev',
        createPasswordConfig({ name: 'dev' }),
      );

      assert.strictEqual(sshConfig.readyTimeout, 30000);
      assert.strictEqual(sshConfig.timeout, 30000);
      assert.strictEqual(sshConfig.keepaliveInterval, 10000);
      assert.strictEqual(sshConfig.keepaliveCountMax, 3);
    });

    it('allows the timeout and keepalive to be overridden', async () => {
      const sshConfig = await manager.buildClientConfig(
        'dev',
        createPasswordConfig({
          name: 'dev',
          connectionTimeoutMs: 1234,
          keepaliveIntervalMs: 5678,
          keepaliveCountMax: 2,
        }),
      );

      assert.strictEqual(sshConfig.readyTimeout, 1234);
      assert.strictEqual(sshConfig.timeout, 1234);
      assert.strictEqual(sshConfig.keepaliveInterval, 5678);
      assert.strictEqual(sshConfig.keepaliveCountMax, 2);
    });

    it('lets custom SSH algorithms override their own category and keeps the safe defaults for the rest', async () => {
      const algorithms = {
        serverHostKey: { append: ['ssh-rsa'] },
        hmac: ['hmac-sha1', 'hmac-md5'],
      };
      const sshConfig = await manager.buildClientConfig(
        'legacy',
        createPasswordConfig({ name: 'legacy', algorithms }),
      );

      assert.deepStrictEqual(sshConfig.algorithms.serverHostKey, algorithms.serverHostKey);
      assert.deepStrictEqual(sshConfig.algorithms.hmac, algorithms.hmac);
      assert.strictEqual(sshConfig.algorithms.kex.includes('curve25519-sha256'), true);
      assert.strictEqual(sshConfig.algorithms.cipher.includes('3des-cbc'), false);
    });

    it('prefers ed25519 in the default negotiation and offers neither SHA-1 nor CBC', async () => {
      const sshConfig = await manager.buildClientConfig(
        'dev',
        createPasswordConfig({ name: 'dev' }),
      );

      assert.strictEqual(sshConfig.algorithms.serverHostKey[0], 'ssh-ed25519');
      assert.strictEqual(sshConfig.algorithms.serverHostKey.includes('ssh-rsa'), false);
      assert.strictEqual(sshConfig.algorithms.serverHostKey.includes('ssh-dss'), false);
      assert.strictEqual(
        sshConfig.algorithms.kex.some((kex) => kex.endsWith('sha1')),
        false,
      );
      assert.strictEqual(
        sshConfig.algorithms.hmac.some((mac) => mac.includes('md5') || mac.includes('sha1')),
        false,
      );
    });

    it('lets hostKeyAlgorithms pin the host key algorithms', async () => {
      const sshConfig = await manager.buildClientConfig(
        'dev',
        createPasswordConfig({ name: 'dev', hostKeyAlgorithms: ['ssh-ed25519'] }),
      );

      assert.deepStrictEqual(sshConfig.algorithms.serverHostKey, ['ssh-ed25519']);
    });

    it('makes the tryKeyboard authHandler return false once the auth methods are exhausted', async () => {
      const sshConfig = await manager.buildClientConfig(
        'dev',
        createPasswordConfig({
          name: 'dev',
          tryKeyboard: true,
        }),
      );

      const attempts = [];
      sshConfig.authHandler(null, null, (nextAuth) => attempts.push(nextAuth));
      sshConfig.authHandler(['password', 'keyboard-interactive'], false, (nextAuth) => attempts.push(nextAuth));
      sshConfig.authHandler(['password', 'keyboard-interactive'], false, (nextAuth) => attempts.push(nextAuth));

      assert.deepStrictEqual(attempts, ['password', 'keyboard-interactive', false]);
    });

    it('makes the tryKeyboard authHandler tell agent and publickey apart', async () => {
      const sshConfig = await manager.buildClientConfig(
        'agent',
        createPasswordConfig({
          name: 'agent',
          password: undefined,
          agent: '/tmp/ssh-agent.sock',
          tryKeyboard: true,
        }),
      );

      const attempts = [];
      sshConfig.authHandler(null, null, (nextAuth) => attempts.push(nextAuth));

      assert.deepStrictEqual(attempts, ['agent']);
      assert.strictEqual(sshConfig.agent, '/tmp/ssh-agent.sock');
    });

    it('makes the tryKeyboard authHandler keep trying the agent while publickey is still offered', async () => {
      const sshConfig = await manager.buildClientConfig(
        'mixed',
        createPasswordConfig({
          name: 'mixed',
          password: undefined,
          privateKey: path.join(process.cwd(), 'node_modules/ssh2/test/fixtures/id_rsa'),
          agent: '/tmp/ssh-agent.sock',
          tryKeyboard: true,
        }),
      );

      const attempts = [];
      sshConfig.authHandler(null, null, (nextAuth) => attempts.push(nextAuth));
      sshConfig.authHandler(['publickey', 'keyboard-interactive'], false, (nextAuth) => attempts.push(nextAuth));

      assert.deepStrictEqual(attempts, ['publickey', 'agent']);
    });

    it('answers the non-password prompt first when the keyboard prompt asks for a one time code', async () => {
      const originalOtp = process.env.SSH_MCP_2FA_CODE;
      process.env.SSH_MCP_2FA_CODE = '654321';

      try {
        const sshConfig = await manager.buildClientConfig(
          'dev',
          createPasswordConfig({
            name: 'dev',
            tryKeyboard: true,
          }),
        );

        let responses;
        sshConfig.keyboard('', '', '', [{ prompt: 'Verification code: ', echo: false }], (answers) => {
          responses = answers;
        });

        assert.deepStrictEqual(responses, ['654321']);
      } finally {
        if (originalOtp === undefined) {
          delete process.env.SSH_MCP_2FA_CODE;
        } else {
          process.env.SSH_MCP_2FA_CODE = originalOtp;
        }
      }
    });

    it('treats a single non-echo prompt as the password when there is no one time code', async () => {
      const originalOtp = process.env.SSH_MCP_2FA_CODE;
      delete process.env.SSH_MCP_2FA_CODE;

      try {
        const sshConfig = await manager.buildClientConfig(
          'dev',
          createPasswordConfig({
            name: 'dev',
            tryKeyboard: true,
          }),
        );

        let responses;
        sshConfig.keyboard('', '', '', [{ prompt: 'Access: ', echo: false }], (answers) => {
          responses = answers;
        });

        assert.deepStrictEqual(responses, ['devpass']);
      } finally {
        if (originalOtp !== undefined) {
          process.env.SSH_MCP_2FA_CODE = originalOtp;
        }
      }
    });
  });

  describe('Shell transport', () => {
    it('runs the ready sequence when a shell mode connection starts', async () => {
      const channel = new FakeShellChannel();
      channel.on('write', (payload) => {
        const readyId = extractMarkerId(payload, '__MCP_READY__');
        if (readyId) {
          setImmediate(() => {
            channel.emit('data', Buffer.from(`banner\r\n__MCP_READY__${readyId}__\r\n$ `));
          });
        }
      });

      const client = new FakeClient({
        onConnect: () => setImmediate(() => client.emit('ready')),
        onShell: ({ callback }) => callback(undefined, channel),
      });

      manager.createClient = () => client;
      manager.scheduleStatusCollection = () => {};
      manager.setConfig({
        shell: createPasswordConfig({
          transportMode: 'shell',
          shellReadyTimeoutMs: 500,
        }),
      });

      await manager.connect('shell');

      assert.strictEqual(client.shellCalls.length, 1);
      assert.strictEqual(manager.shellReady.get('shell'), true);
      assert.strictEqual(manager.getAllServerInfos()[0].connected, true);
      assert.ok(channel.writes.some((payload) => payload.includes('__MCP_READY__')));
    });

    it('runs shell mode commands one after another through the queue', async () => {
      const channel = new FakeShellChannel();
      const commandIds = [];

      channel.on('write', (payload) => {
        const readyId = extractMarkerId(payload, '__MCP_READY__');
        if (readyId) {
          setImmediate(() => {
            channel.emit('data', Buffer.from(`__MCP_READY__${readyId}__\n`));
          });
          return;
        }

        const commandId = extractMarkerId(payload, '__MCP_BEGIN__');
        if (commandId) {
          commandIds.push(commandId);
        }
      });

      const client = new FakeClient({
        onConnect: () => setImmediate(() => client.emit('ready')),
        onShell: ({ callback }) => callback(undefined, channel),
      });

      manager.createClient = () => client;
      manager.scheduleStatusCollection = () => {};
      manager.setConfig({
        shell: createPasswordConfig({
          transportMode: 'shell',
        }),
      });

      await manager.connect('shell');

      const firstPromise = manager.executeCommand('echo first', undefined, 'shell');
      const secondPromise = manager.executeCommand('echo second', undefined, 'shell');

      await delay(0);
      assert.strictEqual(commandIds.length, 1);

      emitShellCommandResult(channel, commandIds[0], 'first', 0);
      assert.strictEqual(await firstPromise, 'first');

      await delay(0);
      assert.strictEqual(commandIds.length, 2);

      emitShellCommandResult(channel, commandIds[1], 'second', 0);
      assert.strictEqual(await secondPromise, 'second');
    });

    it('extracts the output between the markers in shell mode', async () => {
      const channel = new FakeShellChannel();
      let seenScript = '';

      channel.on('write', (payload) => {
        seenScript = payload;

        const readyId = extractMarkerId(payload, '__MCP_READY__');
        if (readyId) {
          setImmediate(() => {
            channel.emit('data', Buffer.from(`__MCP_READY__${readyId}__\n`));
          });
          return;
        }

        const commandId = extractMarkerId(payload, '__MCP_BEGIN__');
        if (commandId) {
          setImmediate(() => {
            channel.emit(
              'data',
              Buffer.from(
                `prompt\r\n__MCP_BEGIN__${commandId}__\r\nhello\nwarning\n__MCP_END__${commandId}__RC__0__\r\n$ `,
              ),
            );
          });
        }
      });

      const client = new FakeClient({
        onConnect: () => setImmediate(() => client.emit('ready')),
        onShell: ({ callback }) => callback(undefined, channel),
      });

      manager.createClient = () => client;
      manager.scheduleStatusCollection = () => {};
      manager.setConfig({
        shell: createPasswordConfig({
          transportMode: 'shell',
        }),
      });

      const result = await manager.executeCommand(
        'printf "hello\\nwarning\\n"',
        '/tmp/work dir',
        'shell',
      );

      assert.strictEqual(result, 'hello\nwarning');
      assert.match(seenScript, /cd -- '\/tmp\/work dir' && \{ printf "hello\\nwarning\\n"; \}/);
    });

    it('strips ANSI sequences and terminal title noise in shell mode', async () => {
      const channel = new FakeShellChannel();

      channel.on('write', (payload) => {
        const readyId = extractMarkerId(payload, '__MCP_READY__');
        if (readyId) {
          setImmediate(() => {
            channel.emit('data', Buffer.from(`__MCP_READY__${readyId}__\n`));
          });
          return;
        }

        const commandId = extractMarkerId(payload, '__MCP_BEGIN__');
        if (commandId) {
          setImmediate(() => {
            channel.emit(
              'data',
              Buffer.from(
                `__MCP_BEGIN__${commandId}__\r\n\u001b]0;host:~\u0007hello\r\n\u001b[?1034hworld\r\n__MCP_END__${commandId}__RC__0__\r\n\u001b]0;host:~\u0007`,
              ),
            );
          });
        }
      });

      const client = new FakeClient({
        onConnect: () => setImmediate(() => client.emit('ready')),
        onShell: ({ callback }) => callback(undefined, channel),
      });

      manager.createClient = () => client;
      manager.scheduleStatusCollection = () => {};
      manager.setConfig({
        shell: createPasswordConfig({
          transportMode: 'shell',
        }),
      });

      const result = await manager.executeCommand('echo hello', undefined, 'shell');
      assert.strictEqual(result, 'hello\nworld');
    });

    it('strips a leftover BEGIN marker from the start of the output in shell mode', async () => {
      const channel = new FakeShellChannel();

      channel.on('write', (payload) => {
        const readyId = extractMarkerId(payload, '__MCP_READY__');
        if (readyId) {
          setImmediate(() => {
            channel.emit('data', Buffer.from(`__MCP_READY__${readyId}__\n`));
          });
          return;
        }

        const commandId = extractMarkerId(payload, '__MCP_BEGIN__');
        if (commandId) {
          setImmediate(() => {
            channel.emit(
              'data',
              Buffer.from(
                `__MCP_BEGIN__${commandId}__\r\nhello\r\n__MCP_END__${commandId}__RC__0__\r\n`,
              ),
            );
          });
        }
      });

      const client = new FakeClient({
        onConnect: () => setImmediate(() => client.emit('ready')),
        onShell: ({ callback }) => callback(undefined, channel),
      });

      manager.createClient = () => client;
      manager.scheduleStatusCollection = () => {};
      manager.setConfig({
        shell: createPasswordConfig({
          transportMode: 'shell',
        }),
      });

      const result = await manager.executeCommand('echo hello', undefined, 'shell');
      assert.strictEqual(result, 'hello');
    });

    it('picks up a non-zero exit code in shell mode', async () => {
      const channel = new FakeShellChannel();

      channel.on('write', (payload) => {
        const readyId = extractMarkerId(payload, '__MCP_READY__');
        if (readyId) {
          setImmediate(() => {
            channel.emit('data', Buffer.from(`__MCP_READY__${readyId}__\n`));
          });
          return;
        }

        const commandId = extractMarkerId(payload, '__MCP_BEGIN__');
        if (commandId) {
          setImmediate(() => emitShellCommandResult(channel, commandId, 'failed', 7));
        }
      });

      const client = new FakeClient({
        onConnect: () => setImmediate(() => client.emit('ready')),
        onShell: ({ callback }) => callback(undefined, channel),
      });

      manager.createClient = () => client;
      manager.scheduleStatusCollection = () => {};
      manager.setConfig({
        shell: createPasswordConfig({
          transportMode: 'shell',
        }),
      });

      await assert.rejects(
        () => manager.executeCommand('false', undefined, 'shell'),
        (error) => {
          assert.ok(error instanceof ToolError);
          assert.strictEqual(error.code, 'COMMAND_EXECUTION_ERROR');
          assert.match(error.message, /failed/);
          assert.match(error.message, /\[exit code\] 7/);
          return true;
        },
      );
    });

    it('returns a fixed error when a shell mode command times out', async () => {
      const channel = new FakeShellChannel();

      channel.on('write', (payload) => {
        const readyId = extractMarkerId(payload, '__MCP_READY__');
        if (readyId) {
          setImmediate(() => {
            channel.emit('data', Buffer.from(`__MCP_READY__${readyId}__\n`));
          });
        }
      });

      const client = new FakeClient({
        onConnect: () => setImmediate(() => client.emit('ready')),
        onShell: ({ callback }) => callback(undefined, channel),
      });

      manager.createClient = () => client;
      manager.scheduleStatusCollection = () => {};
      manager.setConfig({
        shell: createPasswordConfig({
          transportMode: 'shell',
        }),
      });

      await manager.connect('shell');

      await assert.rejects(
        () => manager.executeCommand('sleep 10', undefined, 'shell', { timeout: 20 }),
        (error) => {
          assert.ok(error instanceof ToolError);
          assert.strictEqual(error.code, 'COMMAND_TIMEOUT');
          assert.match(error.message, /timed out after 20ms/);
          return true;
        },
      );

      await delay(0);
      assert.strictEqual(manager.getAllServerInfos()[0].connected, false);
    });

    it('returns UNSUPPORTED_IN_SHELL_MODE for upload and download in shell mode', async () => {
      manager.setConfig({
        shell: createPasswordConfig({
          transportMode: 'shell',
        }),
      });

      await assert.rejects(
        () => manager.upload('/tmp/a.txt', '/remote/a.txt', 'shell'),
        (error) => {
          assert.ok(error instanceof ToolError);
          assert.strictEqual(error.code, 'UNSUPPORTED_IN_SHELL_MODE');
          return true;
        },
      );

      await assert.rejects(
        () => manager.download('/remote/a.txt', '/tmp/a.txt', 'shell'),
        (error) => {
          assert.ok(error instanceof ToolError);
          assert.strictEqual(error.code, 'UNSUPPORTED_IN_SHELL_MODE');
          return true;
        },
      );
    });
  });

  describe('Exec transport regression', () => {
    it('keeps the behaviour of exec mode unchanged', async () => {
      const stream = new FakeExecStream();
      const client = new FakeClient({
        onConnect: () => setImmediate(() => client.emit('ready')),
        onExec: ({ command, options, callback }) => {
          assert.strictEqual(command, "cd -- '/tmp' && pwd");
          assert.deepStrictEqual(options, { pty: true });
          callback(undefined, stream);
          setImmediate(() => {
            stream.emit('data', Buffer.from('/tmp\n'));
            stream.emit('exit', 0);
            stream.emit('close', 0);
          });
        },
      });

      manager.createClient = () => client;
      manager.scheduleStatusCollection = () => {};
      manager.setConfig({
        exec: createPasswordConfig({
          name: 'exec',
          transportMode: 'exec',
        }),
      });

      const result = await manager.executeCommand('pwd', '/tmp', 'exec');
      assert.strictEqual(result, '/tmp');
      assert.strictEqual(client.shellCalls.length, 0);
      assert.strictEqual(client.execCalls.length, 1);
    });

    it('keeps stderr on a successful command instead of dropping it', async () => {
      const stream = new FakeExecStream();
      const client = new FakeClient({
        onConnect: () => setImmediate(() => client.emit('ready')),
        onExec: ({ callback }) => {
          callback(undefined, stream);
          setImmediate(() => {
            stream.emit('data', Buffer.from('out-line\n'));
            stream.stderr.emit('data', Buffer.from('warn-line\n'));
            stream.emit('exit', 0);
            stream.emit('close', 0);
          });
        },
      });

      manager.createClient = () => client;
      manager.scheduleStatusCollection = () => {};
      manager.setConfig({
        exec: createPasswordConfig({
          name: 'exec',
          transportMode: 'exec',
          pty: false,
        }),
      });

      const result = await manager.executeCommand('cmd', undefined, 'exec');
      assert.strictEqual(result, 'out-line\n[stderr]\nwarn-line');
    });

    it('leaves the output untouched when a command succeeds without stderr', async () => {
      const stream = new FakeExecStream();
      const client = new FakeClient({
        onConnect: () => setImmediate(() => client.emit('ready')),
        onExec: ({ callback }) => {
          callback(undefined, stream);
          setImmediate(() => {
            stream.emit('data', Buffer.from('only-stdout\n'));
            stream.emit('exit', 0);
            stream.emit('close', 0);
          });
        },
      });

      manager.createClient = () => client;
      manager.scheduleStatusCollection = () => {};
      manager.setConfig({
        exec: createPasswordConfig({ name: 'exec', transportMode: 'exec' }),
      });

      const result = await manager.executeCommand('cmd', undefined, 'exec');
      assert.strictEqual(result, 'only-stdout');
    });

    it('truncates the output and aborts the command past maxOutputBytes', async () => {
      const stream = new FakeExecStream();
      let closeCalls = 0;
      stream.close = function close() {
        closeCalls += 1;
        this.emit('close');
      };

      const client = new FakeClient({
        onConnect: () => setImmediate(() => client.emit('ready')),
        onExec: ({ callback }) => {
          callback(undefined, stream);
          setImmediate(() => {
            stream.emit('data', Buffer.from('abcdefghij'));
          });
        },
      });

      manager.createClient = () => client;
      manager.scheduleStatusCollection = () => {};
      manager.setConfig({
        exec: createPasswordConfig({
          name: 'exec',
          transportMode: 'exec',
          maxOutputBytes: 8,
        }),
      });

      await assert.rejects(
        () => manager.executeCommand('cmd', undefined, 'exec'),
        (error) => {
          assert.ok(error instanceof ToolError);
          assert.strictEqual(error.code, 'OUTPUT_LIMIT_EXCEEDED');
          assert.strictEqual(error.retriable, false);
          assert.strictEqual(
            error.message,
            'abcdefgh\n[truncated] Output exceeded maxOutputBytes=8; the command was aborted.',
          );
          return true;
        },
      );
      assert.strictEqual(closeCalls, 1);
    });

    it('does not limit the output when maxOutputBytes is 0', async () => {
      const stream = new FakeExecStream();
      const payload = 'x'.repeat(4096);
      const client = new FakeClient({
        onConnect: () => setImmediate(() => client.emit('ready')),
        onExec: ({ callback }) => {
          callback(undefined, stream);
          setImmediate(() => {
            stream.emit('data', Buffer.from(payload));
            stream.emit('exit', 0);
            stream.emit('close', 0);
          });
        },
      });

      manager.createClient = () => client;
      manager.scheduleStatusCollection = () => {};
      manager.setConfig({
        exec: createPasswordConfig({
          name: 'exec',
          transportMode: 'exec',
          maxOutputBytes: 0,
        }),
      });

      const result = await manager.executeCommand('cmd', undefined, 'exec');
      assert.strictEqual(result, payload);
    });

    it('invalidates the connection on the command timeout when the exec channel never opens', async () => {
      const client = new FakeClient({
        onConnect: () => setImmediate(() => client.emit('ready')),
        onExec: () => {
          // Simulate a half-open SSH transport where openChannel never calls back.
        },
      });

      manager.createClient = () => client;
      manager.scheduleStatusCollection = () => {};
      manager.setConfig({
        exec: createPasswordConfig({
          name: 'exec',
          transportMode: 'exec',
        }),
      });

      await assert.rejects(
        () => manager.executeCommand('pwd', undefined, 'exec', { timeout: 20 }),
        (error) => {
          assert.ok(error instanceof ToolError);
          assert.strictEqual(error.code, 'COMMAND_TIMEOUT');
          assert.match(error.message, /Command channel did not open/);
          return true;
        },
      );

      assert.strictEqual(manager.getAllServerInfos()[0].connected, false);
      assert.strictEqual(client.endCalls, 1);
    });

    it('uses the configured commandTimeoutMs as the default timeout in exec mode', async () => {
      const client = new FakeClient({
        onConnect: () => setImmediate(() => client.emit('ready')),
        onExec: () => {
          // Never calls back, so the command can only end on a timeout.
        },
      });

      manager.createClient = () => client;
      manager.scheduleStatusCollection = () => {};
      manager.setConfig({
        exec: createPasswordConfig({
          name: 'exec',
          transportMode: 'exec',
          commandTimeoutMs: 20,
        }),
      });

      const startedAt = Date.now();
      await assert.rejects(
        // With no timeout given the default has to come from the config, not from a hardcoded 30000.
        () => manager.executeCommand('pwd', undefined, 'exec'),
        (error) => {
          assert.strictEqual(error.code, 'COMMAND_TIMEOUT');
          assert.match(error.message, /within 20ms/);
          return true;
        },
      );
      assert.ok(Date.now() - startedAt < 5000);
    });

    it('lets the timeout of the call override commandTimeoutMs', async () => {
      const client = new FakeClient({
        onConnect: () => setImmediate(() => client.emit('ready')),
        onExec: () => {},
      });

      manager.createClient = () => client;
      manager.scheduleStatusCollection = () => {};
      manager.setConfig({
        exec: createPasswordConfig({
          name: 'exec',
          transportMode: 'exec',
          commandTimeoutMs: 900000,
        }),
      });

      await assert.rejects(
        () => manager.executeCommand('pwd', undefined, 'exec', { timeout: 20 }),
        (error) => {
          assert.match(error.message, /within 20ms/);
          return true;
        },
      );
    });

    it('invalidates the connection on sftpTimeoutMs when SFTP open hangs', async () => {
      const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ssh-mcp-test-'));
      const localFile = path.join(tempDir, 'upload.txt');
      fs.writeFileSync(localFile, 'data');

      const client = new FakeClient({
        onConnect: () => setImmediate(() => client.emit('ready')),
        onSftp: () => {
          // Simulate a half-open SSH transport where SFTP never calls back.
        },
      });

      manager.createClient = () => client;
      manager.scheduleStatusCollection = () => {};
      manager.setConfig({
        exec: createPasswordConfig({
          name: 'exec',
          transportMode: 'exec',
          allowedLocalPaths: [tempDir],
          sftpTimeoutMs: 20,
        }),
      });

      await assert.rejects(
        () => manager.upload(localFile, '/tmp/upload.txt', 'exec'),
        (error) => {
          assert.ok(error instanceof ToolError);
          assert.strictEqual(error.code, 'OPERATION_TIMEOUT');
          assert.match(error.message, /SFTP open timed out/);
          return true;
        },
      );

      assert.strictEqual(manager.getAllServerInfos()[0].connected, false);
      assert.strictEqual(client.endCalls, 1);
    });

    it('keeps the OPERATION_TIMEOUT code when an SFTP upload times out', async () => {
      const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ssh-mcp-test-'));
      const localFile = path.join(tempDir, 'upload.txt');
      fs.writeFileSync(localFile, 'data');

      const hangingWriteStream = new Writable({
        write(_chunk, _encoding, _callback) {
          // Simulate a half-open transfer where the remote write never completes.
        },
      });
      const sftp = new FakeSftp();
      sftp.createWriteStream = () => hangingWriteStream;

      const client = new FakeClient({
        onConnect: () => setImmediate(() => client.emit('ready')),
        onSftp: (callback) => callback(undefined, sftp),
      });

      manager.createClient = () => client;
      manager.scheduleStatusCollection = () => {};
      manager.setConfig({
        exec: createPasswordConfig({
          name: 'exec',
          transportMode: 'exec',
          allowedLocalPaths: [tempDir],
          sftpTimeoutMs: 20,
        }),
      });

      await assert.rejects(
        () => manager.upload(localFile, '/tmp/upload.txt', 'exec'),
        (error) => {
          assert.ok(error instanceof ToolError);
          assert.strictEqual(error.code, 'OPERATION_TIMEOUT');
          assert.match(error.message, /SFTP upload timed out/);
          return true;
        },
      );

      assert.strictEqual(manager.getAllServerInfos()[0].connected, false);
      assert.strictEqual(client.endCalls, 1);
    });

    it('wraps the command with commandTemplate in exec mode', async () => {
      const stream = new FakeExecStream();
      const client = new FakeClient({
        onConnect: () => setImmediate(() => client.emit('ready')),
        onExec: ({ command, options, callback }) => {
          assert.strictEqual(
            command,
            `su root -c ${shellQuoteForTest("cd -- '/app' && ls")}`,
          );
          callback(undefined, stream);
          setImmediate(() => {
            stream.emit('data', Buffer.from('file.txt\n'));
            stream.emit('exit', 0);
            stream.emit('close', 0);
          });
        },
      });

      manager.createClient = () => client;
      manager.scheduleStatusCollection = () => {};
      manager.setConfig({
        tmpl: createPasswordConfig({
          name: 'tmpl',
          transportMode: 'exec',
          commandTemplate: "su root -c '<command>'",
        }),
      });

      const result = await manager.executeCommand('ls', '/app', 'tmpl');
      assert.strictEqual(result, 'file.txt');
    });

    it('makes commandTemplate quote a working directory containing a single quote', async () => {
      const stream = new FakeExecStream();
      const client = new FakeClient({
        onConnect: () => setImmediate(() => client.emit('ready')),
        onExec: ({ command, callback }) => {
          assert.strictEqual(
            command,
            `su root -c ${shellQuoteForTest("cd -- '/tmp/it'\\''s' && ls")}`,
          );
          callback(undefined, stream);
          setImmediate(() => {
            stream.emit('data', Buffer.from('done\n'));
            stream.emit('exit', 0);
            stream.emit('close', 0);
          });
        },
      });

      manager.createClient = () => client;
      manager.scheduleStatusCollection = () => {};
      manager.setConfig({
        tmplQuote: createPasswordConfig({
          name: 'tmplQuote',
          transportMode: 'exec',
          commandTemplate: "su root -c '<command>'",
        }),
      });

      const result = await manager.executeCommand('ls', "/tmp/it's", 'tmplQuote');
      assert.strictEqual(result, 'done');
    });

    it('makes commandTemplate wrap the bare command when exec mode gets no directory', async () => {
      const stream = new FakeExecStream();
      const client = new FakeClient({
        onConnect: () => setImmediate(() => client.emit('ready')),
        onExec: ({ command, options, callback }) => {
          assert.strictEqual(command, "su root -c 'whoami'");
          callback(undefined, stream);
          setImmediate(() => {
            stream.emit('data', Buffer.from('root\n'));
            stream.emit('exit', 0);
            stream.emit('close', 0);
          });
        },
      });

      manager.createClient = () => client;
      manager.scheduleStatusCollection = () => {};
      manager.setConfig({
        tmpl2: createPasswordConfig({
          name: 'tmpl2',
          transportMode: 'exec',
          commandTemplate: "su root -c '<command>'",
        }),
      });

      const result = await manager.executeCommand('whoami', undefined, 'tmpl2');
      assert.strictEqual(result, 'root');
    });

    it('keeps commandTemplate from interpreting $& and the other replace sequences', async () => {
      const stream = new FakeExecStream();
      const client = new FakeClient({
        onConnect: () => setImmediate(() => client.emit('ready')),
        onExec: ({ command, callback }) => {
          assert.strictEqual(command, "su root -c 'echo $& test'");
          callback(undefined, stream);
          setImmediate(() => {
            stream.emit('data', Buffer.from('ok\n'));
            stream.emit('exit', 0);
            stream.emit('close', 0);
          });
        },
      });

      manager.createClient = () => client;
      manager.scheduleStatusCollection = () => {};
      manager.setConfig({
        tmpl3: createPasswordConfig({
          name: 'tmpl3',
          transportMode: 'exec',
          commandTemplate: "su root -c '<command>'",
        }),
      });

      const result = await manager.executeCommand('echo $& test', undefined, 'tmpl3');
      assert.strictEqual(result, 'ok');
    });

    it('keeps command substitution characters in the directory from being expanded by the shell', async () => {
      const stream = new FakeExecStream();
      const client = new FakeClient({
        onConnect: () => setImmediate(() => client.emit('ready')),
        onExec: ({ command, callback }) => {
          assert.strictEqual(
            command,
            "cd -- '$(rm -rf /tmp/x)' && ls",
          );
          callback(undefined, stream);
          setImmediate(() => {
            stream.emit('data', Buffer.from('done\n'));
            stream.emit('exit', 0);
            stream.emit('close', 0);
          });
        },
      });

      manager.createClient = () => client;
      manager.scheduleStatusCollection = () => {};
      manager.setConfig({
        inj: createPasswordConfig({
          name: 'inj',
          transportMode: 'exec',
        }),
      });

      const result = await manager.executeCommand('ls', '$(rm -rf /tmp/x)', 'inj');
      assert.strictEqual(result, 'done');
    });

    it('escapes a single quote in the directory', async () => {
      const stream = new FakeExecStream();
      const client = new FakeClient({
        onConnect: () => setImmediate(() => client.emit('ready')),
        onExec: ({ command, callback }) => {
          assert.strictEqual(
            command,
            "cd -- '/tmp/it'\\''s' && ls",
          );
          callback(undefined, stream);
          setImmediate(() => {
            stream.emit('data', Buffer.from('done\n'));
            stream.emit('exit', 0);
            stream.emit('close', 0);
          });
        },
      });

      manager.createClient = () => client;
      manager.scheduleStatusCollection = () => {};
      manager.setConfig({
        quote: createPasswordConfig({
          name: 'quote',
          transportMode: 'exec',
        }),
      });

      const result = await manager.executeCommand('ls', "/tmp/it's", 'quote');
      assert.strictEqual(result, 'done');
    });
  });

  describe('output decoding and limits', () => {
    // Emit `payload` in fixed-size byte slices so multi-byte characters and
    // markers are split across chunk boundaries.
    function emitInByteSlices(emit, payload, sliceSize) {
      const bytes = Buffer.from(payload, 'utf8');
      for (let i = 0; i < bytes.length; i += sliceSize) {
        emit(bytes.subarray(i, i + sliceSize));
      }
    }

    async function connectShell(channel, overrides = {}) {
      channel.on('write', (payload) => {
        const readyId = extractMarkerId(payload, '__MCP_READY__');
        if (readyId) {
          setImmediate(() => {
            channel.emit('data', Buffer.from(`__MCP_READY__${readyId}__\n`));
          });
        }
      });

      const client = new FakeClient({
        onConnect: () => setImmediate(() => client.emit('ready')),
        onShell: ({ callback }) => callback(undefined, channel),
      });

      manager.createClient = () => client;
      manager.scheduleStatusCollection = () => {};
      manager.setConfig({
        shell: createPasswordConfig({ transportMode: 'shell', ...overrides }),
      });

      await manager.connect('shell');
      return client;
    }

    it('keeps multibyte characters intact across chunks in exec mode', async () => {
      const text = 'многобайтовый вывод команды';
      const stream = new FakeExecStream();
      const client = new FakeClient({
        onConnect: () => setImmediate(() => client.emit('ready')),
        onExec: ({ callback }) => {
          callback(undefined, stream);
          setImmediate(() => {
            emitInByteSlices(
              (slice) => stream.emit('data', slice),
              text,
              5,
            );
            stream.emit('exit', 0);
            stream.emit('close', 0);
          });
        },
      });

      manager.createClient = () => client;
      manager.scheduleStatusCollection = () => {};
      manager.setConfig({
        exec: createPasswordConfig({ name: 'exec', transportMode: 'exec' }),
      });

      assert.strictEqual(
        await manager.executeCommand('cat utf8.txt', undefined, 'exec'),
        text,
      );
    });

    it('restores both the multibyte characters and the markers across chunks in shell mode', async () => {
      const text = 'многобайтовый вывод команды';
      const channel = new FakeShellChannel();
      let commandId;
      channel.on('write', (payload) => {
        commandId = extractMarkerId(payload, '__MCP_BEGIN__') ?? commandId;
      });

      await connectShell(channel);
      const pending = manager.executeCommand('cat utf8.txt', undefined, 'shell');
      await delay(0);

      // Five bytes per slice cuts through both the multibyte characters and the markers.
      emitInByteSlices(
        (slice) => channel.emit('data', slice),
        `__MCP_BEGIN__${commandId}__\r\n${text}\n__MCP_END__${commandId}__RC__0__\r\n`,
        5,
      );

      assert.strictEqual(await pending, text);
    });

    it('recognises a marker that arrives one byte at a time in shell mode', async () => {
      const channel = new FakeShellChannel();
      let commandId;
      channel.on('write', (payload) => {
        commandId = extractMarkerId(payload, '__MCP_BEGIN__') ?? commandId;
      });

      await connectShell(channel);
      const pending = manager.executeCommand('echo hi', undefined, 'shell');
      await delay(0);

      emitInByteSlices(
        (slice) => channel.emit('data', slice),
        `__MCP_BEGIN__${commandId}__\r\nhi\n__MCP_END__${commandId}__RC__0__\r\n`,
        1,
      );

      assert.strictEqual(await pending, 'hi');
    });

    it('recognises an exit code that arrives after the marker prefix in shell mode', async () => {
      const channel = new FakeShellChannel();
      let commandId;
      channel.on('write', (payload) => {
        commandId = extractMarkerId(payload, '__MCP_BEGIN__') ?? commandId;
      });

      await connectShell(channel);
      const pending = manager.executeCommand('false', undefined, 'shell');
      await delay(0);

      channel.emit(
        'data',
        Buffer.from(`__MCP_BEGIN__${commandId}__\r\noops\n__MCP_END__${commandId}__RC__`),
      );
      await delay(0);
      channel.emit('data', Buffer.from('3__\r\n'));

      await assert.rejects(pending, (error) => {
        assert.strictEqual(error.code, 'COMMAND_EXECUTION_ERROR');
        assert.match(error.message, /\[exit code\] 3/);
        return true;
      });
    });

    it('aborts the command and invalidates the connection past maxOutputBytes in shell mode', async () => {
      const channel = new FakeShellChannel();
      let commandId;
      channel.on('write', (payload) => {
        commandId = extractMarkerId(payload, '__MCP_BEGIN__') ?? commandId;
      });

      const client = await connectShell(channel, { maxOutputBytes: 1024 });
      const pending = manager.executeCommand('yes', undefined, 'shell');
      await delay(0);

      channel.emit('data', Buffer.from(`__MCP_BEGIN__${commandId}__\r\n`));
      channel.emit('data', Buffer.alloc(4096, 0x78));

      await assert.rejects(pending, (error) => {
        assert.ok(error instanceof ToolError);
        assert.strictEqual(error.code, 'OUTPUT_LIMIT_EXCEEDED');
        assert.match(error.message, /maxOutputBytes=1024/);
        return true;
      });

      assert.strictEqual(manager.getAllServerInfos()[0].connected, false);
      assert.strictEqual(client.endCalls, 1);
    });

    it('counts only the command output between the markers in shell mode', async () => {
      const channel = new FakeShellChannel();
      let commandId;
      channel.on('write', (payload) => {
        commandId = extractMarkerId(payload, '__MCP_BEGIN__') ?? commandId;
      });

      await connectShell(channel, { maxOutputBytes: 1 });
      const pending = manager.executeCommand('printf x', undefined, 'shell');
      await delay(0);

      // BEGIN/END markers and the wrapper's CRLF are protocol framing. Only
      // the single "x" byte should count against the one-byte limit.
      emitInByteSlices(
        (slice) => channel.emit('data', slice),
        `__MCP_BEGIN__${commandId}__\r\nx\r\n__MCP_END__${commandId}__RC__0__\r\n`,
        3,
      );

      assert.strictEqual(await pending, 'x');
    });
  });

  describe('concurrent SFTP transfers', () => {
    const FAST_MIN_BYTES = 256 * 1024;

    function setupTransfer(sftp) {
      const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ssh-mcp-xfer-'));
      const client = new FakeClient({
        onConnect: () => setImmediate(() => client.emit('ready')),
        onSftp: (callback) => callback(undefined, sftp),
      });

      manager.createClient = () => client;
      manager.scheduleStatusCollection = () => {};
      manager.setConfig({
        exec: createPasswordConfig({
          name: 'exec',
          transportMode: 'exec',
          allowedLocalPaths: [tempDir],
        }),
      });

      return tempDir;
    }

    it('uploads a small file over a sequential stream without fastPut', async () => {
      const sftp = new FakeTransferSftp({ statSizes: [0] });
      const tempDir = setupTransfer(sftp);
      const localFile = path.join(tempDir, 'small.bin');
      fs.writeFileSync(localFile, Buffer.alloc(1024, 7));

      await manager.upload(localFile, '/remote/small.bin', 'exec');

      assert.strictEqual(sftp.fastPutCalls.length, 0);
      assert.strictEqual(sftp.writeStreamCalls.length, 1);
      assert.strictEqual(
        Buffer.concat(sftp.uploadedChunks).length,
        1024,
      );
    });

    it('uploads a large file concurrently with fastPut', async () => {
      const sftp = new FakeTransferSftp({ statSizes: [FAST_MIN_BYTES] });
      const tempDir = setupTransfer(sftp);
      const localFile = path.join(tempDir, 'big.bin');
      fs.writeFileSync(localFile, Buffer.alloc(FAST_MIN_BYTES, 7));

      await manager.upload(localFile, '/remote/big.bin', 'exec');

      assert.strictEqual(sftp.fastPutCalls.length, 1);
      assert.strictEqual(sftp.writeStreamCalls.length, 0);
      assert.strictEqual(sftp.fastPutCalls[0].options.concurrency, 64);
      assert.strictEqual(sftp.fastPutCalls[0].options.chunkSize, 32 * 1024);
    });

    // fastGet plans its chunks from the reported size and treats 0 as "nothing
    // to transfer" while still reporting success, so /proc-style pseudo files
    // must never reach it.
    it('reads a pseudo file reporting size 0 over a sequential stream and gets its real content', async () => {
      const content = Buffer.from('processor\t: 0\nmodel name\t: fake\n');
      const sftp = new FakeTransferSftp({
        statSizes: [0],
        remoteContent: content,
      });
      const tempDir = setupTransfer(sftp);
      const localFile = path.join(tempDir, 'cpuinfo');

      await manager.download('/proc/cpuinfo', localFile, 'exec');

      assert.strictEqual(sftp.fastGetCalls.length, 0);
      assert.deepStrictEqual(fs.readFileSync(localFile), content);
    });

    it('never uses fastGet on a remote directory', async () => {
      const sftp = new FakeTransferSftp({
        statSizes: [FAST_MIN_BYTES],
        isFile: false,
        remoteContent: Buffer.alloc(0),
      });
      const tempDir = setupTransfer(sftp);

      await manager.download('/remote/dir', path.join(tempDir, 'dir'), 'exec');

      assert.strictEqual(sftp.fastGetCalls.length, 0);
      assert.strictEqual(sftp.readStreamCalls.length, 1);
    });

    it('downloads a large file concurrently with fastGet', async () => {
      const content = Buffer.alloc(FAST_MIN_BYTES, 3);
      const sftp = new FakeTransferSftp({
        statSizes: [FAST_MIN_BYTES],
        remoteContent: content,
      });
      const tempDir = setupTransfer(sftp);
      const localFile = path.join(tempDir, 'big.bin');

      await manager.download('/remote/big.bin', localFile, 'exec');

      assert.strictEqual(sftp.fastGetCalls.length, 1);
      assert.strictEqual(sftp.readStreamCalls.length, 0);
      assert.deepStrictEqual(fs.readFileSync(localFile), content);
    });

    it('fetches the tail when the remote file grows during a download', async () => {
      const head = Buffer.alloc(FAST_MIN_BYTES, 1);
      const tail = Buffer.from('appended-while-downloading');
      const content = Buffer.concat([head, tail]);
      const sftp = new FakeTransferSftp({
        // The first stat picks fastGet, by the second stat the file has grown.
        statSizes: [head.length, content.length],
        remoteContent: content,
        fastGetBytes: head.length,
      });
      const tempDir = setupTransfer(sftp);
      const localFile = path.join(tempDir, 'growing.log');

      await manager.download('/remote/growing.log', localFile, 'exec');

      assert.strictEqual(sftp.fastGetCalls.length, 1);
      assert.deepStrictEqual(sftp.readStreamCalls[0].options.start, head.length);
      assert.deepStrictEqual(fs.readFileSync(localFile), content);
    });
  });
});
