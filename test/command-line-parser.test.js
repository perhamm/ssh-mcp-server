import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import { CommandLineParser } from '../build/cli/command-line-parser.js';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

describe('Command Line Parser', () => {
  let originalArgv;
  let fixturesDir;
  let testConfigPath;
  let testSshConfigPath;

  before(() => {
    originalArgv = process.argv;

    fixturesDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ssh-mcp-cli-test-'));

    testConfigPath = path.join(fixturesDir, 'test-config.json');
    testSshConfigPath = path.join(fixturesDir, 'test-ssh-config');

    fs.writeFileSync(testConfigPath, JSON.stringify({
      dev: {
        host: '192.168.1.100',
        port: 22,
        username: 'devuser',
        password: 'devpass'
      },
      prod: {
        host: '10.0.0.50',
        port: 22,
        username: 'produser',
        privateKey: '~/.ssh/prod_key'
      }
    }));

    fs.writeFileSync(testSshConfigPath, `
Host testhost
    HostName 172.16.0.1
    Port 2222
    User testuser
    IdentityFile ~/.ssh/test_key
`);
  });

  after(() => {
    process.argv = originalArgv;
    fs.rmSync(fixturesDir, { recursive: true, force: true });
  });

  describe('config file parsing', () => {
    it('parses a JSON config file in object form', () => {
      process.argv = ['node', 'test', '--config-file', testConfigPath];
      const result = CommandLineParser.parseArgs();

      assert.strictEqual(Object.keys(result.configs).length, 2);
      assert.strictEqual(result.configs.dev.host, '192.168.1.100');
      assert.strictEqual(result.configs.dev.username, 'devuser');
      assert.strictEqual(result.configs.prod.privateKey, path.join(os.homedir(), '.ssh', 'prod_key'));
    });

    it('parses a JSON config file in array form', () => {
      const arrayConfigPath = path.join(fixturesDir, 'array-config.json');
      fs.writeFileSync(arrayConfigPath, JSON.stringify([
        {
          name: 'server1',
          host: '1.2.3.4',
          port: 22,
          username: 'user1',
          password: 'pass1'
        },
        {
          name: 'server2',
          host: '5.6.7.8',
          port: 2222,
          username: 'user2',
          privateKey: '~/.ssh/key2'
        }
      ]));

      process.argv = ['node', 'test', '--config-file', arrayConfigPath];
      const result = CommandLineParser.parseArgs();

      assert.strictEqual(Object.keys(result.configs).length, 2);
      assert.strictEqual(result.configs.server1.host, '1.2.3.4');
      assert.strictEqual(result.configs.server2.port, 2222);

      fs.unlinkSync(arrayConfigPath);
    });

    it('keeps the SSH algorithms from a JSON config', () => {
      const algorithmsConfigPath = path.join(fixturesDir, 'algorithms-config.json');
      const algorithms = {
        serverHostKey: { append: ['ssh-rsa'] },
        hmac: ['hmac-sha1', 'hmac-md5']
      };
      fs.writeFileSync(algorithmsConfigPath, JSON.stringify({
        legacy: {
          host: '192.168.1.100',
          port: 22,
          username: 'legacy-user',
          password: 'legacy-pass',
          algorithms
        }
      }));

      try {
        process.argv = ['node', 'test', '--config-file', algorithmsConfigPath];
        const result = CommandLineParser.parseArgs();

        assert.deepStrictEqual(result.configs.legacy.algorithms, algorithms);
      } finally {
        fs.unlinkSync(algorithmsConfigPath);
      }
    });

    it('keeps and validates maxOutputBytes from a JSON config', () => {
      const outputLimitConfigPath = path.join(fixturesDir, 'output-limit-config.json');
      fs.writeFileSync(outputLimitConfigPath, JSON.stringify({
        limited: {
          host: '192.168.1.100',
          port: 22,
          username: 'limited-user',
          password: 'limited-pass',
          maxOutputBytes: 2048
        },
        unlimited: {
          host: '192.168.1.101',
          port: 22,
          username: 'unlimited-user',
          password: 'unlimited-pass',
          maxOutputBytes: 0
        }
      }));

      try {
        process.argv = ['node', 'test', '--config-file', outputLimitConfigPath];
        const result = CommandLineParser.parseArgs();

        assert.strictEqual(result.configs.limited.maxOutputBytes, 2048);
        assert.strictEqual(result.configs.unlimited.maxOutputBytes, 0);
      } finally {
        fs.unlinkSync(outputLimitConfigPath);
      }
    });

    it('parses commandTimeoutMs from a config file', () => {
      const timeoutConfigPath = path.join(fixturesDir, 'command-timeout-config.json');
      fs.writeFileSync(timeoutConfigPath, JSON.stringify({
        slow: {
          host: '192.168.1.100',
          port: 22,
          username: 'slow-user',
          password: 'slow-pass',
          commandTimeoutMs: 180000
        },
        plain: {
          host: '192.168.1.101',
          port: 22,
          username: 'plain-user',
          password: 'plain-pass'
        }
      }));

      try {
        process.argv = ['node', 'test', '--config-file', timeoutConfigPath];
        const result = CommandLineParser.parseArgs();

        assert.strictEqual(result.configs.slow.commandTimeoutMs, 180000);
        assert.strictEqual(result.configs.plain.commandTimeoutMs, undefined);
      } finally {
        fs.unlinkSync(timeoutConfigPath);
      }
    });

    it('throws on an invalid commandTimeoutMs', () => {
      const invalidTimeoutPath = path.join(fixturesDir, 'invalid-command-timeout-config.json');
      fs.writeFileSync(invalidTimeoutPath, JSON.stringify({
        invalid: {
          host: '192.168.1.100',
          port: 22,
          username: 'invalid-user',
          password: 'invalid-pass',
          commandTimeoutMs: 0
        }
      }));

      try {
        process.argv = ['node', 'test', '--config-file', invalidTimeoutPath];
        assert.throws(
          () => CommandLineParser.parseArgs(),
          /commandTimeoutMs must be a positive number/,
        );
      } finally {
        fs.unlinkSync(invalidTimeoutPath);
      }
    });

    it('throws on an invalid maxOutputBytes', () => {
      const invalidConfigPath = path.join(fixturesDir, 'invalid-output-limit-config.json');
      fs.writeFileSync(invalidConfigPath, JSON.stringify({
        invalid: {
          host: '192.168.1.100',
          port: 22,
          username: 'invalid-user',
          password: 'invalid-pass',
          maxOutputBytes: -1
        }
      }));

      try {
        process.argv = ['node', 'test', '--config-file', invalidConfigPath];
        assert.throws(
          () => CommandLineParser.parseArgs(),
          /maxOutputBytes must be a non-negative integer/,
        );
      } finally {
        fs.unlinkSync(invalidConfigPath);
      }
    });

    it('throws when the config file does not exist', () => {
      process.argv = ['node', 'test', '--config-file', '/nonexistent/config.json'];
      assert.throws(() => {
        CommandLineParser.parseArgs();
      }, /not found/);
    });
  });

  describe('--ssh parsing', () => {
    it('parses a JSON --ssh argument', () => {
      const sshJson = JSON.stringify({
        name: 'test',
        host: '1.2.3.4',
        port: 22,
        username: 'testuser',
        password: 'testpass',
        transportMode: 'shell',
        shellReadyTimeoutMs: 15000,
        maxOutputBytes: 0
      });

      process.argv = ['node', 'test', '--ssh', sshJson];
      const result = CommandLineParser.parseArgs();

      assert.strictEqual(result.configs.test.host, '1.2.3.4');
      assert.strictEqual(result.configs.test.username, 'testuser');
      assert.strictEqual(result.configs.test.transportMode, 'shell');
      assert.strictEqual(result.configs.test.shellReadyTimeoutMs, 15000);
      assert.strictEqual(result.configs.test.maxOutputBytes, 0);
    });

    it('parses a legacy --ssh argument', () => {
      process.argv = ['node', 'test', '--ssh', 'name=legacy,host=1.2.3.4,port=22,user=legacyuser,password=legacypass'];
      const result = CommandLineParser.parseArgs();

      assert.strictEqual(result.configs.legacy.host, '1.2.3.4');
      assert.strictEqual(result.configs.legacy.username, 'legacyuser');
    });

    it('supports several --ssh arguments', () => {
      const ssh1 = JSON.stringify({ name: 'server1', host: '1.1.1.1', port: 22, username: 'user1', password: 'pass1' });
      const ssh2 = JSON.stringify({ name: 'server2', host: '2.2.2.2', port: 22, username: 'user2', password: 'pass2' });

      process.argv = ['node', 'test', '--ssh', ssh1, '--ssh', ssh2];
      const result = CommandLineParser.parseArgs();

      assert.strictEqual(Object.keys(result.configs).length, 2);
      assert.strictEqual(result.configs.server1.host, '1.1.1.1');
      assert.strictEqual(result.configs.server2.host, '2.2.2.2');
    });
  });

  describe('single connection mode, the legacy form', () => {
    it('parses command line arguments', () => {
      process.argv = ['node', 'test', '--host', '1.2.3.4', '--port', '22', '--username', 'testuser', '--password', 'testpass'];
      const result = CommandLineParser.parseArgs();

      assert.strictEqual(result.configs.default.host, '1.2.3.4');
      assert.strictEqual(result.configs.default.port, 22);
      assert.strictEqual(result.configs.default.username, 'testuser');
      assert.strictEqual(result.configs.default.password, 'testpass');
    });

    it('parses positional arguments', () => {
      process.argv = ['node', 'test', '1.2.3.4', '22', 'testuser', 'testpass'];
      const result = CommandLineParser.parseArgs();

      assert.strictEqual(result.configs.default.host, '1.2.3.4');
      assert.strictEqual(result.configs.default.port, 22);
      assert.strictEqual(result.configs.default.username, 'testuser');
      assert.strictEqual(result.configs.default.password, 'testpass');
    });

    it('supports private key authentication', () => {
      process.argv = ['node', 'test', '--host', '1.2.3.4', '--port', '22', '--username', 'testuser', '--privateKey', '~/.ssh/id_rsa'];
      const result = CommandLineParser.parseArgs();

      assert.strictEqual(result.configs.default.privateKey, path.join(os.homedir(), '.ssh', 'id_rsa'));
      assert.strictEqual(result.configs.default.password, undefined);
    });

    it('does not inject the SSH agent from the environment when a password is given', () => {
      const originalSshAuthSock = process.env.SSH_AUTH_SOCK;
      process.env.SSH_AUTH_SOCK = '/tmp/environment-agent.sock';
      process.argv = ['node', 'test', '--host', '1.2.3.4', '--username', 'testuser', '--password', 'testpass'];

      try {
        const result = CommandLineParser.parseArgs();

        assert.strictEqual(result.configs.default.password, 'testpass');
        assert.strictEqual(result.configs.default.agent, undefined);
      } finally {
        if (originalSshAuthSock === undefined) {
          delete process.env.SSH_AUTH_SOCK;
        } else {
          process.env.SSH_AUTH_SOCK = originalSshAuthSock;
        }
      }
    });

    it('does not inject the SSH agent from the environment when a private key is given', () => {
      const originalSshAuthSock = process.env.SSH_AUTH_SOCK;
      process.env.SSH_AUTH_SOCK = '/tmp/environment-agent.sock';
      process.argv = ['node', 'test', '--host', '1.2.3.4', '--username', 'testuser', '--privateKey', '~/.ssh/id_rsa'];

      try {
        const result = CommandLineParser.parseArgs();

        assert.strictEqual(result.configs.default.privateKey, path.join(os.homedir(), '.ssh', 'id_rsa'));
        assert.strictEqual(result.configs.default.agent, undefined);
      } finally {
        if (originalSshAuthSock === undefined) {
          delete process.env.SSH_AUTH_SOCK;
        } else {
          process.env.SSH_AUTH_SOCK = originalSshAuthSock;
        }
      }
    });

    it('throws when a required argument is missing', () => {
      process.argv = ['node', 'test', '--host', '1.2.3.4'];
      assert.throws(() => {
        CommandLineParser.parseArgs();
      }, /Missing required parameters/);
    });
  });

  describe('SSH config integration', () => {
    it('falls back to the default port and the SSH agent when the SSH config has no Port and no IdentityFile', () => {
      const minimalSshConfigPath = path.join(fixturesDir, 'minimal-ssh-config');
      const originalSshAuthSock = process.env.SSH_AUTH_SOCK;
      fs.writeFileSync(minimalSshConfigPath, `
Host minimalhost
    HostName 172.16.0.2
    User minimaluser
`);
      process.env.SSH_AUTH_SOCK = '/tmp/test-ssh-agent.sock';
      process.argv = ['node', 'test', '--host', 'minimalhost', '--ssh-config-file', minimalSshConfigPath];

      try {
        const result = CommandLineParser.parseArgs();

        assert.strictEqual(result.configs.default.host, '172.16.0.2');
        assert.strictEqual(result.configs.default.port, 22);
        assert.strictEqual(result.configs.default.username, 'minimaluser');
        assert.strictEqual(result.configs.default.agent, '/tmp/test-ssh-agent.sock');
      } finally {
        if (originalSshAuthSock === undefined) {
          delete process.env.SSH_AUTH_SOCK;
        } else {
          process.env.SSH_AUTH_SOCK = originalSshAuthSock;
        }
        fs.unlinkSync(minimalSshConfigPath);
      }
    });

    it('lets the command line port and agent override the SSH config defaults', () => {
      const originalSshAuthSock = process.env.SSH_AUTH_SOCK;
      process.env.SSH_AUTH_SOCK = '/tmp/environment-agent.sock';

      try {
        process.argv = [
          'node', 'test', '--host', 'testhost', '--port', '3333', '--agent', '/tmp/explicit-agent.sock',
          '--ssh-config-file', testSshConfigPath,
        ];
        const result = CommandLineParser.parseArgs();

        assert.strictEqual(result.configs.default.port, 3333);
        assert.strictEqual(result.configs.default.agent, '/tmp/explicit-agent.sock');
      } finally {
        if (originalSshAuthSock === undefined) {
          delete process.env.SSH_AUTH_SOCK;
        } else {
          process.env.SSH_AUTH_SOCK = originalSshAuthSock;
        }
      }
    });

    it('reads the connection parameters from the SSH config', () => {
      process.argv = ['node', 'test', '--host', 'testhost', '--ssh-config-file', testSshConfigPath];
      const result = CommandLineParser.parseArgs();

      assert.strictEqual(result.configs.default.host, '172.16.0.1');
      assert.strictEqual(result.configs.default.port, 2222);
      assert.strictEqual(result.configs.default.username, 'testuser');
      assert.ok(
        result.configs.default.privateKey.endsWith(path.join('.ssh', 'test_key')),
      );
    });

    it('lets command line arguments override the SSH config', () => {
      process.argv = ['node', 'test', '--host', 'testhost', '--port', '3333', '--ssh-config-file', testSshConfigPath];
      const result = CommandLineParser.parseArgs();

      assert.strictEqual(result.configs.default.port, 3333); // overridden
      assert.strictEqual(result.configs.default.host, '172.16.0.1'); // from the SSH config
      assert.strictEqual(result.configs.default.username, 'testuser'); // from the SSH config
    });

    it('supports an SSH config alias with password authentication', () => {
      process.argv = ['node', 'test', '--host', 'testhost', '--password', 'mypass', '--ssh-config-file', testSshConfigPath];
      const result = CommandLineParser.parseArgs();

      assert.strictEqual(result.configs.default.password, 'mypass');
      assert.strictEqual(result.configs.default.host, '172.16.0.1');
    });
  });

  describe('command whitelist and blacklist', () => {
    it('parses the command whitelist', () => {
      process.argv = ['node', 'test', '--host', '1.2.3.4', '--port', '22', '--username', 'user', '--password', 'pass', '--whitelist', 'ls,cat,grep'];
      const result = CommandLineParser.parseArgs();

      assert.deepStrictEqual(result.configs.default.commandWhitelist, ['ls', 'cat', 'grep']);
    });

    it('parses the command blacklist', () => {
      process.argv = ['node', 'test', '--host', '1.2.3.4', '--port', '22', '--username', 'user', '--password', 'pass', '--blacklist', 'rm,shutdown,reboot'];
      const result = CommandLineParser.parseArgs();

      assert.deepStrictEqual(result.configs.default.commandBlacklist, ['rm', 'shutdown', 'reboot']);
    });
  });

  describe('other options', () => {
    it('defaults transportMode to exec', () => {
      process.argv = ['node', 'test', '--host', '1.2.3.4', '--port', '22', '--username', 'user', '--password', 'pass'];
      const result = CommandLineParser.parseArgs();

      assert.strictEqual(result.configs.default.transportMode, 'exec');
      assert.strictEqual(result.configs.default.shellReadyTimeoutMs, 10000);
    });

    it('parses the shell transport options', () => {
      process.argv = [
        'node',
        'test',
        '--host', '1.2.3.4',
        '--port', '22',
        '--username', 'user',
        '--password', 'pass',
        '--transport-mode', 'shell',
        '--shell-ready-timeout', '15000'
      ];
      const result = CommandLineParser.parseArgs();

      assert.strictEqual(result.configs.default.transportMode, 'shell');
      assert.strictEqual(result.configs.default.shellReadyTimeoutMs, 15000);
    });

    it('parses the --pty option', () => {
      process.argv = ['node', 'test', '--host', '1.2.3.4', '--port', '22', '--username', 'user', '--password', 'pass', '--pty'];
      const result = CommandLineParser.parseArgs();

      assert.strictEqual(result.configs.default.pty, true);
    });

    it('parses a string false pty from a config file', () => {
      const ptyConfigPath = path.join(fixturesDir, 'pty-config.json');
      fs.writeFileSync(ptyConfigPath, JSON.stringify({
        dev: {
          host: '192.168.1.100',
          port: 22,
          username: 'devuser',
          password: 'devpass',
          pty: 'false'
        }
      }));

      process.argv = ['node', 'test', '--config-file', ptyConfigPath];
      const result = CommandLineParser.parseArgs();

      assert.strictEqual(result.configs.dev.pty, false);

      fs.unlinkSync(ptyConfigPath);
    });

    it('parses the --pre-connect option', () => {
      process.argv = ['node', 'test', '--host', '1.2.3.4', '--port', '22', '--username', 'user', '--password', 'pass', '--pre-connect'];
      const result = CommandLineParser.parseArgs();

      assert.strictEqual(result.preConnect, true);
    });

    it('parses the SOCKS proxy', () => {
      process.argv = ['node', 'test', '--host', '1.2.3.4', '--port', '22', '--username', 'user', '--password', 'pass', '--socksProxy', 'socks://proxy:1080'];
      const result = CommandLineParser.parseArgs();

      assert.strictEqual(result.configs.default.socksProxy, 'socks://proxy:1080');
    });

    it('parses the generic proxy', () => {
      process.argv = ['node', 'test', '--host', '1.2.3.4', '--port', '22', '--username', 'user', '--password', 'pass', '--proxy', 'http://proxy:8080'];
      const result = CommandLineParser.parseArgs();

      assert.strictEqual(result.configs.default.proxy, 'http://proxy:8080');
    });

    it('parses the allowed local paths', () => {
      process.argv = ['node', 'test', '--host', '1.2.3.4', '--port', '22', '--username', 'user', '--password', 'pass', '--allowed-local-paths', './tmp,~/.ssh'];
      const result = CommandLineParser.parseArgs();

      assert.ok(Array.isArray(result.configs.default.allowedLocalPaths));
      assert.strictEqual(result.configs.default.allowedLocalPaths.length, 2);
      assert.ok(result.configs.default.allowedLocalPaths.every((entry) => path.isAbsolute(entry)));
      assert.strictEqual(result.configs.default.allowedLocalPaths[1], path.join(os.homedir(), '.ssh'));
    });

    it('parses the allowed remote paths', () => {
      process.argv = ['node', 'test', '--host', '1.2.3.4', '--port', '22', '--username', 'user', '--password', 'pass', '--allowed-remote-paths', '/var/log,/home/ops/inbox/'];
      const result = CommandLineParser.parseArgs();

      assert.deepStrictEqual(
        result.configs.default.allowedRemotePaths,
        ['/var/log', '/home/ops/inbox']
      );
    });

    it('throws on a relative allowedRemotePaths entry', () => {
      process.argv = ['node', 'test', '--host', '1.2.3.4', '--port', '22', '--username', 'user', '--password', 'pass', '--allowed-remote-paths', 'var/log'];
      assert.throws(() => CommandLineParser.parseArgs(), /absolute POSIX/);
    });

    it('parses commandTemplate from a config file', () => {
      const templateConfigPath = path.join(fixturesDir, 'template-config.json');
      fs.writeFileSync(templateConfigPath, JSON.stringify({
        dev: {
          host: '192.168.1.100',
          port: 22,
          username: 'devuser',
          password: 'devpass',
          commandTemplate: "su root -c '<command>'"
        }
      }));

      process.argv = ['node', 'test', '--config-file', templateConfigPath];
      const result = CommandLineParser.parseArgs();

      assert.strictEqual(result.configs.dev.commandTemplate, "su root -c '<command>'");

      fs.unlinkSync(templateConfigPath);
    });

    it('supports the <quotedCommand> placeholder in commandTemplate', () => {
      const templateConfigPath = path.join(fixturesDir, 'quoted-template-config.json');
      fs.writeFileSync(templateConfigPath, JSON.stringify({
        dev: {
          host: '192.168.1.100',
          port: 22,
          username: 'devuser',
          password: 'devpass',
          commandTemplate: "su root -c <quotedCommand>"
        }
      }));

      process.argv = ['node', 'test', '--config-file', templateConfigPath];
      const result = CommandLineParser.parseArgs();

      assert.strictEqual(result.configs.dev.commandTemplate, "su root -c <quotedCommand>");

      fs.unlinkSync(templateConfigPath);
    });

    it('throws when commandTemplate has no <command> placeholder', () => {
      const badConfigPath = path.join(fixturesDir, 'bad-template-config.json');
      fs.writeFileSync(badConfigPath, JSON.stringify({
        dev: {
          host: '192.168.1.100',
          port: 22,
          username: 'devuser',
          password: 'devpass',
          commandTemplate: "su root -c 'missing placeholder'"
        }
      }));

      process.argv = ['node', 'test', '--config-file', badConfigPath];
      assert.throws(() => CommandLineParser.parseArgs(), /<command>/);

      fs.unlinkSync(badConfigPath);
    });
  });

  describe('precedence', () => {
    it('prefers the config file over --ssh arguments', () => {
      const sshJson = JSON.stringify({ name: 'test', host: '1.1.1.1', port: 22, username: 'user1', password: 'pass1' });
      process.argv = ['node', 'test', '--config-file', testConfigPath, '--ssh', sshJson];
      const result = CommandLineParser.parseArgs();

      // Only the servers from the config file are expected.
      assert.strictEqual(Object.keys(result.configs).length, 2);
      assert.ok(result.configs.dev);
      assert.ok(result.configs.prod);
      assert.ok(!result.configs.test);
    });

    it('prefers --ssh arguments over single connection mode', () => {
      const sshJson = JSON.stringify({ name: 'test', host: '1.1.1.1', port: 22, username: 'user1', password: 'pass1' });
      process.argv = ['node', 'test', '--ssh', sshJson, '--host', '2.2.2.2', '--port', '22', '--username', 'user2', '--password', 'pass2'];
      const result = CommandLineParser.parseArgs();

      assert.strictEqual(Object.keys(result.configs).length, 1);
      assert.strictEqual(result.configs.test.host, '1.1.1.1');
    });
  });
});
