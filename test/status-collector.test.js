import { describe, it } from 'node:test';
import assert from 'node:assert';
import { collectSystemStatus } from '../build/utils/status-collector.js';

const PROBE_PATTERN = /printf '\\n(__MCP_FIELD_\w+_)(\w+)\\n'/g;

/** Field names in the order the script probes them, plus the shared marker. */
function readProbes(script) {
  const probes = [...script.matchAll(PROBE_PATTERN)];
  return {
    marker: probes[0]?.[1],
    fields: probes.map((probe) => probe[2]),
  };
}

/**
 * Stand-in for the remote shell: emits the marker line for every probe the
 * script declares, followed by whatever `values` supplies for it.
 */
function fakeRemote(values, { lineEnding = '\n' } = {}) {
  return (script) => {
    const { marker, fields } = readProbes(script);
    const output = fields
      .map((field) => `${marker}${field}${lineEnding}${values[field] ?? ''}`)
      .join(lineEnding);
    return Promise.resolve(lineEnding + output);
  };
}

describe('status collector', () => {
  it('merges every probe into a single line command', async () => {
    const scripts = [];
    await collectSystemStatus((script) => {
      scripts.push(script);
      return Promise.resolve('');
    }, 'dev');

    assert.strictEqual(scripts.length, 1);
    // A multiline script would be broken by the quoting of commandTemplate.
    assert.ok(!scripts[0].includes('\n'));
    // Every probe is isolated, so one failure neither hides the rest nor fails the run.
    assert.ok(scripts[0].endsWith('; true'));

    const { fields } = readProbes(scripts[0]);
    assert.ok(fields.includes('hostname'));
    assert.ok(fields.includes('servicesInstalled'));
    assert.strictEqual(new Set(fields).size, fields.length);
  });

  it('restores every field by its marker', async () => {
    const status = await collectSystemStatus(
      fakeRemote({
        hostname: 'web-01',
        osName: 'Linux',
        kernelVersion: '6.1.0',
        memory: 'free:2.1G total:7.7G',
        processes: '181',
        threads: '901',
      }),
      'dev',
    );

    assert.strictEqual(status.reachable, true);
    assert.strictEqual(status.hostname, 'web-01');
    assert.strictEqual(status.osName, 'Linux');
    assert.strictEqual(status.kernelVersion, '6.1.0');
    assert.deepStrictEqual(status.memory, { free: '2.1G', total: '7.7G' });
    // The parser drops one header line from each of them.
    assert.deepStrictEqual(status.processes, { running: 180, threads: 900 });
  });

  // Multiline fields are where the CRLF normalisation matters: values split per line are
  // not trimmed again, so a leftover \r would land in the result.
  it('parses the CRLF output of a pty as well', async () => {
    const status = await collectSystemStatus(
      fakeRemote(
        {
          hostname: 'web-02',
          ipAddresses: '10.0.0.7\r\n192.168.1.5',
          drives: '/dev/sda1|50G|20G|30G|40%|/',
        },
        { lineEnding: '\r\n' },
      ),
      'dev',
    );

    assert.strictEqual(status.hostname, 'web-02');
    assert.deepStrictEqual(status.ipAddresses, ['10.0.0.7', '192.168.1.5']);
    assert.deepStrictEqual(status.drives, [
      {
        device: '/dev/sda1',
        total: '50G',
        used: '20G',
        free: '30G',
        usagePercent: '40%',
        mountPoint: '/',
      },
    ]);
  });

  it('keeps an empty probe from affecting the other fields', async () => {
    const status = await collectSystemStatus(
      fakeRemote({ hostname: 'web-03', ipAddresses: '', osName: 'Linux' }),
      'dev',
    );

    assert.strictEqual(status.hostname, 'web-03');
    assert.strictEqual(status.osName, 'Linux');
    assert.strictEqual(status.ipAddresses, undefined);
  });

  // A command whitelist rejects the probe script. The fields stay empty in that case,
  // the host must not be reported as unreachable.
  it('leaves the fields empty but keeps the host reachable when the command is rejected', async () => {
    const status = await collectSystemStatus(
      () => Promise.reject(new Error('Command validation failed')),
      'dev',
    );

    assert.strictEqual(status.reachable, true);
    assert.strictEqual(status.hostname, undefined);
    assert.ok(status.lastUpdated);
  });

  it('authorises every probe first and then runs only the allowed commands', async () => {
    const scripts = [];
    const recordingRemote = fakeRemote({ hostname: 'allowed-host' });
    const status = await collectSystemStatus(
      (script) => {
        scripts.push(script);
        return recordingRemote(script);
      },
      'dev',
      (command) => command === 'hostname',
    );

    assert.strictEqual(status.hostname, 'allowed-host');
    assert.strictEqual(scripts.length, 1);
    assert.match(scripts[0], /hostname/);
    assert.ok(!scripts[0].includes('uname -s'));
    assert.ok(!scripts[0].includes('cat /etc/os-release'));
  });

  it('runs no remote script when no probe is allowed', async () => {
    let calls = 0;
    const status = await collectSystemStatus(
      async () => {
        calls += 1;
        return '';
      },
      'dev',
      () => false,
    );

    assert.strictEqual(calls, 0);
    assert.strictEqual(status.reachable, true);
    assert.strictEqual(status.hostname, undefined);
  });
});
