import { describe, it } from 'node:test';
import assert from 'node:assert';
import { formatServerList } from '../build/tools/list-servers.js';
import { filterSshHosts, formatSshHostList } from '../build/tools/list-ssh-hosts.js';

describe('List Servers Tool', () => {
  it('returns a friendly notice when nothing is configured', () => {
    assert.strictEqual(formatServerList([]), 'No SSH servers configured.');
  });

  it('returns a readable summary and the raw JSON', () => {
    const output = formatServerList([
      {
        name: 'dev',
        host: '192.168.1.100',
        port: 22,
        username: 'root',
        connected: true,
        status: {
          reachable: true,
          hostname: 'dev-box',
          osName: 'Linux',
          lastUpdated: '2026-04-02T12:00:00.000Z'
        }
      }
    ]);

    assert.match(output, /Configured SSH servers:/);
    assert.match(output, /\[connected\] dev \| root@192.168.1.100:22/);
    assert.match(output, /hostname=dev-box/);
    assert.match(output, /Raw JSON:/);
    assert.match(output, /"name":"dev"/);
  });

  it('leaves the raw JSON unindented and still parseable into the same object', () => {
    const servers = [
      {
        name: 'dev',
        host: '192.168.1.100',
        port: 22,
        username: 'root',
        connected: true,
        status: {
          reachable: true,
          hostname: 'dev-box',
          osName: 'Linux',
          drives: [
            {
              device: '/dev/sda1',
              mountPoint: '/',
              total: '512G',
              used: '380G',
              free: '106G',
              usagePercent: '78%',
            },
          ],
          lastUpdated: '2026-04-02T12:00:00.000Z',
        },
      },
    ];

    const rawJson = formatServerList(servers).split('\nRaw JSON:\n')[1];

    assert.deepStrictEqual(JSON.parse(rawJson), servers);
    // Indentation is what makes this payload big, so the compact form is a single line.
    assert.ok(!rawJson.includes('\n'));
    assert.ok(rawJson.length < JSON.stringify(servers, null, 2).length * 0.7);
  });
});

describe('list-ssh-hosts formatting', () => {
  it('filters by substring and by glob', () => {
    const hosts = [
      { alias: 'prod-master', hostName: '10.0.0.1' },
      { alias: 'prod-worker', hostName: '10.0.0.2' },
      { alias: 'stage-master', hostName: '10.1.0.1' },
    ];

    assert.deepStrictEqual(
      filterSshHosts(hosts, 'prod').map((host) => host.alias),
      ['prod-master', 'prod-worker'],
    );
    assert.deepStrictEqual(
      filterSshHosts(hosts, '*-master').map((host) => host.alias),
      ['prod-master', 'stage-master'],
    );
    assert.deepStrictEqual(
      filterSshHosts(hosts, '10.1.0.1').map((host) => host.alias),
      ['stage-master'],
    );
  });

  it('caps a long list and says how many are missing', () => {
    const hosts = Array.from({ length: 250 }, (_, index) => ({ alias: `host-${index}` }));
    const output = formatSshHostList(hosts, { total: 250 });

    assert.match(output, /showing 100 of 250/);
    assert.match(output, /150 more aliases are not listed/);
    assert.ok(!output.includes('host-120'));
  });

  it('explains an empty filter result', () => {
    assert.match(
      formatSshHostList([], { filter: 'nope', total: 12 }),
      /No SSH config host alias matches 'nope'/,
    );
  });
});
