// Node regression tests for llinea parsing (stdlib only).
const assert = require('node:assert');
const { parseLine, parseLogs, markChains, formatWIB, formatUTC, toCSV } = require('../app.js');

let n = 0;
const check = (name, fn) => { fn(); n++; console.log('ok -', name); };
const WIB = 420; // naive timestamps assumed WIB

check('ISO with +07 offset sorts equal to same instant in UTC', () => {
  const a = parseLine('2026-10-30T09:15:22+07:00 login ok', WIB);
  const b = parseLine('2026-10-30T02:15:22Z login ok', WIB);
  assert.strictEqual(a.epoch, b.epoch);
});

check('ISO -05 offset converts correctly (02:35-05 = 14:35 WIB)', () => {
  const ev = parseLine('2026-10-30T02:35:47-05:00 alert', WIB);
  assert.strictEqual(formatWIB(ev.epoch), '2026-10-30 14:35:47 WIB');
});

check('naive timestamp uses the assumed timezone', () => {
  const ev = parseLine('2026-10-30 09:15:22 login', WIB);
  assert.strictEqual(formatUTC(ev.epoch), '2026-10-30 02:15:22 UTC');
});

check('RFC 3164 syslog parses host + message', () => {
  const ev = parseLine('Oct 30 02:14:09 web01 sshd[421]: Failed password for admin from 203.0.113.7', WIB);
  assert.strictEqual(ev.source, 'Syslog');
  assert.strictEqual(ev.host, 'web01');
  assert.strictEqual(ev.src_ip, '203.0.113.7');
  assert.strictEqual(ev.severity, 'high');
});

check('RFC 5424 syslog parses host + message', () => {
  const ev = parseLine('<165>1 2026-10-30T02:15:22Z db01 app 42 - - query slow', WIB);
  assert.strictEqual(ev.host, 'db01');
  assert.strictEqual(ev.message, 'query slow');
});

check('SIEM JSON line parses all fields', () => {
  const ev = parseLine('{"timestamp": "2026-10-30T02:20:11Z", "event": "sudo opened", "host": "db01", "user": "admin"}', WIB);
  assert.strictEqual(ev.host, 'db01');
  assert.strictEqual(ev.user, 'admin');
  assert.strictEqual(ev.source, 'SIEM');
});

check('browser CSV parses URL + title', () => {
  const ev = parseLine('2026-10-30 09:30:00,https://example.local/page,Some Page', WIB);
  assert.strictEqual(ev.source, 'Browser');
  assert.ok(ev.message.includes('example.local'));
});

check('DD/MM/YYYY generic format parses', () => {
  const ev = parseLine('30/10/2026 09:15:22 something happened', WIB);
  assert.strictEqual(formatWIB(ev.epoch), '2026-10-30 09:15:22 WIB');
});

check('line without timestamp is skipped, others sort chronologically', () => {
  const { events, skipped } = parseLogs('no timestamp here\n2026-10-30 10:00:00 second\n2026-10-30 09:00:00 first\n', WIB);
  assert.strictEqual(skipped.length, 1);
  assert.deepStrictEqual(events.map((e) => e.message), ['first', 'second']);
});

check('chain detection: same user on 2 hosts is flagged, single host is not', () => {
  const { events } = parseLogs('2026-10-30 09:00:00 user admin logged in on web01\n2026-10-30 09:05:00 user admin logged in on db01\n2026-10-30 09:06:00 user bob logged in on web01\n', WIB);
  markChains(events);
  assert.strictEqual(events[0].chain, true);
  assert.strictEqual(events[1].chain, true);
  assert.strictEqual(events[2].chain, false);
});

check('CSV export quotes messages containing commas', () => {
  const { events } = parseLogs('2026-10-30 09:00:00 hello, world\n', WIB);
  const csv = toCSV(events);
  assert.ok(csv.includes('"hello, world"'));
  assert.ok(csv.startsWith('"time_wib"'));
});

check('ISO line with host + sshd tag strips the tag and keeps the host', () => {
  const ev = parseLine('2026-10-30T02:15:41Z web01 sshd[422]: Accepted password for admin from 203.0.113.7', WIB);
  assert.strictEqual(ev.host, 'web01');
  assert.strictEqual(ev.message, 'Accepted password for admin from 203.0.113.7');
});

check('failed-password line yields user admin, not the source IP as user', () => {
  const ev = parseLine('Oct 30 02:14:09 web01 sshd[421]: Failed password for admin from 203.0.113.7', WIB);
  assert.strictEqual(ev.user, 'admin');
  assert.strictEqual(ev.src_ip, '203.0.113.7');
});

check('empty input yields zero events, zero skipped', () => {
  const { events, skipped } = parseLogs('', WIB);
  assert.strictEqual(events.length, 0);
  assert.strictEqual(skipped.length, 0);
});

console.log(`\n${n} assertions passed.`);
