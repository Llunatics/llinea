// llinea — incident / forensic timeline normalizer.
// Pure logic (no DOM at load) so tests can require() this file in Node.
// In the browser the same functions are wired to the UI in index.html.

'use strict';

const MONTHS = { Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5, Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11 };

function parseOffset(str) {
  // "+07:00", "+0700", "Z" -> minutes east of UTC. Null if unparseable
  // or out of range (hour > 23 or minute > 59, e.g. +99:99).
  if (!str) return null;
  if (str === 'Z' || str === 'z') return 0;
  const m = /^([+-])(\d{2}):?(\d{2})$/.exec(str.trim());
  if (!m) return null;
  const hh = Number(m[2]);
  const mm = Number(m[3]);
  if (hh > 23 || mm > 59) return null;
  const mins = hh * 60 + mm;
  return m[1] === '-' ? -mins : mins;
}

function toEpoch(y, mo, d, h, mi, s, offsetMin) {
  // Treat the given wall-clock fields as UTC, then subtract the offset.
  // Returns null for out-of-range fields instead of letting Date.UTC
  // silently roll them over (Feb 30 -> Mar 2, hour 25 -> next day, ...):
  // a forensic timeline must never invent a different instant.
  const sec = s || 0;
  if (mo < 0 || mo > 11 || d < 1 || d > 31 ||
      h < 0 || h > 23 || mi < 0 || mi > 59 || sec < 0 || sec > 59) return null;
  const utc = Date.UTC(y, mo, d, h, mi, sec);
  const chk = new Date(utc);
  if (chk.getUTCFullYear() !== y || chk.getUTCMonth() !== mo || chk.getUTCDate() !== d ||
      chk.getUTCHours() !== h || chk.getUTCMinutes() !== mi || chk.getUTCSeconds() !== sec) return null;
  return utc - (offsetMin || 0) * 60000;
}

// Guess host / user / src_ip from a free-text message, for chain detection.
// Only the first IP with all octets <= 255 is kept (999.999.999.999 is
// not an address, and must not shadow a real IP later in the message).
function extractFields(msg) {
  const out = {};
  const ipRe = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
  let m;
  while ((m = ipRe.exec(msg)) !== null) {
    if (m[0].split('.').every((o) => Number(o) <= 255)) { out.src_ip = m[0]; break; }
  }
  const user = /\buser=([A-Za-z0-9._-]+)/i.exec(msg)
    || /\b(?:user|account|username)\s+([A-Za-z0-9._-]{2,32})/i.exec(msg)
    || /\bfor\s+([A-Za-z][A-Za-z0-9._-]{1,31})\b/i.exec(msg);
  if (user) out.user = user[1];
  const host = /\bhost=([A-Za-z0-9._-]+)/i.exec(msg)
    || /\bon\s+([A-Za-z0-9._-]{2,32})\b/i.exec(msg);
  if (host) out.host = host[1];
  return out;
}

function severityOf(msg) {
  const m = msg.toLowerCase();
  if (/(failed|failure|denied|unauthorized|malware|ransom|exploit|breach|alert|critical|error)/.test(m)) return 'high';
  if (/(warning|warn|suspicious|unusual|anomaly|blocked|timeout|retry)/.test(m)) return 'medium';
  if (/(accepted|success|login|authenticated|sudo|session opened|connected)/.test(m)) return 'auth';
  return 'info';
}

// "web01 sshd[422]: Accepted ..." -> host web01, message without the tag.
function stripHostTag(msg) {
  const m = /^([A-Za-z0-9._-]+)\s+(?:[A-Za-z0-9._-]+\[[0-9]+\]:|[A-Za-z0-9._-]+:)\s+(.*)$/.exec(msg);
  return m ? { host: m[1], message: m[2] } : { host: null, message: msg };
}

// Parse ONE line. naiveOffsetMin is applied to timestamps with no offset.
// Returns null when the line carries no recognizable timestamp.
function parseLine(line, naiveOffsetMin) {
  const raw = line;
  const text = line.trim();
  if (!text) return null;

  // 1. SIEM JSON (one object per line)
  if (text.startsWith('{')) {
    try {
      const o = JSON.parse(text);
      const ts = o.timestamp || o.time || o['@timestamp'] || o.ts;
      if (ts) {
        // Numeric timestamps below 1e11 are epoch seconds, not ms
        // (a 10-digit value as ms would land in Jan 1970). The same
        // rule applies to digit-only strings, which some SIEM exports
        // emit: Date does not parse a bare digit string as an epoch,
        // so "1761800000" would otherwise be skipped entirely.
        let ms = ts;
        if (typeof ts === 'number') ms = ts < 1e11 ? ts * 1000 : ts;
        else if (typeof ts === 'string' && /^-?\d+$/.test(ts.trim())) {
          const n = Number(ts.trim());
          ms = Math.abs(n) < 1e11 ? n * 1000 : n;
        }
        const d = new Date(ms);
        if (!Number.isNaN(d.getTime())) {
          return finish(d.getTime(), o.event || o.message || o.action || 'event',
            o.source || o.type || 'SIEM', o.host || o.hostname || null,
            o.user || o.username || null, o.src_ip || o.ip || null, raw);
        }
      }
    } catch (e) { /* fall through to generic parsing */ }
  }

  // 2. Browser history CSV: 2026-10-30 10:15:22,https://...,Title  (or ; / tab separated)
  const csv = /^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2})(?::(\d{2}))?\s*([Zz]|[+-]\d{2}:?\d{2})?[,\t;]\s*(https?:\/\/\S+)(?:[,\t;]\s*(.*))?$/.exec(text);
  if (csv) {
    const off = csv[7] ? parseOffset(csv[7]) : naiveOffsetMin;
    if (csv[7] && off === null) return null; // explicit but invalid offset: skip, don't fall back to naive
    return finish(toEpoch(+csv[1], +csv[2] - 1, +csv[3], +csv[4], +csv[5], +(csv[6] || 0), off),
      (csv[9] || '') + (csv[8] ? ' — ' + csv[8] : ''), 'Browser', null, null, null, raw);
  }

  // 3. Syslog RFC 5424: <165>1 2026-10-30T10:15:22Z host app pid msgid [structured-data] msg
  // MSGID and structured data are real fields (not always '-'), so both are
  // consumed: msgid as one token, SD as '-' or one-or-more [...] elements.
  const rfc5424 = /^(?:<\d+>)?\d+\s+(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?([Zz]|[+-]\d{2}:\d{2})\s+(\S+)\s+(\S+)(?:\s+\S+)?\s+\S+\s+(?:-|\[.*?\])\s+(.*)$/.exec(text);
  if (rfc5424) {
    const off = parseOffset(rfc5424[7]);
    if (off === null) return null;
    return finish(toEpoch(+rfc5424[1], +rfc5424[2] - 1, +rfc5424[3], +rfc5424[4], +rfc5424[5], +rfc5424[6], off),
      rfc5424[10], 'Syslog', rfc5424[8], null, null, raw);
  }

  // 4. ISO 8601 anywhere at the start: 2026-10-30T10:15:22+07:00 rest
  // Seconds are optional and a space may replace the 'T', so space-separated
  // timestamps carrying an explicit offset are honoured, not skipped.
  const iso = /^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2})(?::(\d{2}))?(?:\.\d+)?([Zz]|[+-]\d{2}:?\d{2})?\s+[-:]?\s*(.*)$/.exec(text);
  if (iso) {
    const off = iso[7] ? parseOffset(iso[7]) : naiveOffsetMin;
    if (iso[7] && off === null) return null;
    const stripped = stripHostTag(iso[8] || '');
    return finish(toEpoch(+iso[1], +iso[2] - 1, +iso[3], +iso[4], +iso[5], +(iso[6] || 0), off), stripped.message, 'Log', stripped.host, null, null, raw);
  }

  // 5. Syslog RFC 3164: Oct 30 10:15:22 host sshd[123]: msg  (year = current year)
  const rfc3164 = /^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+(\S+)\s+(?:\S+?:\s+)?(.*)$/.exec(text);
  if (rfc3164) {
    const year = new Date().getFullYear();
    return finish(toEpoch(year, MONTHS[rfc3164[1]], +rfc3164[2], +rfc3164[3], +rfc3164[4], +rfc3164[5], naiveOffsetMin),
      rfc3164[7], 'Syslog', rfc3164[6], null, null, raw);
  }

  // 6. Generic naive datetime: 2026-10-30 10:15:22 rest  /  30/10/2026 10:15:22 rest
  const naive = /^(\d{4})-(\d{2})-(\d{2})\s+(\d{2}):(\d{2})(?::(\d{2}))?\s+[-:]?\s*(.*)$/.exec(text)
    || /^(\d{2})\/(\d{2})\/(\d{4})\s+(\d{2}):(\d{2})(?::(\d{2}))?\s+[-:]?\s*(.*)$/.exec(text);
  if (naive) {
    let y, mo, d;
    if (naive[1].length === 4) { y = +naive[1]; mo = +naive[2] - 1; d = +naive[3]; }
    else { d = +naive[1]; mo = +naive[2] - 1; y = +naive[3]; }
    return finish(toEpoch(y, mo, d, +naive[4], +naive[5], +(naive[6] || 0), naiveOffsetMin),
      naive[7] || '', 'Log', null, null, null, raw);
  }

  return null;

  function finish(epoch, message, source, host, user, srcIp, rawLine) {
    if (epoch === null || epoch === undefined || Number.isNaN(epoch)) return null;
    const msg = (message || '').trim() || rawLine;
    const extra = extractFields(msg);
    const ev = {
      epoch, message: msg, source,
      host: host || extra.host || null,
      user: user || extra.user || null,
      src_ip: srcIp || extra.src_ip || null,
      severity: severityOf(msg), raw: rawLine, chain: false,
    };
    return ev;
  }
}

function parseLogs(text, naiveOffsetMin) {
  const events = [];
  const skipped = [];
  for (const line of String(text || '').split(/\r?\n/)) {
    if (!line.trim()) continue;
    const ev = parseLine(line, naiveOffsetMin);
    if (ev) events.push(ev); else skipped.push(line);
  }
  events.sort((a, b) => a.epoch - b.epoch);
  return { events, skipped };
}

// Mark events that share a user or src_ip across >= 2 distinct hosts
// as lateral-movement candidates.
function markChains(events) {
  const byKey = new Map();
  for (const ev of events) {
    for (const key of [ev.user && ('u:' + ev.user), ev.src_ip && ('ip:' + ev.src_ip)]) {
      if (!key) continue;
      if (!byKey.has(key)) byKey.set(key, new Set());
      if (ev.host) byKey.get(key).add(ev.host);
    }
  }
  for (const ev of events) {
    ev.chain = [ev.user && ('u:' + ev.user), ev.src_ip && ('ip:' + ev.src_ip)]
      .some((k) => k && byKey.get(k) && byKey.get(k).size >= 2);
  }
  return events;
}

function formatWIB(epoch) {
  const d = new Date(epoch);
  const p = (n) => String(n).padStart(2, '0');
  // WIB = UTC+7, computed arithmetically so output is identical everywhere.
  const w = new Date(epoch + 7 * 3600000);
  return `${w.getUTCFullYear()}-${p(w.getUTCMonth() + 1)}-${p(w.getUTCDate())} ${p(w.getUTCHours())}:${p(w.getUTCMinutes())}:${p(w.getUTCSeconds())} WIB`;
}

function formatUTC(epoch) {
  const d = new Date(epoch);
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getUTCFullYear()}-${p(d.getUTCMonth() + 1)}-${p(d.getUTCDate())} ${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())} UTC`;
}

function toCSV(events) {
  const esc = (v) => '"' + String(v == null ? '' : v).replace(/"/g, '""') + '"';
  const rows = [['time_wib', 'time_utc', 'source', 'host', 'user', 'src_ip', 'severity', 'chain', 'message']];
  for (const ev of events) {
    rows.push([formatWIB(ev.epoch), formatUTC(ev.epoch), ev.source, ev.host, ev.user, ev.src_ip, ev.severity, ev.chain ? 'yes' : 'no', ev.message]);
  }
  return rows.map((r) => r.map(esc).join(',')).join('\n');
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { parseLine, parseLogs, markChains, formatWIB, formatUTC, toCSV, parseOffset, severityOf };
}
