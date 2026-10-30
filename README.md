# llinea

Incident / forensic timeline normalizer, **100% client-side**: paste logs from different timezones and sources, get one chronological timeline normalized to WIB — with lateral-movement candidates flagged.

## Features

- **Multi-format parsing** (one event per line):
  - Syslog RFC 3164 (`Oct 30 02:14:09 host sshd[421]: …`) and RFC 5424
  - ISO 8601 with or without offset (`2026-10-30T02:35:47-05:00 …`)
  - SIEM JSON, one object per line (`timestamp`, `event`, `host`, `user`, `src_ip`)
  - Browser history CSV (`2026-10-30 09:30:00,https://…,Title`)
  - Generic `YYYY-MM-DD HH:MM:SS` and `DD/MM/YYYY HH:MM:SS`
- **Timezone normalization**: an explicit offset always wins; timestamps without one are interpreted in the timezone you select (WIB/WITA/WIT/UTC/US Eastern/Central Europe). Every event is displayed in WIB with its UTC time on hover.
- **Chronological timeline**: events sorted by true instant, not by wall-clock text — an event logged at `02:35−05:00` correctly lands after one logged at `09:20+07:00`.
- **Lateral-movement candidates**: any user or source IP seen on **≥ 2 distinct hosts** is flagged in red, so a login chain across machines stands out.
- **Filter & search**: full-text search across message/host/user/IP, filter by source, and a chain-only toggle.
- **Import & export**: open a `.log` / `.txt` / `.json` / `.csv` file, or export the sorted timeline as JSON or CSV.
- **No upload, no build**: vanilla HTML/CSS/JS, no dependencies, no CDN. Open `index.html` and it works.

## Usage

```bash
python3 -m http.server 8000
# open http://localhost:8000
```

1. Click **Muat contoh insiden** for a 6-event sample (SSH brute-force → login → sudo on a second host → `/etc/shadow` access → browser activity → EDR alert in another timezone).
2. Or paste your own logs and click **Normalisasi & urutkan**.
3. Use the search box and filters to narrow the timeline; export with **Ekspor JSON** / **Ekspor CSV**.

## Behavior notes

| Case | Behavior |
|---|---|
| Timestamp with explicit offset | Offset is authoritative; the assumed timezone is ignored |
| Timestamp without offset | Interpreted in the selected assumed timezone |
| Syslog RFC 3164 (no year) | Current year is assumed |
| Line with no recognizable timestamp | Skipped and counted; all other lines still render |
| Same user/IP, one host only | Not flagged — a chain needs ≥ 2 distinct hosts |
| Severity dot | Red = high (failed/denied/malware/error), lime = auth event, grey = info/medium |

## Tests

```bash
node tests/run.js   # 14 assertions, stdlib only
```

Covers offset conversion, every parser, chronological sorting, chain detection, CSV quoting, and skipped-line counting.

## Structure

```
llinea/
├── index.html   # UI (Indonesian)
├── styles.css   # dark neutral theme, responsive
├── app.js       # parsing, normalization, chain detection (no DOM at load)
└── tests/
    └── run.js   # Node regression tests
```

## Limitations

- One event per line; multi-line stack traces are treated as separate lines (only lines with timestamps parse).
- Host/user/IP extraction from free text is heuristic — SIEM JSON lines carry exact fields and should be preferred for precise attribution.
- Timezone conversion is arithmetic on the offset; it does not model DST transitions for named zones (use explicit offsets for DST-sensitive logs).
