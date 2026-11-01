# AUDIT.md — llinea

Audit bertahap ala llumen/llogic-yara: ronde fungsional + adversarial,
bukan sekali lalu. Repo Web Jumat 30 Okt 2026; audit Sabtu 31 Okt 2026
(ronde mendalam). Ronde Minggu: fresh-copy full-suite re-run + verdict
final.

## Ronde Sabtu (2026-10-31) — temuan & perbaikan

Semua temuan di bawah diverifikasi dulu sebagai bug nyata (probe),
diperbaiki, lalu dikunci tes regresi. Suite: 14 -> 20 asersi Node,
semua hijau; uji klik UI nyata via jsdom: 16/16 lolos.

### P1 — Tanggal/waktu tak valid di-rollover diam-diam (diperbaiki)

`Date.UTC` menggeser field di luar rentang tanpa protes, jadi tool
forensik ini *menciptakan* instant palsu: `2026-02-30` -> 2 Mar,
bulan 13 -> 1 Jan tahun berikut, jam 25 -> keesokan hari 01:00,
menit 99 -> +39 menit, `Oct 32` -> 1 Nov. Untuk timeline insiden ini
fatal: urutan kronologis jadi salah tanpa jejak. Sekarang `toEpoch`
memvalidasi field + round-trip `Date.UTC`, dan `finish()` mengubah
epoch tak valid menjadi baris skipped (terhitung, bukan hilang diam-diam).

### P1 — Offset liar diterima dan menggeser hari (diperbaiki)

`+99:99` dan `+25:00` lolos `parseOffset` dan menggeser event
berhari-hari (`+99:99` -> 4 hari lebih awal). Sekarang jam offset
> 23 atau menit > 59 ditolak; offset eksplisit yang tak valid membuat
baris di-skip, bukan jatuh ke zona waktu asumsi/UTC.

### P1 — Syslog RFC 5424 bermsgid/structured-data dilewati (diperbaiki)

Regex lama mengharuskan MSGID dan SD persis `- -`, jadi syslog
dunia nyata (`... app 42 ID47 [exampleSDID@32473 iut="3"] query slow`)
gagal total dan barisnya hilang dari timeline. Sekarang MSGID dibaca
sebagai satu token dan SD sebagai `-` atau satu/beberapa blok `[...]`
(backtracking regex menangani multi-elemen). Bentuk lama `- -` tetap
lolos (tes regresi lama hijau).

### P2 — ISO tanpa detik / pemisah spasi + offset dilewati (diperbaiki)

`2026-10-30T09:15 login` dan `2026-10-30 09:15:22+07:00 login`
sebelumnya skipped. Sekarang detik opsional dan pemisah boleh `T`
atau spasi; offset eksplisit tetap menang. Efek samping yang
diterima: baris `YYYY-MM-DD HH:MM:SS` kini lewat jalur ISO (bukan
generik), sehingga `server01 sshd[12]: ...` ikut ter-strip tag-nya
dan host terisi — perilaku yang lebih baik, konsisten dengan jalur
ISO-`T`.

### P2 — IP `999.999.999.999` diekstrak sebagai src_ip (diperbaiki)

Regex IP lama tak memvalidasi oktet, jadi `999.999.999.999` tercatat
sebagai alamat sumber dan membayangi IP valid di baris yang sama.
Sekarang hanya IP pertama dengan semua oktet <= 255 yang dipakai;
baris tanpa IP valid mendapat `src_ip: null`.

### P2 — Timestamp SIEM numerik detik dibaca sebagai ms (diperbaiki)

`{"timestamp": 1761800000}` (epoch detik) sebelumnya jadi Jan 1970.
Sekarang angka < 1e11 dibaca sebagai detik, sisanya sebagai ms.

## Terverifikasi aman (tidak diubah)

- **XSS dari data tak tepercaya**: 4 baris bermuatan (`<img onerror>`,
  `</li><script>`, `<svg onload>` di event JSON, host berisi
  `"><script>`) dirender sebagai teks ter-escape, tanpa `alert()`,
  tanpa elemen mentah di DOM — 16 cek klik jsdom lolos (tombol
  contoh, urutan kronologis, badge chain, search, filter sumber,
  toggle chain-only).
- **SIEM JSON bertimestamp sampah** -> skipped, bukan crash.
- **Perf**: 10.000 baris ter-parse dalam 38 ms (Node, VM ini).
- **Perilaku lama utuh**: 14 asersi awal tetap hijau, termasuk
  deteksi chain, quoting CSV, dan contoh insiden 6 event.

## Limitasi jujur (bawaan, bukan bug ronde ini)

- Satu event per baris; stack trace multi-baris tetap terpecah.
- Ekstraksi host/user dari teks bebas bersifat heuristik (mis.
  `on Monday` bisa terbaca sebagai host) — JSON SIEM tetap jalur
  yang presisi.
- Konversi zona waktu bersifat aritmetik atas offset; tidak memodelkan
  transisi DST untuk zona bernama (pakai offset eksplisit untuk log
  yang sensitif DST).
- Tahun 0–99 ditolak validasi tanggal (dianggap bukan tahun log
  modern); RFC 3164 tanpa tahun memakai tahun berjalan, jadi log
  31 Des yang dibuka pada 1 Jan akan bergeser setahun ke depan.

## Ronde Minggu (2026-11-01) — fresh-copy re-run + pendalaman

Fresh clone dari remote (`ae15d3c`, sama dengan HEAD Sabtu) lolos
penuh: suite Node 20/20 hijau, dan uji klik UI nyata via jsdom
13/13 lolos (contoh 6 event kronologis, badge chain, search, filter
sumber, toggle chain-only, skipped terhitung, empty notice, plus
4 payload XSS dirender sebagai teks ter-escape tanpa `alert()` dan
tanpa elemen mentah di DOM). Perf ulang: 10.000 baris dalam 48 ms.

### P2 — Timestamp SIEM epoch sebagai string dilewati (diperbaiki)

`{"timestamp": "1761800000"}` (dan `"1761800000000"`) di-skip total:
`Date` tidak mem-parse string digit murni sebagai epoch. Beberapa
ekspor SIEM mengeluarkan epoch sebagai string, jadi event-nya hilang
dari timeline tanpa jejak. Sekarang string digit murni memakai aturan
yang sama dengan angka (`< 1e11` = detik, sisanya ms). `timestamp: 0`
sengaja tetap di-skip (epoch 0 hampir pasti berarti timestamp hilang,
bukan event tahun 1970).

### P2 — ISO/RFC 5424/CSV dengan `z` kecil dilewati (diperbaiki)

`2026-10-30T10:00:00z` di-skip padahal `parseOffset` sudah menerima
`z`: regex jalur ISO, RFC 5424, dan browser CSV hanya mengizinkan
`Z` kapital. Sekarang `[Zz]` di ketiga jalur; `z` kecil terbukti
menghasilkan epoch yang identik dengan `Z`.

### Diamati, sengaja tidak diubah

- **CSV `;` + judul**: `url;Title` dirender sebagai pesan
  `— url;Title` (judul menempel di URL, bukan hilang) karena `\S+`
  rakus menelan `;`. Alternatif (URL malas) justru memotong URL yang
  mengandung `;` di query — perilaku sekarang lebih aman untuk
  fidelitas URL; judul tetap terbaca.
- **Chain case-sensitive**: `Admin` vs `admin` tidak di-chain.
  User Unix case-sensitive, jadi penggabungan paksa bisa menyatukan
  dua akun berbeda; perilaku sekarang konservatif (false negative
  lebih aman daripada false positive di alat triase).
- **Karakter kontrol di pesan** (mis. ESC) dipertahankan apa adanya:
  UI meng-escape HTML sehingga aman di browser, dan untuk alat
  forensik pesan mentah adalah barang bukti — stripping akan mengubah
  bukti.

Suite: 20 -> 22 asersi, semua hijau (lokal + ulang pasca-fix);
uji klik jsdom 13/13 hijau.

## Verdict final (Minggu)

v1.0.2 solid sebagai normalizer timeline belajar/triage: total 8 bug
nyata diperbaiki selama dua ronde audit (6 Sabtu + 2 Minggu), tidak
ada bug fungsional/adversarial baru yang tersisa dari probe ronde
ini, seluruh suite hijau di fresh copy maupun lokal, dan UI nyata
terverifikasi klik-per-klik termasuk ketahanan XSS. Limitasi jujur
di atas tetap berlaku (satu event per baris, heuristik host/user
teks bebas, tanpa model DST, tahun 0–99 ditolak).
