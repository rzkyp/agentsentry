# Changelog

## 0.3.0

**Pelaporan**

- `--format sarif` — keluaran SARIF 2.1.0, siap untuk GitHub code scanning
- `--summary-only` — header, ringkasan, dan tabel per aturan tanpa detail per temuan
- `--max-rows N` — batasi jumlah baris tabel di terminal
- Ringkasan "file dengan temuan terbanyak" ditambahkan
- `--baseline FILE` — akui temuan yang sudah diketahui (report JSON atau teks
  `RULE_ID path [line]`); temuan yang di-baseline tidak dihitung dan tidak memengaruhi
  exit code
- Ringkasan `--lang id` kini juga melaporkan jumlah temuan yang diakui

**Aturan**

- `NET-001` mengabaikan rentang dokumentasi (`192.0.2.0/24`, `198.51.100.0/24`,
  `203.0.113.0/24`), link-local, dan string mirip versi seperti `Chrome/124.0.0.0`
- `INJ-001` mewajibkan kata kerja berbahaya setelah `you must (always|now|instead)`,
  sehingga tugas biasa seperti "you must now upgrade" tidak lagi terdeteksi
- `EXEC-003` mengabaikan `eval()` / `exec()` yang ditulis sebagai prosa

**Penemuan target**

- `--exclude POLA` (berulang, fnmatch) untuk melewati vendor tree dan cache
- Direktori vendor/cache dilewati secara bawaan (`.venv`, `node_modules`, `.gradle`, …)
- Berkas JSON larger dari 64 KB dianggap data, bukan konfigurasi MCP

## 0.2.0

- `--exclude`, `--lang`, dan ringkasan berbahasa mudah di setiap laporan
- Filter false positive: alamat loopback/RFC1918, penunjuk skema JSON, rahasia placeholder
  (`your-api-key`, `DEMO_KEY`), serta prosa yang mengutip frasa injection
- Aturan prosa dibatasi pada berkas teks, sehingga skema JSON tidak lagi dipindai sebagai
  teks skill

## 0.1.0

- Rilis awal: 23 aturan deteksi, penemuan konfigurasi MCP dan agent skill,
  keluaran tabel/JSON/Markdown, exit code ramah CI
