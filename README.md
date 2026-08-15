# GarudaSentry

Tool intelijen ancaman siber (Cyber Threat Intelligence) berbasis Python untuk **mendeteksi, menganalisis, dan mendokumentasikan** indikasi situs judi online (judol) — termasuk kasus defacement/injeksi konten judol pada domain pemerintahan (`.go.id`) dan akademis (`.ac.id`).

Tool ini melakukan pemindaian **asinkron massal**, analisis **heuristik konten** (kata kunci, elemen tersembunyi, script obfuscated, redirect mencurigakan), pengayaan **forensik** (DNS, WHOIS, ASN/hosting), dan menghasilkan **laporan bukti digital** dalam format CSV & JSON yang siap dilampirkan pada laporan ke Kominfo/BSSN/Bareskrim.

---

## ⚖️ Catatan Etika & Legal

- Tool ini **hanya** melakukan request HTTP GET biasa (seperti browser) serta query DNS/WHOIS/RDAP yang bersifat **publik**. Tidak ada eksploitasi kerentanan, brute force, atau upaya akses tidak sah.
- Gunakan `--rate-limit` dan `--concurrency` yang wajar agar tidak membebani server target (terutama server pemerintah/kampus yang mungkin sudah lemah karena disusupi).
- Hasil deteksi bersifat **heuristik berbasis skor** — selalu lakukan verifikasi manual sebelum melaporkan resmi ke pihak berwenang.
- Laporkan temuan konten judi online melalui kanal resmi: [aduankonten.id](https://aduankonten.id) (Kominfo) atau kontak CSIRT/BSSN instansi terkait.

---

## 1. Instalasi

Membutuhkan Python 3.9+.

```bash
# (Opsional) buat virtual environment
python3 -m venv venv
source venv/bin/activate   # Linux/Mac
# venv\Scripts\activate    # Windows

# Install dependensi
pip install -r requirements.txt
```

Isi `requirements.txt`:
- `aiohttp` — async HTTP client
- `beautifulsoup4` + `lxml` — parsing DOM HTML
- `python-whois` — query WHOIS
- `ipwhois` — query RDAP (ASN/hosting provider)
- `dnspython` — resolusi DNS
- `rich` — console logging berwarna & tabel

---

## 2. Cara Menjalankan

### Scan satu domain/URL

```bash
python garuda_sentry.py --url contoh-kampus.ac.id
```

### Scan massal dari file daftar domain

Buat file `target.txt`, satu domain per baris (baris berawalan `#` diabaikan sebagai komentar):

```
# Daftar target pemindaian
kominfo-palsu-contoh.go.id
universitas-contoh.ac.id
https://sudah-lengkap-dengan-skema.go.id
```

Jalankan:

```bash
python garuda_sentry.py --file target.txt --concurrency 20 --rate-limit 8
```

### Argumen CLI lengkap

| Argumen | Default | Keterangan |
|---|---|---|
| `--url URL` | - | Satu domain/URL target tunggal (mutually exclusive dengan `--file`) |
| `--file FILE` | - | Path file berisi daftar domain (mutually exclusive dengan `--url`) |
| `--concurrency N` | `10` | Jumlah request bersamaan maksimum |
| `--rate-limit N` | `5` | Batas request per detik secara global (token bucket) |
| `--timeout N` | `15` | Timeout per request (detik) |
| `--retries N` | `3` | Jumlah percobaan ulang jika request gagal/timeout |
| `--output-dir DIR` | `./evidence_output` | Direktori tempat CSV & JSON hasil scan disimpan |
| `--no-whois` | off | Lewati query WHOIS (mempercepat scan) |
| `--no-asn` | off | Lewati query ASN/hosting provider |
| `--verbose` | off | Tampilkan detail temuan hidden element/JS langsung di konsol |

Contoh lanjutan:

```bash
# Scan cepat tanpa WHOIS/ASN, rate limit rendah untuk target sensitif
python garuda_sentry.py --file target.txt --no-whois --no-asn --rate-limit 2

# Scan dengan output detail penuh di konsol
python garuda_sentry.py --url contoh.go.id --verbose
```

---

## 3. Cara Kerja (Logika Tool)

### 3.1 Asynchronous Engine
- Semua request HTTP dijalankan lewat `aiohttp` + `asyncio.gather`, dibatasi oleh `asyncio.Semaphore` (jumlah koneksi bersamaan) dan sebuah **token bucket rate limiter** custom (`RateLimiter`) yang membatasi jumlah request/detik secara global — mencegah tool ini tanpa sengaja memicu efek DoS ke server target.
- Setiap request punya `timeout` dan mekanisme **retry dengan exponential backoff** (2s, 4s, 8s, ...) jika koneksi gagal/timeout.
- Domain tanpa skema dicoba dengan `https://` terlebih dahulu, fallback ke `http://` jika gagal.

### 3.2 Advanced Heuristic Detection
Setiap halaman yang berhasil diambil dianalisis lewat `analyze_content()`:

1. **Deteksi kata kunci judol** — regex atas judul, meta tag, teks tampak, dan raw HTML (agar teks yang disembunyikan lewat CSS tetap tertangkap) terhadap ~27 pola kata kunci umum (slot gacor, bandar togel, link alternatif, bonus member, dsb).
2. **Deteksi elemen tersembunyi** — memeriksa atribut `style` inline dan blok `<style>` untuk pola `display:none`, `visibility:hidden`, `opacity:0`, `font-size:0`, posisi off-screen, dsb. Juga memeriksa `<iframe>` berukuran 0px/1px atau bergaya tersembunyi.
3. **Deteksi JavaScript obfuscated** — memindai tag `<script>` untuk pola `eval()`, `unescape()`, `String.fromCharCode`, `atob()`, rentetan hex escape panjang, atau blob base64 panjang.
4. **Deteksi client-side redirect** — memeriksa `<meta http-equiv="refresh">` dan pola `window.location` / `window.location.replace` / `top.location` di JavaScript. Redirect ditandai **mencurigakan** jika domain tujuan berbeda dari domain asal.

### 3.3 Sistem Skor & Verdict

| Indikator | Bobot |
|---|---|
| Setiap kata kunci judol cocok | +2 |
| Setiap elemen tersembunyi mencurigakan | +3 |
| Setiap indikasi JS obfuscated | +2 |
| Redirect ke domain berbeda (suspicious) | +5 |

- **Skor 0** → `CLEAN`
- **Skor 1–4** → `SUSPICIOUS`
- **Skor ≥ 5** → `CRITICAL_JUDOL_DETECTED`

### 3.4 Reconnaissance & Forensics Enrichment
- **DNS**: resolusi A record via `dnspython` (dijalankan di thread executor agar tidak memblokir event loop asyncio).
- **WHOIS**: registrar, tanggal registrasi, negara via `python-whois`.
- **ASN/Hosting**: lookup RDAP via `ipwhois` untuk mendapatkan nomor ASN, deskripsi ASN (nama penyedia hosting/ISP), dan negara ASN — berguna untuk mengidentifikasi infrastruktur pelaku (misalnya hosting luar negeri yang sering dipakai judol).

### 3.5 Reporting
- **Console**: log berwarna via `rich` — hijau (`CLEAN`), kuning (`SUSPICIOUS`), merah (`CRITICAL/JUDOL DETECTED`), plus tabel ringkasan di akhir.
- **CSV** (`judol_scan_evidence_<timestamp>.csv`): satu baris per target, semua kolom bukti (status HTTP, IP, WHOIS, ASN, skor, verdict, kata kunci cocok, temuan hidden element/JS, redirect).
- **JSON** (`judol_scan_evidence_<timestamp>.json`): struktur lengkap `{"metadata": {...}, "results": [...]}` — metadata mencakup waktu scan, durasi, dan ringkasan jumlah per verdict, cocok sebagai lampiran laporan formal.

---

## 4. Struktur Output

```
evidence_output/
├── judol_scan_evidence_20260815_143000.csv
└── judol_scan_evidence_20260815_143000.json
```

---

## 5. Batasan Diketahui

- Deteksi bersifat heuristik berbasis pola — situs judol yang sangat baru pola kata kuncinya, atau yang menyembunyikan konten lewat rendering client-side kompleks (SPA berat JS), mungkin butuh headless browser (di luar cakupan tool ini) untuk analisis lebih dalam.
- Query WHOIS bisa lambat/dibatasi rate oleh registry tertentu — gunakan `--no-whois` untuk scan cepat berskala besar, lalu jalankan WHOIS terpisah hanya pada domain berverdict `SUSPICIOUS`/`CRITICAL`.
- Tool tidak menyimpan/menge-cache HTML mentah sebagai bukti; jika dibutuhkan sebagai bukti forensik tambahan, simpan response HTML secara manual (mis. via `curl -o` atau tangkapan layar) di luar tool ini.
