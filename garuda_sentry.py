#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
===============================================================================
 GARUDA SENTRY
 Threat Intelligence Tool untuk Deteksi Situs Judi Online (Judol)
 Fokus: Defacement pada domain pemerintahan (.go.id) & akademis (.ac.id)
===============================================================================

Deskripsi:
    Tool ini melakukan pemindaian massal secara asinkron terhadap daftar
    domain/URL untuk mendeteksi indikasi konten perjudian online, baik yang
    tampil terang-terangan maupun yang disisipkan secara tersembunyi (hasil
    defacement/injeksi). Tool mengumpulkan bukti forensik dasar (DNS, WHOIS,
    ASN/hosting) dan mengekspor hasil dalam format CSV & JSON sebagai bahan
    laporan ke regulator (Kominfo / Bareskrim / BSSN).

Catatan Etika & Legal:
    - Tool ini HANYA melakukan permintaan HTTP GET biasa (seperti browser)
      serta query DNS/WHOIS/RDAP yang bersifat publik. Tidak ada eksploitasi
      kerentanan, brute force, atau upaya akses tidak sah dalam bentuk apa pun.
    - Gunakan rate limiting yang wajar agar tidak membebani server target.
    - Hasil deteksi bersifat heuristik (berbasis skor indikator) dan tetap
      memerlukan verifikasi manual sebelum dilaporkan resmi ke pihak berwenang.

Author: Dibuat untuk kebutuhan Threat Hunting internal.
"""

import argparse
import asyncio
import csv
import json
import os
import re
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import List, Dict, Optional, Tuple
from urllib.parse import urlparse, urljoin

import aiohttp
from bs4 import BeautifulSoup

try:
    import whois as pywhois
except ImportError:
    pywhois = None

try:
    from ipwhois import IPWhois
except ImportError:
    IPWhois = None

try:
    import dns.resolver
except ImportError:
    dns = None

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

__version__ = "1.0.0"

console = Console()

# ==============================================================================
# 1. KONSTANTA & POLA DETEKSI (SIGNATURES)
# ==============================================================================

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 "
    "CyberAntiJudolScanner/1.0 (+threat-intel-research)"
)

# Kata kunci / frasa yang umum dipakai situs judi online (judol).
# Setiap entri: (label_terbaca, pola_regex). Pola regex toleran terhadap
# variasi spasi/karakter; label dipakai untuk laporan agar mudah dibaca manusia.
GAMBLING_KEYWORD_PATTERNS = [
    ("slot gacor", r"slot\s*gacor"),
    ("situs slot", r"situs\s*slot"),
    ("judi online", r"judi\s*online"),
    ("bandar togel/slot/bola", r"bandar\s*(togel|slot|bola|ceme|domino|poker)"),
    ("link alternatif", r"link\s*alternatif"),
    ("ajakan daftar akun", r"daftar\s*(sekarang|slot|togel|akun)"),
    ("bonus member/deposit", r"bonus\s*(new\s*member|deposit|cashback)"),
    ("maxwin", r"maxwin"),
    ("rtp live/slot", r"rtp\s*(live|slot|tertinggi)"),
    ("deposit e-wallet/pulsa", r"deposit\s*(pulsa|dana|ovo|gopay|qris)\s*(tanpa\s*potongan)?"),
    ("agen judi/slot/togel", r"agen\s*(judi|slot|togel|bola)"),
    ("casino online", r"casino\s*online"),
    ("togel online", r"togel\s*(online|hongkong|singapore|sgp|hk)"),
    ("slot88/slot online", r"slot\s*(88|gacor|online|terpercaya)"),
    ("wd cepat (istilah withdraw)", r"wd\s*cepat"),
    ("gacor hari ini", r"gacor\s*(hari\s*ini|malam\s*ini)"),
    ("klaim situs terpercaya judi", r"situs\s*(terpercaya|resmi)\s*(slot|togel|judi)"),
    ("jackpot terbesar", r"jackpot\s*terbesar"),
    ("anti rungkad", r"anti\s*rungkad"),
    ("scatter hitam/merah", r"scatter\s*(hitam|merah)"),
    ("toto togel/slot/4d", r"toto\s*(togel|slot|4d)"),
    ("spin gratis", r"spin\s*gratis"),
    ("free bet", r"free\s*bet"),
    ("pola gacor/jitu", r"pola\s*(gacor|jitu)"),
    ("prediksi togel/angka", r"prediksi\s*(togel|jitu|angka)"),
    ("klaim situs resmi no 1", r"situs\s*resmi\s*terpercaya\s*no\s*1"),
    ("nominal deposit minimal", r"minimal\s*deposit\s*\d+(rb|ribu|k)?"),
]

COMPILED_KEYWORD_PATTERNS = [
    (label, re.compile(pat, re.IGNORECASE)) for label, pat in GAMBLING_KEYWORD_PATTERNS
]

# Pola CSS inline yang sering dipakai untuk menyembunyikan konten injeksi.
HIDDEN_STYLE_PATTERNS = [
    re.compile(r"display\s*:\s*none", re.IGNORECASE),
    re.compile(r"visibility\s*:\s*hidden", re.IGNORECASE),
    re.compile(r"opacity\s*:\s*0(\.0+)?\b", re.IGNORECASE),
    re.compile(r"font-size\s*:\s*0(px)?\b", re.IGNORECASE),
    re.compile(r"width\s*:\s*0(px)?\s*;?\s*height\s*:\s*0(px)?", re.IGNORECASE),
    re.compile(r"position\s*:\s*absolute[^;]*(left|top)\s*:\s*-\d{3,}px", re.IGNORECASE),
    re.compile(r"text-indent\s*:\s*-\d{3,}px", re.IGNORECASE),
]

# Pola JavaScript yang mengindikasikan obfuscation / encoding mencurigakan.
# Setiap entri: (label_terbaca, pola_regex_compiled).
SUSPICIOUS_JS_PATTERNS = [
    ("penggunaan eval()", re.compile(r"eval\s*\(", re.IGNORECASE)),
    ("penggunaan unescape()", re.compile(r"unescape\s*\(", re.IGNORECASE)),
    ("String.fromCharCode (encoding karakter)", re.compile(r"String\.fromCharCode", re.IGNORECASE)),
    ("document.write + unescape", re.compile(r"document\.write\s*\(\s*unescape", re.IGNORECASE)),
    ("penggunaan atob() (decode base64)", re.compile(r"atob\s*\(", re.IGNORECASE)),
    ("rentetan hex escape panjang", re.compile(r"(?:\\x[0-9a-fA-F]{2}){10,}")),
    ("kemungkinan blob base64 panjang", re.compile(r"[A-Za-z0-9+/]{120,}={0,2}")),
]

# Pola redirect sisi klien.
JS_REDIRECT_PATTERNS = [
    re.compile(r"window\.location(\.href)?\s*=\s*['\"]([^'\"]+)['\"]", re.IGNORECASE),
    re.compile(r"window\.location\.replace\s*\(\s*['\"]([^'\"]+)['\"]\s*\)", re.IGNORECASE),
    re.compile(r"window\.location\.assign\s*\(\s*['\"]([^'\"]+)['\"]\s*\)", re.IGNORECASE),
    re.compile(r"top\.location(\.href)?\s*=\s*['\"]([^'\"]+)['\"]", re.IGNORECASE),
]

# Bobot skor untuk setiap kategori indikator (dipakai untuk verdict akhir).
SCORE_WEIGHT_KEYWORD = 2
SCORE_WEIGHT_HIDDEN_ELEMENT = 3
SCORE_WEIGHT_SUSPICIOUS_JS = 2
SCORE_WEIGHT_SUSPICIOUS_REDIRECT = 5

VERDICT_CLEAN = "CLEAN"
VERDICT_SUSPICIOUS = "SUSPICIOUS"
VERDICT_CRITICAL = "CRITICAL_JUDOL_DETECTED"


# ==============================================================================
# 2. STRUKTUR DATA HASIL SCAN
# ==============================================================================

@dataclass
class ScanResult:
    """Merepresentasikan satu baris hasil pemindaian (evidence record)."""
    domain: str
    url_scanned: str = ""
    final_url: str = ""
    http_status: Optional[int] = None
    ip_addresses: List[str] = field(default_factory=list)
    whois_registrar: str = "N/A"
    whois_creation_date: str = "N/A"
    whois_country: str = "N/A"
    asn: str = "N/A"
    asn_description: str = "N/A"
    asn_country: str = "N/A"
    detection_score: int = 0
    verdict: str = VERDICT_CLEAN
    matched_keywords: List[str] = field(default_factory=list)
    hidden_element_findings: List[str] = field(default_factory=list)
    suspicious_js_findings: List[str] = field(default_factory=list)
    redirect_detected: bool = False
    redirect_target: str = ""
    redirect_suspicious: bool = False
    error: str = ""
    scan_timestamp: str = ""

    def to_flat_dict(self) -> Dict:
        """Konversi ke dict datar (untuk CSV) - list digabung jadi string."""
        d = asdict(self)
        d["ip_addresses"] = "; ".join(self.ip_addresses)
        d["matched_keywords"] = "; ".join(self.matched_keywords)
        d["hidden_element_findings"] = "; ".join(self.hidden_element_findings)
        d["suspicious_js_findings"] = "; ".join(self.suspicious_js_findings)
        return d


# ==============================================================================
# 3. RATE LIMITER (TOKEN BUCKET) - MENCEGAH TOOL MEMICU DoS
# ==============================================================================

class RateLimiter:
    """
    Token bucket sederhana & thread-safe (async-safe) untuk membatasi
    jumlah request per detik secara global di seluruh coroutine.
    """

    def __init__(self, rate_per_second: float):
        self.rate = max(rate_per_second, 0.1)
        self.allowance = self.rate
        self.last_check = time.monotonic()
        self.lock = asyncio.Lock()

    async def acquire(self):
        async with self.lock:
            current = time.monotonic()
            elapsed = current - self.last_check
            self.last_check = current
            self.allowance += elapsed * self.rate
            if self.allowance > self.rate:
                self.allowance = self.rate
            if self.allowance < 1.0:
                sleep_time = (1.0 - self.allowance) / self.rate
                await asyncio.sleep(sleep_time)
                self.allowance = 0.0
            else:
                self.allowance -= 1.0


# ==============================================================================
# 4. UTILITAS TARGET
# ==============================================================================

def load_targets_from_file(path: str) -> List[str]:
    """Membaca daftar domain dari file teks (satu domain per baris)."""
    targets = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            targets.append(line)
    return targets


def build_candidate_urls(raw_target: str) -> Tuple[str, List[str]]:
    """
    Menormalisasi input target menjadi (domain, [daftar_url_kandidat]).
    Jika input sudah berupa URL lengkap, hanya URL tersebut yang dipakai.
    Jika input berupa domain polos, dicoba HTTPS terlebih dahulu lalu HTTP.
    """
    raw_target = raw_target.strip()
    if raw_target.startswith("http://") or raw_target.startswith("https://"):
        parsed = urlparse(raw_target)
        domain = parsed.netloc
        return domain, [raw_target]
    domain = raw_target
    return domain, [f"https://{domain}", f"http://{domain}"]


def extract_domain(url: str) -> str:
    try:
        return urlparse(url).netloc.split(":")[0]
    except Exception:
        return url


# ==============================================================================
# 5. RECONNAISSANCE: DNS, WHOIS, ASN/HOSTING
# ==============================================================================

async def resolve_dns(domain: str, loop: asyncio.AbstractEventLoop, timeout: int = 5) -> List[str]:
    """Resolusi DNS (A record) domain menjadi daftar IP Address."""
    if dns is None:
        return []
    domain = domain.split(":")[0]

    def _resolve():
        try:
            resolver = dns.resolver.Resolver()
            resolver.lifetime = timeout
            resolver.timeout = timeout
            answers = resolver.resolve(domain, "A")
            return [str(r) for r in answers]
        except Exception:
            return []

    try:
        return await asyncio.wait_for(loop.run_in_executor(None, _resolve), timeout=timeout + 2)
    except Exception:
        return []


async def get_whois_info(domain: str, loop: asyncio.AbstractEventLoop, timeout: int = 10) -> Dict:
    """Query data WHOIS domain: registrar, tanggal registrasi, negara."""
    result = {"registrar": "N/A", "creation_date": "N/A", "country": "N/A"}
    if pywhois is None:
        return result

    domain = domain.split(":")[0]

    def _lookup():
        return pywhois.whois(domain)

    try:
        w = await asyncio.wait_for(loop.run_in_executor(None, _lookup), timeout=timeout)
        if not w:
            return result

        registrar = getattr(w, "registrar", None)
        if isinstance(registrar, list):
            registrar = registrar[0] if registrar else None
        result["registrar"] = str(registrar) if registrar else "N/A"

        creation_date = getattr(w, "creation_date", None)
        if isinstance(creation_date, list):
            creation_date = creation_date[0] if creation_date else None
        if isinstance(creation_date, datetime):
            result["creation_date"] = creation_date.strftime("%Y-%m-%d")
        elif creation_date:
            result["creation_date"] = str(creation_date)

        country = getattr(w, "country", None)
        if isinstance(country, list):
            country = country[0] if country else None
        result["country"] = str(country) if country else "N/A"

    except Exception:
        pass

    return result


async def get_asn_info(ip: str, loop: asyncio.AbstractEventLoop, timeout: int = 10) -> Dict:
    """Query RDAP (via ipwhois) untuk mendapatkan ASN dan penyedia hosting."""
    result = {"asn": "N/A", "asn_description": "N/A", "asn_country": "N/A"}
    if IPWhois is None or not ip:
        return result

    def _lookup():
        obj = IPWhois(ip)
        return obj.lookup_rdap(depth=1)

    try:
        data = await asyncio.wait_for(loop.run_in_executor(None, _lookup), timeout=timeout)
        result["asn"] = str(data.get("asn", "N/A") or "N/A")
        result["asn_description"] = str(data.get("asn_description", "N/A") or "N/A")
        result["asn_country"] = str(data.get("asn_country_code", "N/A") or "N/A")
    except Exception:
        pass

    return result


# ==============================================================================
# 6. FETCH ENGINE (ASYNC, TIMEOUT, RETRY)
# ==============================================================================

async def fetch_url(
    session: aiohttp.ClientSession,
    url: str,
    timeout_sec: int,
    max_retries: int,
    rate_limiter: RateLimiter,
) -> Dict:
    """
    Mengambil konten sebuah URL secara asinkron dengan rate limiting,
    timeout, dan retry dengan exponential backoff.
    """
    last_error = None
    for attempt in range(1, max_retries + 1):
        await rate_limiter.acquire()
        try:
            client_timeout = aiohttp.ClientTimeout(total=timeout_sec)
            async with session.get(
                url,
                timeout=client_timeout,
                ssl=False,
                allow_redirects=True,
                headers={"User-Agent": DEFAULT_USER_AGENT},
            ) as resp:
                html = await resp.text(errors="ignore")
                return {
                    "status": resp.status,
                    "html": html,
                    "headers": dict(resp.headers),
                    "final_url": str(resp.url),
                    "error": None,
                }
        except asyncio.TimeoutError:
            last_error = "Timeout saat mengambil koneksi"
        except aiohttp.ClientConnectorError as e:
            last_error = f"Gagal terhubung: {e}"
        except aiohttp.ClientError as e:
            last_error = f"Client error: {e}"
        except Exception as e:
            last_error = f"Unexpected error: {e}"

        if attempt < max_retries:
            backoff = min(2 ** attempt, 8)
            await asyncio.sleep(backoff)

    return {"status": None, "html": "", "headers": {}, "final_url": url, "error": last_error}


# ==============================================================================
# 7. HEURISTIC DETECTION ENGINE
# ==============================================================================

def detect_keywords(text: str) -> List[str]:
    """Mendeteksi kata kunci judol dalam teks (title, meta, body, raw html).
    Mengembalikan label yang mudah dibaca manusia (bukan pola regex mentah)."""
    matches = []
    for label, pattern in COMPILED_KEYWORD_PATTERNS:
        if pattern.search(text):
            matches.append(label)
    return matches


def detect_hidden_elements(soup: BeautifulSoup) -> List[str]:
    """Mendeteksi elemen tersembunyi via CSS inline atau iframe mencurigakan."""
    findings = []

    # Cek atribut style inline di semua tag
    for tag in soup.find_all(style=True):
        style_value = tag.get("style", "")
        for pattern in HIDDEN_STYLE_PATTERNS:
            if pattern.search(style_value):
                tag_name = tag.name
                snippet = style_value.strip()[:80]
                findings.append(f"<{tag_name}> style tersembunyi: '{snippet}'")
                break

    # Cek <style> block terpisah untuk class yang mengarah ke display:none dsb.
    for style_tag in soup.find_all("style"):
        css_text = style_tag.get_text() or ""
        for pattern in HIDDEN_STYLE_PATTERNS:
            if pattern.search(css_text):
                findings.append("Blok <style> mengandung aturan penyembunyian elemen")
                break

    # Cek iframe mencurigakan: ukuran 0/1px, atau style hidden
    for iframe in soup.find_all("iframe"):
        width = (iframe.get("width") or "").strip()
        height = (iframe.get("height") or "").strip()
        style_value = iframe.get("style", "")
        src = iframe.get("src", "unknown-src")
        is_tiny = width in ("0", "0px", "1", "1px") or height in ("0", "0px", "1", "1px")
        is_hidden_style = any(p.search(style_value) for p in HIDDEN_STYLE_PATTERNS)
        if is_tiny or is_hidden_style:
            findings.append(f"<iframe> tersembunyi/berukuran nol, src='{src[:100]}'")

    return findings


def detect_obfuscated_js(soup: BeautifulSoup) -> List[str]:
    """Mendeteksi indikasi JavaScript ter-obfuscate/encoded di dalam <script>."""
    findings = []
    for script_tag in soup.find_all("script"):
        content = script_tag.string or script_tag.get_text() or ""
        if not content.strip():
            continue
        for label, pattern in SUSPICIOUS_JS_PATTERNS:
            if pattern.search(content):
                snippet = re.sub(r"\s+", " ", content.strip())[:100]
                findings.append(f"{label} - cuplikan script: '{snippet}'")
                break
    return findings


def detect_redirect(html: str, soup: BeautifulSoup, base_domain: str) -> Tuple[bool, str, bool]:
    """
    Mendeteksi client-side redirect via meta refresh atau window.location.
    Mengembalikan (terdeteksi, target_url, apakah_mencurigakan).
    Redirect dianggap mencurigakan jika domain tujuan berbeda dari domain asal.
    """
    # Meta refresh
    meta_refresh = soup.find("meta", attrs={"http-equiv": re.compile("refresh", re.IGNORECASE)})
    if meta_refresh and meta_refresh.get("content"):
        content_val = meta_refresh.get("content")
        url_match = re.search(r"url\s*=\s*['\"]?([^'\";]+)", content_val, re.IGNORECASE)
        if url_match:
            target = url_match.group(1).strip()
            target_domain = extract_domain(urljoin(f"https://{base_domain}", target))
            suspicious = bool(target_domain) and target_domain != base_domain
            return True, target, suspicious

    # JavaScript redirect
    for script_tag in soup.find_all("script"):
        content = script_tag.string or script_tag.get_text() or ""
        if not content:
            continue
        for pattern in JS_REDIRECT_PATTERNS:
            m = pattern.search(content)
            if m:
                target = m.group(m.lastindex)
                target_domain = extract_domain(urljoin(f"https://{base_domain}", target))
                suspicious = bool(target_domain) and target_domain != base_domain
                return True, target, suspicious

    return False, "", False


@dataclass
class DetectionAnalysis:
    score: int
    verdict: str
    matched_keywords: List[str]
    hidden_findings: List[str]
    js_findings: List[str]
    redirect_detected: bool
    redirect_target: str
    redirect_suspicious: bool


def analyze_content(html: str, base_domain: str) -> DetectionAnalysis:
    """Menjalankan seluruh pipeline analisis heuristik atas konten HTML."""
    if not html:
        return DetectionAnalysis(0, VERDICT_CLEAN, [], [], [], False, "", False)

    soup = BeautifulSoup(html, "lxml")

    title = soup.title.get_text() if soup.title else ""
    meta_texts = []
    for meta_tag in soup.find_all("meta"):
        content_val = meta_tag.get("content")
        if content_val:
            meta_texts.append(content_val)
    visible_text = soup.get_text(separator=" ", strip=True)

    combined_text = " ".join([title, " ".join(meta_texts), visible_text, html])

    matched_keywords = detect_keywords(combined_text)
    hidden_findings = detect_hidden_elements(soup)
    js_findings = detect_obfuscated_js(soup)
    redirect_detected, redirect_target, redirect_suspicious = detect_redirect(html, soup, base_domain)

    score = (
        len(matched_keywords) * SCORE_WEIGHT_KEYWORD
        + len(hidden_findings) * SCORE_WEIGHT_HIDDEN_ELEMENT
        + len(js_findings) * SCORE_WEIGHT_SUSPICIOUS_JS
        + (SCORE_WEIGHT_SUSPICIOUS_REDIRECT if redirect_suspicious else 0)
    )

    if score <= 0:
        verdict = VERDICT_CLEAN
    elif score < 5:
        verdict = VERDICT_SUSPICIOUS
    else:
        verdict = VERDICT_CRITICAL

    return DetectionAnalysis(
        score=score,
        verdict=verdict,
        matched_keywords=matched_keywords,
        hidden_findings=hidden_findings,
        js_findings=js_findings,
        redirect_detected=redirect_detected,
        redirect_target=redirect_target,
        redirect_suspicious=redirect_suspicious,
    )


# ==============================================================================
# 8. ORKESTRASI PEMINDAIAN PER TARGET
# ==============================================================================

async def scan_target(
    raw_target: str,
    session: aiohttp.ClientSession,
    semaphore: asyncio.Semaphore,
    rate_limiter: RateLimiter,
    args: argparse.Namespace,
    loop: asyncio.AbstractEventLoop,
) -> ScanResult:
    """Menjalankan seluruh alur pemindaian untuk satu target (fetch, recon, analisis)."""
    domain, candidate_urls = build_candidate_urls(raw_target)
    result = ScanResult(domain=domain, scan_timestamp=datetime.now(timezone.utc).isoformat())

    async with semaphore:
        fetch_data = None
        last_error = "Tidak ada URL kandidat"
        for candidate_url in candidate_urls:
            fetch_data = await fetch_url(session, candidate_url, args.timeout, args.retries, rate_limiter)
            result.url_scanned = candidate_url
            if fetch_data["status"] is not None:
                last_error = None
                break
            last_error = fetch_data["error"]

        result.final_url = fetch_data["final_url"] if fetch_data else result.url_scanned
        result.http_status = fetch_data["status"] if fetch_data else None
        result.error = last_error or ""

        # --- Reconnaissance (DNS, WHOIS, ASN) dijalankan paralel ---
        dns_task = resolve_dns(domain, loop)
        whois_task = (
            get_whois_info(domain, loop) if not args.no_whois else _noop_whois()
        )
        result.ip_addresses = await dns_task
        whois_info = await whois_task
        result.whois_registrar = whois_info["registrar"]
        result.whois_creation_date = whois_info["creation_date"]
        result.whois_country = whois_info["country"]

        if not args.no_asn and result.ip_addresses:
            asn_info = await get_asn_info(result.ip_addresses[0], loop)
            result.asn = asn_info["asn"]
            result.asn_description = asn_info["asn_description"]
            result.asn_country = asn_info["asn_country"]

        # --- Analisis konten heuristik ---
        if fetch_data and fetch_data["html"]:
            analysis = analyze_content(fetch_data["html"], extract_domain(result.final_url) or domain)
            result.detection_score = analysis.score
            result.verdict = analysis.verdict
            result.matched_keywords = analysis.matched_keywords
            result.hidden_element_findings = analysis.hidden_findings
            result.suspicious_js_findings = analysis.js_findings
            result.redirect_detected = analysis.redirect_detected
            result.redirect_target = analysis.redirect_target
            result.redirect_suspicious = analysis.redirect_suspicious
        else:
            result.verdict = VERDICT_CLEAN if not result.error else "UNREACHABLE"

    print_live_result(result, args.verbose)
    return result


async def _noop_whois() -> Dict:
    return {"registrar": "N/A (dilewati)", "creation_date": "N/A", "country": "N/A"}


# ==============================================================================
# 9. REPORTING - CONSOLE (RICH)
# ==============================================================================

def print_banner():
    banner_text = Text()
    banner_text.append("GARUDA SENTRY", style="bold white")
    banner_text.append(f"  v{__version__}\n", style="dim")
    banner_text.append("Threat Intelligence Tool - Deteksi Situs Judi Online & Defacement .go.id/.ac.id", style="cyan")
    console.print(Panel(banner_text, border_style="bright_blue", expand=False))


def print_live_result(result: ScanResult, verbose: bool = False):
    """Mencetak satu baris log hasil scan secara real-time dengan warna sesuai level."""
    if result.verdict == VERDICT_CRITICAL:
        style = "bold white on red"
        label = "CRITICAL/JUDOL DETECTED"
    elif result.verdict == VERDICT_SUSPICIOUS:
        style = "bold black on yellow"
        label = "WARNING/SUSPICIOUS"
    elif result.verdict == "UNREACHABLE":
        style = "dim white"
        label = "UNREACHABLE"
    else:
        style = "bold green"
        label = "CLEAN"

    header = f" [{label}] {result.domain} "
    console.print(Text(header, style=style))

    detail_lines = [f"  Status HTTP : {result.http_status or '-'}   Skor Deteksi: {result.detection_score}"]
    if result.ip_addresses:
        detail_lines.append(f"  IP          : {', '.join(result.ip_addresses)}")
    if result.asn != "N/A":
        detail_lines.append(f"  ASN/Hosting : {result.asn} - {result.asn_description}")
    if result.matched_keywords:
        kw_preview = ", ".join(result.matched_keywords[:5])
        more = f" (+{len(result.matched_keywords)-5} lainnya)" if len(result.matched_keywords) > 5 else ""
        detail_lines.append(f"  Keyword     : {kw_preview}{more}")
    if result.hidden_element_findings:
        detail_lines.append(f"  Hidden Elmt : {len(result.hidden_element_findings)} temuan")
    if result.suspicious_js_findings:
        detail_lines.append(f"  Susp. JS    : {len(result.suspicious_js_findings)} temuan")
    if result.redirect_detected:
        flag = "MENCURIGAKAN" if result.redirect_suspicious else "internal"
        detail_lines.append(f"  Redirect    : -> {result.redirect_target} [{flag}]")
    if result.error:
        detail_lines.append(f"  Error       : {result.error}")

    console.print("\n".join(detail_lines), style="dim" if result.verdict == "CLEAN" else "")

    if verbose:
        for finding in result.hidden_element_findings:
            console.print(f"    - {finding}", style="yellow")
        for finding in result.suspicious_js_findings:
            console.print(f"    - {finding}", style="yellow")

    console.print()


def print_summary_table(results: List[ScanResult]):
    table = Table(title="Ringkasan Hasil Pemindaian", show_lines=False)
    table.add_column("Verdict", style="bold")
    table.add_column("Jumlah", justify="right")

    counts = {}
    for r in results:
        counts[r.verdict] = counts.get(r.verdict, 0) + 1

    verdict_order = [VERDICT_CRITICAL, VERDICT_SUSPICIOUS, VERDICT_CLEAN, "UNREACHABLE"]
    color_map = {
        VERDICT_CRITICAL: "red",
        VERDICT_SUSPICIOUS: "yellow",
        VERDICT_CLEAN: "green",
        "UNREACHABLE": "dim",
    }
    for v in verdict_order:
        if v in counts:
            table.add_row(Text(v, style=color_map.get(v, "white")), str(counts[v]))

    console.print(table)
    console.print(f"Total target dipindai: [bold]{len(results)}[/bold]\n")


# ==============================================================================
# 10. REPORTING - EKSPOR CSV & JSON (DIGITAL EVIDENCE)
# ==============================================================================

CSV_FIELDNAMES = [
    "domain", "url_scanned", "final_url", "http_status", "ip_addresses",
    "whois_registrar", "whois_creation_date", "whois_country",
    "asn", "asn_description", "asn_country",
    "detection_score", "verdict", "matched_keywords",
    "hidden_element_findings", "suspicious_js_findings",
    "redirect_detected", "redirect_target", "redirect_suspicious",
    "error", "scan_timestamp",
]


def export_csv(results: List[ScanResult], path: str):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDNAMES)
        writer.writeheader()
        for r in results:
            writer.writerow(r.to_flat_dict())


def export_json(results: List[ScanResult], path: str, metadata: Dict):
    payload = {
        "metadata": metadata,
        "results": [asdict(r) for r in results],
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)


# ==============================================================================
# 11. ENTRY POINT / CLI
# ==============================================================================

def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="garuda_sentry.py",
        description="GarudaSentry - Deteksi situs judi online & defacement .go.id/.ac.id",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Contoh penggunaan:\n"
            "  python garuda_sentry.py --url contoh-kampus.ac.id\n"
            "  python garuda_sentry.py --file target.txt --concurrency 20 --rate-limit 8\n"
        ),
    )
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument("--url", type=str, help="Satu domain/URL target tunggal.")
    target_group.add_argument("--file", type=str, help="Path file berisi daftar domain (satu per baris).")

    parser.add_argument("--concurrency", type=int, default=10, help="Jumlah request bersamaan maksimum (default: 10).")
    parser.add_argument("--rate-limit", type=float, default=5.0, help="Batas request per detik global (default: 5).")
    parser.add_argument("--timeout", type=int, default=15, help="Timeout per request dalam detik (default: 15).")
    parser.add_argument("--retries", type=int, default=3, help="Jumlah percobaan ulang jika gagal (default: 3).")
    parser.add_argument("--output-dir", type=str, default="./evidence_output", help="Direktori output laporan.")
    parser.add_argument("--no-whois", action="store_true", help="Lewati query WHOIS (mempercepat scan).")
    parser.add_argument("--no-asn", action="store_true", help="Lewati query ASN/hosting.")
    parser.add_argument("--verbose", action="store_true", help="Tampilkan detail temuan hidden element/JS di konsol.")

    return parser.parse_args()


async def run_scanner(args: argparse.Namespace) -> List[ScanResult]:
    if args.file:
        targets = load_targets_from_file(args.file)
    else:
        targets = [args.url]

    if not targets:
        console.print("[bold red]Tidak ada target valid ditemukan.[/bold red]")
        return []

    console.print(f"[bold]Total target:[/bold] {len(targets)}")
    console.print(
        f"[bold]Konfigurasi:[/bold] concurrency={args.concurrency}, "
        f"rate_limit={args.rate_limit}/s, timeout={args.timeout}s, retries={args.retries}\n"
    )

    loop = asyncio.get_event_loop()
    semaphore = asyncio.Semaphore(args.concurrency)
    rate_limiter = RateLimiter(args.rate_limit)

    connector = aiohttp.TCPConnector(limit=args.concurrency * 2, ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [
            scan_target(target, session, semaphore, rate_limiter, args, loop)
            for target in targets
        ]
        results = await asyncio.gather(*tasks)

    return list(results)


def main():
    print_banner()
    args = parse_arguments()

    os.makedirs(args.output_dir, exist_ok=True)

    start_time = time.time()
    try:
        results = asyncio.run(run_scanner(args))
    except KeyboardInterrupt:
        console.print("\n[bold red]Pemindaian dihentikan oleh pengguna.[/bold red]")
        sys.exit(130)

    elapsed = time.time() - start_time

    if not results:
        console.print("[yellow]Tidak ada hasil untuk dilaporkan.[/yellow]")
        return

    print_summary_table(results)

    timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_path = os.path.join(args.output_dir, f"judol_scan_evidence_{timestamp_str}.csv")
    json_path = os.path.join(args.output_dir, f"judol_scan_evidence_{timestamp_str}.json")

    metadata = {
        "tool_name": "GarudaSentry",
        "tool_version": __version__,
        "scan_started_utc": datetime.fromtimestamp(start_time, tz=timezone.utc).isoformat(),
        "scan_duration_seconds": round(elapsed, 2),
        "total_targets": len(results),
        "critical_count": sum(1 for r in results if r.verdict == VERDICT_CRITICAL),
        "suspicious_count": sum(1 for r in results if r.verdict == VERDICT_SUSPICIOUS),
        "clean_count": sum(1 for r in results if r.verdict == VERDICT_CLEAN),
    }

    export_csv(results, csv_path)
    export_json(results, json_path, metadata)

    console.print(f"[bold green]Laporan CSV  :[/bold green] {csv_path}")
    console.print(f"[bold green]Laporan JSON :[/bold green] {json_path}")
    console.print(f"[dim]Durasi scan: {elapsed:.2f} detik[/dim]")


if __name__ == "__main__":
    main()
