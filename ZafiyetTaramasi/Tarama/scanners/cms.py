import re
import requests
from urllib.parse import urlparse
from bs4 import BeautifulSoup

from .base import Scanner, ScanResult, Finding, Severity, Confidence, FindingStatus
from ..services.evidence_redaction import redact_then_truncate
from ..services.safe_http import SafeSession, safe_session


_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

_OWASP_MISCONFIG = "A05:2021 - Security Misconfiguration"
_CWE_SENSITIVE_FILE = "CWE-538"  # Insertion of Sensitive Information into Externally-Accessible File or Directory

# CMS parmak izi: (pattern, cms_name, confidence) — generator/JS-marker imzaları yol-tabanlı imzalardan daha güvenilir
_CMS_SIGNATURES = [
    (r"/wp-content/",               "WordPress", Confidence.MEDIUM),
    (r"/wp-includes/",              "WordPress", Confidence.MEDIUM),
    (r'name="generator"[^>]*WordPress', "WordPress", Confidence.HIGH),
    (r"joomla",                     "Joomla",    Confidence.MEDIUM),
    (r"/components/com_",           "Joomla",    Confidence.MEDIUM),
    (r"Drupal\.settings",           "Drupal",    Confidence.HIGH),
    (r"/sites/default/files/",      "Drupal",    Confidence.MEDIUM),
    (r'name="generator"[^>]*Drupal', "Drupal",   Confidence.HIGH),
    (r"typo3",                      "TYPO3",     Confidence.MEDIUM),
    (r'name="generator"[^>]*TYPO3', "TYPO3",     Confidence.HIGH),
]

# Versiyon sızdıran yollar: (path, description)
_VERSION_PATHS = [
    ("/readme.html",              "WordPress readme"),
    ("/license.txt",              "WordPress lisans"),
    ("/wp-links-opml.php",        "WordPress OPML endpoint"),
    ("/administrator/README.txt", "Joomla README"),
    ("/CHANGELOG.txt",            "Drupal CHANGELOG"),
    ("/INSTALL.txt",              "Drupal INSTALL"),
]

# Hassas / açık dosyalar: (path, severity, description)
_SENSITIVE_PATHS = [
    ("/.env",                Severity.CRITICAL, "Ortam değişkenleri (secret key, DB şifresi)"),
    ("/.git/config",         Severity.CRITICAL, "Git deposu açığa çıkmış"),
    ("/config.php",          Severity.HIGH,     "PHP yapılandırma dosyası"),
    ("/configuration.php",   Severity.HIGH,     "Joomla yapılandırma dosyası"),
    ("/wp-config.php.bak",   Severity.HIGH,     "WordPress yapılandırma yedeği"),
    ("/backup.sql",          Severity.CRITICAL, "Veritabanı yedeği"),
    ("/db.sql",              Severity.CRITICAL, "Veritabanı dökümü"),
    ("/phpinfo.php",         Severity.HIGH,     "PHP bilgi sayfası"),
    ("/server-status",       Severity.MEDIUM,   "Apache server-status"),
    ("/elmah.axd",           Severity.HIGH,     ".NET hata logu"),
]

# İçerik doğrulama imzaları — yol var + HTTP 200 tek başına yeterli kanıt değildir
# (SPA/catch-all route'lar her yolu 200 ile HTML döndürebilir)
_SENSITIVE_PATH_MARKERS: dict[str, tuple[str, ...]] = {
    "/.git/config":       ("[core]", "repositoryformatversion", "[remote"),
    "/config.php":        ("<?php", "define(", "DB_"),
    "/configuration.php": ("<?php", "jconfig", "$db"),
    "/wp-config.php.bak":  ("db_name", "db_password", "wp-config", "define("),
    "/backup.sql":        ("create table", "insert into", "mysql dump"),
    "/db.sql":            ("create table", "insert into", "mysql dump"),
    "/phpinfo.php":       ("phpinfo()", "php version"),
    "/server-status":     ("apache server status", "current time:"),
    "/elmah.axd":         ("error log for", "elmah"),
}

# Admin panel yolları
_ADMIN_PATHS = [
    ("/wp-admin/",      "WordPress Admin"),
    ("/administrator/", "Joomla Admin"),
    ("/admin/",         "Admin Panel"),
    ("/panel/",         "Panel"),
    ("/dashboard/",     "Dashboard"),
    ("/login.php",      "Login"),
]


def _text_snippet(html: str, max_len: int = 250) -> str:
    """HTML'den tag'leri temizler ve ilk anlamlı metni döner.

    Hedef dosya içeriği (.env, config, SQL dump) gerçek gizli değerler içerebilir:
    redaksiyon satır yapısı korunurken ve HER kırpmadan önce yapılır.
    """
    clean = redact_then_truncate(html, 64 * 1024)
    clean = re.sub(r'<[^>]+>', ' ', clean)
    clean = ' '.join(clean.split())
    return clean[:max_len] + ("…" if len(clean) > max_len else "")


def _page_title(html: str) -> str:
    m = re.search(r'<title[^>]*>([^<]{1,120})</title>', html, re.I)
    return m.group(1).strip() if m else ""


def _looks_like_generic_html(text: str) -> bool:
    return text.lstrip()[:15].lower().startswith(("<!doctype html", "<html"))


def _verify_sensitive_content(path: str, text: str) -> bool:
    """İçeriğin gerçekten beklenen hassas dosya türüyle eşleştiğini doğrular."""
    if path == "/.env":
        return bool(re.search(r'(?m)^[A-Z][A-Z0-9_]*\s*=', text))
    markers = _SENSITIVE_PATH_MARKERS.get(path)
    if not markers:
        return True
    lower = text.lower()
    return any(m in lower for m in markers)


class CmsScanner(Scanner):
    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout

    def _make_session(self) -> SafeSession:
        s = safe_session()
        s.headers["User-Agent"] = _USER_AGENT
        return s

    def _get(self, session: requests.Session, url: str) -> requests.Response | None:
        try:
            return session.get(url, timeout=self.timeout, allow_redirects=True)
        except requests.RequestException:
            return None

    def scan(self, target: str) -> ScanResult:
        result  = ScanResult(scanner="cms", target=target)
        session = self._make_session()

        res = self._get(session, target)
        if not res:
            result.error = "Ana sayfa alınamadı"
            return result

        html = res.text
        soup = BeautifulSoup(html, "html.parser")
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.hostname}"

        self._detect_cms(html, target, result)
        self._check_generator_tag(soup, target, result)
        self._check_version_paths(session, base, target, result)
        self._check_sensitive_paths(session, base, target, result)
        self._check_admin_paths(session, base, target, result)
        self._check_robots(session, base, target, result)

        return result

    # --- CMS tespiti ---

    def _detect_cms(self, html: str, target: str, result: ScanResult) -> None:
        cms_evidence: dict[str, list[str]] = {}
        cms_confidence: dict[str, Confidence] = {}
        for pattern, cms_name, confidence in _CMS_SIGNATURES:
            m = re.search(pattern, html, re.IGNORECASE)
            if m:
                cms_evidence.setdefault(cms_name, [])
                matched = m.group(0)[:80]
                if matched not in cms_evidence[cms_name]:
                    cms_evidence[cms_name].append(matched)
                # Birden fazla imza eşleşirse en güçlü kanıtı kullan
                if confidence == Confidence.HIGH or cms_name not in cms_confidence:
                    cms_confidence[cms_name] = confidence

        if cms_evidence:
            for cms, matches in cms_evidence.items():
                result.findings.append(Finding(
                    severity=Severity.INFO,
                    title=f"CMS Tespit Edildi: {cms}",
                    evidence=f"Eşleşen imza(lar): {' | '.join(matches[:3])}",
                    confidence=cms_confidence[cms],
                    status=FindingStatus.INFORMATIONAL,
                    description="CMS fingerprinting is reconnaissance information, not a vulnerability by itself.",
                    affected_url=target,
                ))
        else:
            result.findings.append(Finding(
                severity=Severity.INFO,
                title="Bilinen CMS tespit edilmedi",
                evidence="WordPress / Joomla / Drupal / TYPO3 imzası bulunamadı",
                confidence=Confidence.MEDIUM,
                status=FindingStatus.INFORMATIONAL,
                description="No known CMS fingerprint was found. This does not confirm the absence of a CMS "
                            "— it may use a fingerprint not in this scanner's signature list.",
                affected_url=target,
            ))

    # --- Generator meta tag ---

    def _check_generator_tag(self, soup, target: str, result: ScanResult) -> None:
        generator = soup.find("meta", attrs={"name": re.compile("generator", re.I)})
        if generator and generator.get("content"):
            result.findings.append(Finding(
                severity=Severity.LOW,
                title="Generator meta tag — sürüm sızıntısı",
                evidence=generator["content"],
                confidence=Confidence.MEDIUM,
                status=FindingStatus.INFORMATIONAL,
                description="The generator meta tag discloses CMS/version information. This is treated as "
                            "informational version disclosure, not a confirmed vulnerability — no CVE is "
                            "inferred from this string.",
                affected_url=target,
                owasp=_OWASP_MISCONFIG,
                recommendation="Remove or genericize the generator meta tag if minimizing fingerprinting is desired.",
            ))

    # --- Versiyon sızdıran yollar ---

    def _check_version_paths(self, session: requests.Session,
                              base: str, target: str, result: ScanResult) -> None:
        for path, description in _VERSION_PATHS:
            r = self._get(session, base + path)
            if not r or r.status_code != 200 or len(r.content) < 100:
                continue
            version = self._extract_version(r.text)
            snippet = _text_snippet(r.text, 200)
            evidence = description
            if version:
                evidence += f" — Sürüm: {version}"
            evidence += f" | Kanıt: {snippet}"
            result.findings.append(Finding(
                severity=Severity.LOW if version else Severity.INFO,
                title=f"Sürüm bilgisi açığa çıkmış: {path}",
                evidence=evidence,
                confidence=Confidence.MEDIUM if version else Confidence.LOW,
                status=FindingStatus.INFORMATIONAL,
                description="A publicly accessible file discloses version information. File existence alone "
                            "(readme/license/changelog) is not a vulnerability; this is reported as "
                            "informational reconnaissance data, not a confirmed exploitable weakness.",
                affected_url=base + path,
                owasp=_OWASP_MISCONFIG if version else None,
                cwe="CWE-200" if version else None,
            ))

    # --- Hassas dosyalar ---

    def _check_sensitive_paths(self, session: requests.Session,
                                base: str, target: str, result: ScanResult) -> None:
        for path, severity, description in _SENSITIVE_PATHS:
            r = self._get(session, base + path)
            if not r or r.status_code != 200 or len(r.content) < 10:
                continue

            snippet = _text_snippet(r.text, 300)
            content_confirmed = _verify_sensitive_content(path, r.text)

            if content_confirmed:
                result.findings.append(Finding(
                    severity=severity,
                    title=f"Hassas dosya erişilebilir: {path}",
                    evidence=f"{description} | HTTP 200 | İçerik: {snippet}",
                    confidence=Confidence.HIGH,
                    status=FindingStatus.CONFIRMED,
                    description=f"{path} returned HTTP 200 with content markers consistent with "
                                f"{description.lower()}, indicating genuine exposure rather than a generic "
                                "catch-all response.",
                    affected_url=base + path,
                    owasp=_OWASP_MISCONFIG,
                    cwe=_CWE_SENSITIVE_FILE,
                    recommendation=f"Remove or restrict public access to {path}; it should not be served "
                                   "from the web root.",
                ))
            elif not _looks_like_generic_html(r.text):
                result.findings.append(Finding(
                    severity=Severity.LOW,
                    title=f"Yol erişilebilir ama içerik doğrulanamadı: {path}",
                    evidence=f"{description} | HTTP 200 | İçerik: {snippet}",
                    confidence=Confidence.LOW,
                    status=FindingStatus.MANUAL_REVIEW,
                    description=f"{path} returned HTTP 200, but the response content did not clearly match "
                                f"expected markers for {description.lower()}. Manual verification is "
                                "recommended before treating this as a confirmed exposure.",
                    affected_url=base + path,
                    recommendation=f"Manually verify whether {path} genuinely exposes {description.lower()}.",
                ))
            # else: tipik SPA/HTML catch-all yanıtı — muhtemel false positive, bulgu üretme

    # --- Admin panel erişimi ---

    def _check_admin_paths(self, session: requests.Session,
                            base: str, target: str, result: ScanResult) -> None:
        for path, label in _ADMIN_PATHS:
            r = self._get(session, base + path)
            if not r or r.status_code not in (200, 401, 403):
                continue
            title_tag = _page_title(r.text)
            evidence = f"{label} — HTTP {r.status_code}"
            if title_tag:
                evidence += f" | Sayfa başlığı: {title_tag}"

            if r.status_code == 200:
                result.findings.append(Finding(
                    severity=Severity.INFO,
                    title=f"Admin paneli bulundu: {path}",
                    evidence=evidence,
                    confidence=Confidence.HIGH,
                    status=FindingStatus.INFORMATIONAL,
                    description="An admin interface is reachable. This is discovery information, not a "
                                "vulnerability by itself — severity should only increase if missing "
                                "authentication, sensitive exposure, or an access-control problem is "
                                "separately confirmed.",
                    affected_url=base + path,
                ))
            else:
                result.findings.append(Finding(
                    severity=Severity.INFO,
                    title=f"Admin paneli bulundu: {path}",
                    evidence=evidence,
                    confidence=Confidence.HIGH,
                    status=FindingStatus.SECURE,
                    description="An admin interface path exists but requires authentication/is forbidden, "
                                "which is the expected, secure behavior.",
                    affected_url=base + path,
                ))

    # --- robots.txt ---

    def _check_robots(self, session: requests.Session,
                       base: str, target: str, result: ScanResult) -> None:
        r = self._get(session, base + "/robots.txt")
        if not r or r.status_code != 200:
            return
        disallowed = [
            line.split(":", 1)[1].strip()
            for line in r.text.splitlines()
            if line.strip().lower().startswith("disallow:") and line.split(":", 1)[1].strip()
        ]
        if disallowed:
            result.findings.append(Finding(
                severity=Severity.INFO,
                title="robots.txt — Gizlenen yollar",
                evidence=", ".join(disallowed[:8]) + (
                    f" (+{len(disallowed) - 8} daha)" if len(disallowed) > 8 else ""
                ),
                confidence=Confidence.HIGH,
                status=FindingStatus.INFORMATIONAL,
                description="robots.txt existing and listing disallowed paths is normal, public, and not a "
                            "vulnerability by itself — it only tells crawlers what not to index.",
                affected_url=base + "/robots.txt",
            ))

    # --- Yardımcılar ---

    def _extract_version(self, text: str) -> str:
        patterns = [
            r"version\s+(\d+\.\d+[\.\d]*)",
            r"wordpress\s+(\d+\.\d+[\.\d]*)",
            r"drupal\s+(\d+\.\d+[\.\d]*)",
            r"joomla[!\s]+(\d+\.\d+[\.\d]*)",
        ]
        for pattern in patterns:
            m = re.search(pattern, text, re.IGNORECASE)
            if m:
                return m.group(1)
        return ""
