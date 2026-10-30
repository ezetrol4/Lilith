"""
OWASP Top 10 — A08: Software and Data Integrity Failures

Kontroller:
- Harici script/stylesheet SRI (Subresource Integrity) kontrolü
- Third-party kaynak domain analizi
- Dependency manifest dosyalarının erişilebilirliği
- CSP nonce/hash olmayan inline <script> varlığı
"""
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

_OWASP_INTEGRITY = "A08:2021 - Software and Data Integrity Failures"
_CWE_UNTRUSTED_INCLUSION = "CWE-829"  # Inclusion of Functionality from Untrusted Control Sphere

# Güvenilir, yaygın CDN domainleri
_TRUSTED_CDNS = frozenset({
    "cdnjs.cloudflare.com",
    "cdn.jsdelivr.net",
    "unpkg.com",
    "code.jquery.com",
    "ajax.googleapis.com",
    "ajax.aspnetcdn.com",
    "fonts.googleapis.com",
    "fonts.gstatic.com",
    "maxcdn.bootstrapcdn.com",
    "stackpath.bootstrapcdn.com",
    "use.fontawesome.com",
    "kit.fontawesome.com",
    "cdn.fontawesome.com",
    "cdn.tailwindcss.com",
    "cdn.staticfile.org",
})

# Bağımlılık manifest dosyaları: (path, description, severity, is_log)
# is_log=True olanlar (örn. debug.log) bir "dependency metadata" dosyası değil, çalışma zamanı
# logudur — içeriği öngörülemez olduğundan ayrı ve daha yüksek severity ile ele alınır.
_DEPENDENCY_FILES = [
    ("/package.json",       "Node.js bağımlılık listesi",          Severity.LOW,    False),
    ("/package-lock.json",  "NPM lock — tam versiyon ağacı",       Severity.LOW,    False),
    ("/yarn.lock",          "Yarn lock — tam versiyon ağacı",       Severity.LOW,    False),
    ("/composer.json",      "PHP Composer bağımlılıkları",          Severity.LOW,    False),
    ("/composer.lock",      "Composer lock — tam versiyon ağacı",   Severity.LOW,    False),
    ("/requirements.txt",   "Python bağımlılıkları",                Severity.LOW,    False),
    ("/Pipfile",            "Pipenv bağımlılıkları",                Severity.LOW,    False),
    ("/Pipfile.lock",       "Pipenv lock — tam versiyon ağacı",     Severity.LOW,    False),
    ("/Gemfile",            "Ruby bağımlılıkları",                  Severity.LOW,    False),
    ("/Gemfile.lock",       "Bundler lock dosyası",                 Severity.LOW,    False),
    ("/go.mod",             "Go modül dosyası",                     Severity.LOW,    False),
    ("/pom.xml",            "Maven bağımlılıkları",                 Severity.LOW,    False),
    ("/build.gradle",       "Gradle bağımlılıkları",                Severity.LOW,    False),
    ("/wp-content/debug.log", "WordPress hata logu",               Severity.MEDIUM, True),
]


def _extract_domain(url: str, base_domain: str) -> str | None:
    """URL'den domain çıkarır; birinci taraf veya göreli ise None döner."""
    if not url:
        return None
    if url.startswith("//"):
        url = "https:" + url
    parsed = urlparse(url)
    if not parsed.netloc:
        return None  # göreli URL → birinci taraf
    domain = parsed.netloc.lower().split(":")[0]
    # www. önekini normalize et
    base = base_domain.lower().removeprefix("www.")
    d    = domain.removeprefix("www.")
    if d == base or d.endswith("." + base):
        return None  # birinci taraf
    return domain


class IntegrityScanner(Scanner):
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
        result  = ScanResult(scanner="integrity", target=target)
        session = self._make_session()

        parsed      = urlparse(target)
        base_domain = (parsed.hostname or "").lower()
        base        = f"{parsed.scheme}://{parsed.hostname}"
        if parsed.port:
            base += f":{parsed.port}"

        res = self._get(session, target)
        if not res:
            result.error = "Ana sayfa alınamadı"
            return result

        soup = BeautifulSoup(res.content, "html.parser")
        csp  = res.headers.get("Content-Security-Policy", "")

        self._check_sri(soup, base_domain, target, result)
        self._check_third_party_origins(soup, base_domain, target, result)
        self._check_inline_scripts(soup, csp, target, result)
        self._check_dependency_files(session, base, result)

        return result

    # --- SRI Kontrolü ---

    def _check_sri(self, soup, base_domain: str, target: str, result: ScanResult) -> None:
        # SRI yalnızca harici script/stylesheet kaynakları için anlamlıdır — img, a, birinci
        # taraf kaynaklar için bulgu üretilmez (tag_set kasıtlı olarak dar tutuldu).
        missing, protected = [], []

        for tag in soup.find_all(["script", "link"]):
            src = tag.get("src") or (
                tag.get("href") if tag.get("rel") in (["stylesheet"], ["preload"]) else None
            )
            if not src:
                continue
            domain = _extract_domain(src, base_domain)
            if domain is None:
                continue  # birinci taraf → SRI zorunlu değil

            has_integrity   = bool(tag.get("integrity"))
            has_crossorigin = bool(tag.get("crossorigin"))
            src_short = src[:90]

            if has_integrity and has_crossorigin:
                protected.append(src_short)
            elif has_integrity and not has_crossorigin:
                result.findings.append(Finding(
                    severity=Severity.LOW,
                    title=f"SRI var ama crossorigin eksik: <{tag.name}>",
                    evidence=f"{src_short} — crossorigin olmadan tarayıcı SRI'yi uygulamayabilir",
                    confidence=Confidence.HIGH,
                    status=FindingStatus.CONFIRMED,
                    affected_url=target,
                    owasp=_OWASP_INTEGRITY,
                    recommendation="Add a matching crossorigin attribute (e.g. crossorigin=\"anonymous\") "
                                   "alongside the integrity attribute.",
                ))
            else:
                missing.append((tag.name, src_short, domain))

        if missing:
            for tag_name, src, domain in missing[:15]:
                result.findings.append(Finding(
                    severity=Severity.LOW,
                    title=f"SRI eksik: <{tag_name}>",
                    evidence=f"Kaynak: {src} | Domain: {domain}",
                    confidence=Confidence.HIGH,
                    status=FindingStatus.POTENTIAL,
                    description="Missing Subresource Integrity increases supply-chain exposure if the "
                                "third-party host is ever compromised or its content is tampered with in "
                                "transit — it does NOT mean this resource is currently compromised.",
                    affected_url=target,
                    parameter=src,
                    owasp=_OWASP_INTEGRITY,
                    cwe=_CWE_UNTRUSTED_INCLUSION,
                    recommendation="Add an integrity attribute (sha384/sha256 hash) and crossorigin "
                                   "attribute to this external resource, or self-host it.",
                ))
        else:
            result.findings.append(Finding(
                severity=Severity.INFO,
                title="Tüm harici kaynaklar SRI ile korunuyor",
                evidence=f"Kontrol edilen kaynak: {len(protected)}",
                confidence=Confidence.HIGH,
                status=FindingStatus.SECURE,
                affected_url=target,
            ))

    # --- Third-Party Kaynak Analizi ---

    def _check_third_party_origins(self, soup, base_domain: str,
                                    target: str, result: ScanResult) -> None:
        origins: dict[str, list[str]] = {}

        for tag in soup.find_all(["script", "link", "img", "iframe"]):
            src = tag.get("src") or tag.get("href") or ""
            domain = _extract_domain(src, base_domain)
            if not domain:
                continue
            origins.setdefault(domain, [])
            tag_type = tag.name + ("/" + tag.get("rel", [""])[0] if tag.name == "link" else "")
            if tag_type not in origins[domain]:
                origins[domain].append(tag_type)

        if not origins:
            result.findings.append(Finding(
                severity=Severity.INFO,
                title="Third-party kaynak yok",
                evidence="Tüm kaynaklar birinci taraf domain'den yükleniyor",
                confidence=Confidence.HIGH,
                status=FindingStatus.INFORMATIONAL,
                affected_url=target,
            ))
            return

        trusted   = {d for d in origins if d in _TRUSTED_CDNS}
        untrusted = {d for d in origins if d not in _TRUSTED_CDNS}

        if trusted:
            result.findings.append(Finding(
                severity=Severity.INFO,
                title=f"Güvenilir CDN kaynakları ({len(trusted)} domain)",
                evidence=", ".join(sorted(trusted)),
                confidence=Confidence.HIGH,
                status=FindingStatus.INFORMATIONAL,
                affected_url=target,
            ))

        for domain in sorted(untrusted):
            result.findings.append(Finding(
                severity=Severity.INFO,
                title=f"Bilinmeyen third-party kaynak: {domain}",
                evidence=f"Yüklenen tipler: {', '.join(origins[domain])}",
                confidence=Confidence.MEDIUM,
                status=FindingStatus.INFORMATIONAL,
                description="An unrecognized third-party domain is loaded by this page. An unknown domain "
                            "is not automatically malicious — this is reconnaissance information for manual "
                            "review of the trust relationship, not a confirmed security issue.",
                affected_url=target,
            ))

    # --- Inline Script Kontrolü ---

    def _check_inline_scripts(self, soup, csp: str, target: str,
                               result: ScanResult) -> None:
        inline_scripts = [
            s for s in soup.find_all("script")
            if not s.get("src") and s.string and s.string.strip()
        ]

        if not inline_scripts:
            return

        has_nonce = "nonce-" in csp
        has_hash  = re.search(r"'sha(256|384|512)-", csp) is not None
        has_unsafe_inline = "'unsafe-inline'" in csp

        if has_nonce or has_hash:
            result.findings.append(Finding(
                severity=Severity.INFO,
                title=f"Inline script'ler CSP ile korunuyor ({len(inline_scripts)} adet)",
                evidence="CSP nonce veya hash tabanlı koruma tespit edildi",
                confidence=Confidence.HIGH,
                status=FindingStatus.SECURE,
                affected_url=target,
            ))
            return

        if not csp:
            # CSP hiç yoksa inline script'ler tamamen kısıtlamasız çalışır — bu, HeaderScanner'ın
            # ayrı ürettiği "CSP eksik" bulgusundan farklı olarak, sayfanın GERÇEKTEN inline script'e
            # dayandığını doğrular.
            result.findings.append(Finding(
                severity=Severity.MEDIUM,
                title=f"CSP olmadan inline <script> ({len(inline_scripts)} adet)",
                evidence="Content-Security-Policy başlığı yok — inline script'ler kısıtlama olmadan çalışır",
                confidence=Confidence.HIGH,
                status=FindingStatus.CONFIRMED,
                description="This page relies on inline scripts with no Content-Security-Policy at all, so "
                            "they execute unrestricted. If an XSS is ever achieved, an attacker's injected "
                            "script would also run without restriction.",
                affected_url=target,
                owasp=_OWASP_INTEGRITY,
                recommendation="Adopt a Content-Security-Policy using nonces or hashes for inline scripts, "
                               "or move script logic to external files.",
            ))
            return

        if has_unsafe_inline:
            # HeaderScanner zaten bu durumu "CSP 'unsafe-inline' içeriyor" olarak raporluyor —
            # aynı sorunu iki kez göstermemek için burada tekrar bulgu üretilmiyor.
            return

        # CSP var, unsafe-inline/nonce/hash yok → tarayıcı inline script'i zaten engeller,
        # gerçek bir güvenlik sorunu yok.

    # --- Dependency Manifest Dosyaları ---

    def _check_dependency_files(self, session: requests.Session,
                                  base: str, result: ScanResult) -> None:
        for path, description, severity, is_log in _DEPENDENCY_FILES:
            r = self._get(session, base + path)
            if not r or r.status_code != 200 or len(r.content) < 20:
                continue

            # debug.log / manifest gizli değer içerebilir — kırpmadan ÖNCE redakte edilir
            snippet = redact_then_truncate(r.text, 200).replace("\n", " ").strip()

            if is_log:
                result.findings.append(Finding(
                    severity=severity,
                    title=f"Hata log dosyası erişilebilir: {path}",
                    evidence=f"{description} | İçerik: {snippet}…",
                    confidence=Confidence.HIGH,
                    status=FindingStatus.CONFIRMED,
                    description="A runtime error log is publicly accessible. Unlike a static dependency "
                                "manifest, log content is unpredictable and may contain paths, queries, or "
                                "other runtime details.",
                    affected_url=base + path,
                    owasp=_OWASP_INTEGRITY,
                    recommendation=f"Remove or restrict public access to {path}.",
                ))
            else:
                result.findings.append(Finding(
                    severity=severity,
                    title=f"Dependency Metadata Exposed: {path}",
                    evidence=f"{description} | İçerik: {snippet}…",
                    confidence=Confidence.HIGH,
                    status=FindingStatus.CONFIRMED,
                    description="A dependency manifest is publicly accessible, disclosing library names and "
                                "versions used by the application. This is metadata exposure, not a confirmed "
                                "vulnerable component — no CVE/version match was performed.",
                    affected_url=base + path,
                    owasp=_OWASP_INTEGRITY,
                    recommendation=f"Restrict public access to {path} if it is not intentionally published.",
                ))
