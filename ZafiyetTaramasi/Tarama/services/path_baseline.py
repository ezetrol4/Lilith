"""
Path-probe baseline — soft-404 / catch-all yanlış pozitif azaltımı.

HTTP 200, bir yolun gerçekten var olduğunu kanıtlamaz: SPA'lar, özel 404 sayfaları,
catch-all route'lar ve reverse proxy'ler var olmayan her yol için 200 (ya da aynı
yönlendirmeyi) döndürebilir. Bu modül hedefin "var olmayan kaynak" davranışını iki
rastgele, yüksek entropili yolla ölçer ve aday yanıtı bu profille karşılaştırır.

    baseline = PathBaseline.build(session, base, timeout)   # tarama başına bir kez, 2 istek
    relation = baseline.classify(response, "/debug")

Sınıflar:
    MATCHES_BASELINE       aday, var olmayan bir yolun yanıtından ayırt edilemiyor
    DIFFERS_FROM_BASELINE  aday anlamlı biçimde farklı (kaynak muhtemelen gerçek)
    AMBIGUOUS              karar verilemiyor (ara benzerlik / kararsız baseline)
    BASELINE_UNAVAILABLE   baseline alınamadı (ağ hatası, SSRF engeli...)

Kararlar tek bir sinyale dayanmaz: durum kodu, yönlendirme hedefi, içerik türü, sayfa
başlığı ve normalize edilmiş gövde benzerliği birlikte değerlendirilir. Benzerlik
skoru bilimsel bir kesinlik değil, açık eşiklerle kullanılan bir sezgiseldir.

Bu modül kendi başına bulgu üretmez; scanner'lar içerik doğrulamasıyla birlikte kullanır.
Tüm istekler çağıranın SafeSession'ından geçer (P0-1 SSRF zorlaması korunur).
"""
import re
import secrets
from dataclasses import dataclass
from difflib import SequenceMatcher
from enum import Enum
from urllib.parse import urlsplit

import requests


class Relation(Enum):
    MATCHES_BASELINE = "MATCHES_BASELINE"
    DIFFERS_FROM_BASELINE = "DIFFERS_FROM_BASELINE"
    AMBIGUOUS = "AMBIGUOUS"
    BASELINE_UNAVAILABLE = "BASELINE_UNAVAILABLE"


# Benzerlik eşikleri (normalize gövdeler, difflib SequenceMatcher.ratio):
#   ≥ 0.90  → aynı sayfa (yalnızca dinamik değerler/küçük farklar) — testlerle doğrulanır
#   < 0.70  → farklı sayfa
#   arası   → belirsiz; başlık farklıysa farklı sayılır, aksi halde AMBIGUOUS
MATCH_THRESHOLD = 0.90
DIFFER_THRESHOLD = 0.70

BASELINE_SAMPLES = 2
_MAX_COMPARE_CHARS = 20_000

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)

# Açıkça tanınabilen dinamik değerler (istek kimliği, zaman damgası, CSRF/nonce benzeri
# uzun tokenlar). Güvenlik içeriğini silmez — yalnızca KARŞILAŞTIRMA için kullanılır,
# kanıta asla yazılmaz.
_DYNAMIC_PATTERNS = [
    re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.IGNORECASE),
    re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?"),
    re.compile(r"\b(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun), \d{2} [A-Z][a-z]{2} \d{4} \d{2}:\d{2}:\d{2} GMT\b"),
    re.compile(r"\b[0-9a-f]{16,}\b", re.IGNORECASE),
    re.compile(r"\b[A-Za-z0-9_\-]{32,}\b"),
    re.compile(r"\b\d{6,}\b"),
]
_WS_RE = re.compile(r"\s+")


def random_probe_path() -> str:
    """Uygulamadan bağımsız, gerçek bir route olması pratikte imkânsız yol."""
    return f"/__lilith_probe_{secrets.token_hex(12)}__"


@dataclass(frozen=True)
class ResponseSignature:
    status: int
    redirected: bool
    final_path: str
    content_type: str
    title: str
    body: str


def _content_type(response) -> str:
    headers = getattr(response, "headers", None)
    value = None
    if headers is not None:
        try:
            value = headers.get("Content-Type") or headers.get("content-type")
        except Exception:
            value = None
    return value.split(";", 1)[0].strip().lower() if isinstance(value, str) else ""


def _normalize_body(text: str, requested_path: str) -> str:
    text = text[: _MAX_COMPARE_CHARS * 2]
    bare_path = requested_path.strip("/")
    if bare_path:
        # Özel 404 sayfaları istenen yolu yansıtır ("/debug bulunamadı")
        text = text.replace(requested_path, "{path}").replace(bare_path, "{path}")
    for pattern in _DYNAMIC_PATTERNS:
        text = pattern.sub("{dyn}", text)
    return _WS_RE.sub(" ", text).strip()[:_MAX_COMPARE_CHARS]


def signature(response, requested_url: str, requested_path: str) -> ResponseSignature:
    status = getattr(response, "status_code", None)
    text = getattr(response, "text", "")
    final_url = getattr(response, "url", None)
    history = getattr(response, "history", None)

    text = text if isinstance(text, str) else ""
    final_url = final_url if isinstance(final_url, str) else requested_url
    redirected = (isinstance(history, list) and bool(history)) or (
        urlsplit(final_url).path.rstrip("/") != urlsplit(requested_url).path.rstrip("/")
    )
    final_path = urlsplit(final_url).path if redirected else ""

    title_match = _TITLE_RE.search(text[:_MAX_COMPARE_CHARS])
    title = _WS_RE.sub(" ", title_match.group(1)).strip() if title_match else ""
    if requested_path:
        title = title.replace(requested_path, "{path}")

    return ResponseSignature(
        status=status if isinstance(status, int) else 0,
        redirected=redirected,
        final_path=final_path,
        content_type=_content_type(response),
        title=title,
        body=_normalize_body(text, requested_path),
    )


def _similarity(a: str, b: str) -> float:
    if a == b:
        return 1.0
    if not a or not b:
        return 0.0
    matcher = SequenceMatcher(None, a, b, autojunk=False)
    # Ucuz üst sınırlar zaten farklı olduğunu gösteriyorsa pahalı hesaplamaya gerek yok
    if matcher.real_quick_ratio() < DIFFER_THRESHOLD or matcher.quick_ratio() < DIFFER_THRESHOLD:
        return matcher.quick_ratio()
    return matcher.ratio()


def compare_signatures(candidate: ResponseSignature, sample: ResponseSignature) -> Relation:
    if candidate.status != sample.status:
        return Relation.DIFFERS_FROM_BASELINE
    if candidate.redirected != sample.redirected or candidate.final_path != sample.final_path:
        return Relation.DIFFERS_FROM_BASELINE
    if candidate.content_type != sample.content_type:
        return Relation.DIFFERS_FROM_BASELINE

    score = _similarity(candidate.body, sample.body)
    if score >= MATCH_THRESHOLD:
        return Relation.MATCHES_BASELINE
    if score < DIFFER_THRESHOLD:
        return Relation.DIFFERS_FROM_BASELINE
    if candidate.title and sample.title and candidate.title != sample.title:
        return Relation.DIFFERS_FROM_BASELINE
    return Relation.AMBIGUOUS


class PathBaseline:
    """Tek bir hedef + tek bir scanner çalıştırması için var-olmayan-kaynak profili.

    Kalıcı önbellek yoktur; farklı hedefler arasında paylaşılmaz.
    """

    def __init__(self, samples: list[ResponseSignature]):
        self.samples = samples
        # İki örnek birbiriyle eşleşmiyorsa uygulama rastgele yollar için bile değişken
        # içerik üretiyor demektir — "farklı" kararı güvenilir değildir.
        self.stable = (
            len(samples) >= 2 and compare_signatures(samples[0], samples[1]) == Relation.MATCHES_BASELINE
        )

    @property
    def available(self) -> bool:
        return bool(self.samples)

    @classmethod
    def build(cls, session, base: str, timeout: float) -> "PathBaseline":
        samples = []
        for _ in range(BASELINE_SAMPLES):
            path = random_probe_path()
            url = base + path
            try:
                response = session.get(url, timeout=timeout, allow_redirects=True)
            except requests.RequestException:
                # Ağ hatası / zaman aşımı / SSRF engeli: bu örnek yok sayılır.
                # Baseline yoksa adaylar "farklı" sayılmaz (muhafazakâr davranış).
                continue
            if response is None:
                continue
            samples.append(signature(response, url, path))
        return cls(samples)

    def classify(self, response, url: str, path: str) -> Relation:
        if not self.samples:
            return Relation.BASELINE_UNAVAILABLE

        candidate = signature(response, url, path)
        relations = [compare_signatures(candidate, sample) for sample in self.samples]
        if Relation.MATCHES_BASELINE in relations:
            return Relation.MATCHES_BASELINE
        if Relation.AMBIGUOUS in relations:
            return Relation.AMBIGUOUS
        # Her örnekten farklı. Baseline kararsızsa ve fark yalnızca gövdedeyse
        # (durum/yönlendirme aynı) bu farka güvenilmez.
        if not self.stable and any(
            s.status == candidate.status and s.redirected == candidate.redirected for s in self.samples
        ):
            return Relation.AMBIGUOUS
        return Relation.DIFFERS_FROM_BASELINE
