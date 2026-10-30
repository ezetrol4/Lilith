"""
Lilith kanıt redaksiyonu — hedeften gelen içerik güvenilmez veridir ve gerçek parola,
token veya anahtar içerebilir.

Tek, paylaşılan sanitizer: scanner'lar hedef yanıtından aldıkları her ham parçayı
(dosya içeriği, hata sayfası satırı, yanıt kesiti) buradan geçirir. Değerler
redakte edilir, bağlam korunur:

    DB_PASSWORD=hunter2   →   DB_PASSWORD=[REDACTED]

Özellikler: deterministik, idempotent, ağ erişimi yok, harici bağımlılık yok.
Yalnızca YÜKSEK GÜVENLİ bağlamlar redakte edilir (anahtar adı, Authorization başlığı,
URL userinfo, PEM private key, bilinen token önekleri) — entropi tabanlı tahmin
YAPILMAZ; hash, UUID, payload ve normal teknik tanımlayıcılar korunur.

Kurallar:
  - Kırpma (truncation) her zaman redaksiyondan SONRA yapılır (redact_then_truncate).
  - Tek işaret: [REDACTED]
"""
import re
from urllib.parse import unquote_plus, urlsplit, urlunsplit

REDACTED = "[REDACTED]"

# Kırpılacak metinlerde redaksiyon için incelenen azami ön ek. Kesim yalnızca metnin
# sonundan yapıldığı için bir anahtarın değeri hiçbir zaman anahtarından ayrı görünmez;
# bu sınır yalnızca çok büyük yanıtlarda regex maliyetini sınırlar.
_MAX_TRUNCATION_INPUT = 256 * 1024

_NOT_REDACTED = rf"(?!{re.escape(REDACTED)})"

# --- Gizli değer taşıyan anahtar adları (büyük/küçük harf duyarsız) ---
# Anahtar, bu kelimelerden birini İÇEREN bir tanımlayıcıdır: DB_PASSWORD,
# DJANGO_SECRET_KEY, GITHUB_TOKEN, client_secret, accessToken, X-Api-Key ...
# 'pass' yalnızca tam bileşen olarak (DB_PASS, MAIL_PASS) — 'bypass'/'compass' değil.
_SECRET_WORD = (
    r"(?:passw(?:or)?d|passphrase|pwd|secret|token|api[_\-]?key|private[_\-]?key|"
    r"access[_\-]?key|sess(?:ion)?[_\-]?id|csrf|xsrf)"
)
_KEY_CHARS = r"[A-Za-z0-9_.\-]"
_SECRET_KEY = (
    rf"(?<![A-Za-z0-9_.\-])(?:{_KEY_CHARS}*{_SECRET_WORD}{_KEY_CHARS}*"
    rf"|{_KEY_CHARS}*(?<![A-Za-z0-9])pass(?![A-Za-z0-9]){_KEY_CHARS}*)"
)

# --- 1. PEM private key blokları (public sertifika/anahtarlar dokunulmaz) ---
_PEM_LABEL = r"(?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?"
_PEM_BLOCK_RE = re.compile(
    rf"(-----BEGIN (?P<label>{_PEM_LABEL})-----)[\s\S]*?(-----END (?P=label)-----)"
)
# Kesilmiş/kapanmamış blok: BEGIN'den sonraki her şey redakte edilir
_PEM_UNTERMINATED_RE = re.compile(
    rf"(-----BEGIN {_PEM_LABEL}-----)(?![\s\S]*-----END {_PEM_LABEL}-----)(?!\n\[REDACTED\]$)[\s\S]+"
)

# --- 2. URL userinfo: scheme://user:password@host ---
_URL_USERINFO_RE = re.compile(
    r"(?P<prefix>\b[A-Za-z][A-Za-z0-9+.\-]*://[^\s:/?#@'\"<>]*:)(?P<pw>[^\s@/?#'\"<>]+)@"
)

# Metin içinde geçen mutlak URL (sorgu parametreleri redact_sensitive_url ile işlenir)
_ABSOLUTE_URL_RE = re.compile(r"\b[A-Za-z][A-Za-z0-9+.\-]*://[^\s\"'<>]+")

# --- 3. HTTP kimlik doğrulama başlıkları ---
_AUTH_HEADER_RE = re.compile(
    r"(?P<prefix>\b(?:Proxy-)?Authorization[\"']?\s*[:=]\s*[\"']?"
    # possessive (?+): şema bir kez eşleşirse geri bırakılmaz — "Bearer [REDACTED]"
    # ikinci geçişte "[REDACTED]"a dönüşmez (idempotence)
    r"(?:(?:Bearer|Basic|Digest|Token|Bot|Negotiate|NTLM|AWS4-HMAC-SHA256)[ \t]+)?+)"
    rf"{_NOT_REDACTED}(?P<cred>[^\s\"'|<>][^\"'\r\n|<>]*)",
    re.IGNORECASE,
)
# Bağlamsız "Bearer <token>": en az 16 karakter ve bir rakam (düz metindeki
# "Bearer token required" gibi ifadeler korunur)
_BEARER_RE = re.compile(
    rf"(?P<prefix>\bBearer[ \t]+){_NOT_REDACTED}(?=[A-Za-z0-9\-._~+/]*\d)(?P<cred>[A-Za-z0-9\-._~+/]{{16,}}=*)"
)

# --- 4. Cookie / Set-Cookie başlıkları: değer redakte, öznitelikler korunur ---
_COOKIE_HEADER_RE = re.compile(
    r"(?P<prefix>\b(?P<name>Set-Cookie|Cookie)\s*:\s*)(?P<value>[^\r\n|]+)", re.IGNORECASE
)

# --- 5. Tırnaklı anahtar/değer: JSON, Python, PHP, JS ---
#   "password": "x"   'password' => 'x'   password="x"
_QUOTED_VALUE = r"(?P<value>(?:\\.|(?!(?P=vq))[^\\\r\n])+)(?P=vq)"
_QUOTED_KV_RE = re.compile(
    rf"(?P<prefix>(?P<kq>[\"']?){_SECRET_KEY}(?P=kq)\s*(?:=>|[:=])\s*(?P<vq>[\"'])){_QUOTED_VALUE}",
    re.IGNORECASE,
)
# Parantez içi çift: define('DB_PASSWORD', 'x') — SQL ('db_password', 'x')
# (yalnızca '(' sonrası: JSON dizileri ["password", "email"] etkilenmez)
_TUPLE_KV_RE = re.compile(
    rf"(?P<prefix>\(\s*(?P<kq>[\"']){_SECRET_KEY}(?P=kq)\s*,\s*(?P<vq>[\"'])){_QUOTED_VALUE}",
    re.IGNORECASE,
)

# --- 6. phpinfo/HTML tablo hücresi: <td>DB_PASSWORD</td><td>x</td> ---
_HTML_CELL_KV_RE = re.compile(
    rf"(?P<prefix>{_SECRET_KEY}\s*</t[dh]>\s*<td[^>]*>\s*){_NOT_REDACTED}(?P<value>[^<\s][^<]*?)(?=\s*</td>)",
    re.IGNORECASE,
)

# --- 7. SQL'e özgü yüksek güvenli bağlamlar ---
_SQL_SECRET_RE = re.compile(
    r"(?P<prefix>\b(?:IDENTIFIED\s+BY(?:\s+PASSWORD)?|PASSWORD\s*\()\s*(?P<vq>['\"]))"
    r"(?P<value>(?:\\.|(?!(?P=vq))[^\\\r\n])+)(?P=vq)",
    re.IGNORECASE,
)

# --- 8. Tırnaksız anahtar/değer: .env, INI, YAML, sorgu dizesi, bağlantı dizesi ---
#   DB_PASSWORD=x   password = x   password: x   ?token=x&a=b   Server=h;Password=x;
# Değer satır sonuna kadar sürer; ; & < > " ' , | } ile ya da bir sonraki
# "anahtar=" ile biter. ':' ile başlayan değerler (Password::Hash) değer sayılmaz.
_VALUE_STOP = r"\r\n;&<>\"',|}"
_NEXT_KEY = r"\s+[A-Za-z_][\w.\-]*\s*[=:]"
_UNQUOTED_KV_RE = re.compile(
    rf"(?P<prefix>{_SECRET_KEY}[ \t]*(?:=>|=|:)[ \t]*){_NOT_REDACTED}"
    rf"(?P<value>[^\s{_VALUE_STOP}:\[\]](?:(?!{_NEXT_KEY})[^{_VALUE_STOP}])*)",
    re.IGNORECASE,
)

# --- 9. Bilinen formatta tokenlar ve parola hash'leri (bağlamdan bağımsız) ---
_TOKEN_RE = re.compile(
    r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"   # JWT
    r"|\bgh[pousr]_[A-Za-z0-9]{36,}\b"                                      # GitHub token
    r"|\bgithub_pat_[A-Za-z0-9_]{22,}\b"                                    # GitHub fine-grained
    r"|\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"                                       # AWS access key id
    r"|\bxox[abprs]-[A-Za-z0-9\-]{10,}"                                     # Slack
    r"|\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}\b"                            # Stripe
    r"|\bAIza[0-9A-Za-z_\-]{35}\b"                                          # Google API key
    r"|\bsk-(?:ant|proj)-[A-Za-z0-9_\-]{20,}"                               # Anthropic / OpenAI
    r"|\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}"                                  # bcrypt hash
    r"|\$argon2(?:id|i|d)\$v=\d+\$[^\s'\"$]+\$[^\s'\"$]+\$[^\s'\",;)]+"     # argon2 hash
)


def _keep_trailing_space(value: str) -> str:
    stripped = value.rstrip()
    return REDACTED + value[len(stripped):]


def _redact_cookie_header(m: re.Match) -> str:
    is_set_cookie = m.group("name").lower() == "set-cookie"
    parts = m.group("value").split(";")
    redacted = []
    for index, part in enumerate(parts):
        name, sep, value = part.partition("=")
        # Set-Cookie: yalnızca ilk çift çerezin kendisi; sonrakiler öznitelik (Path, Secure...)
        is_cookie_pair = sep and (not is_set_cookie or index == 0)
        if is_cookie_pair and value.strip() and value.strip() != REDACTED:
            leading = value[:len(value) - len(value.lstrip())]
            redacted.append(f"{name}={leading}{_keep_trailing_space(value.lstrip())}")
        else:
            redacted.append(part)
    return m.group("prefix") + ";".join(redacted)


def redact_sensitive_text(value):
    """Metindeki yüksek güvenli gizli değerleri [REDACTED] ile değiştirir.

    str olmayan / boş değerler aynen döner. İdempotenttir:
    redact_sensitive_text(redact_sensitive_text(x)) == redact_sensitive_text(x)
    """
    if not value or not isinstance(value, str):
        return value
    return _redact_text(value, include_urls=True)


def _redact_text(value: str, include_urls: bool) -> str:
    text = _PEM_BLOCK_RE.sub(lambda m: f"{m.group(1)}\n{REDACTED}\n{m.group(3)}", value)
    text = _PEM_UNTERMINATED_RE.sub(lambda m: f"{m.group(1)}\n{REDACTED}", text)
    text = _URL_USERINFO_RE.sub(lambda m: f"{m.group('prefix')}{REDACTED}@", text)
    if include_urls:
        # Metin içindeki mutlak URL'ler URL politikasıyla aynı şekilde redakte edilir
        # (ör. istisna mesajındaki imzalı S3 URL'si: X-Amz-Signature, sig, token...)
        text = _ABSOLUTE_URL_RE.sub(lambda m: redact_sensitive_url(m.group(0)), text)
    text = _AUTH_HEADER_RE.sub(lambda m: m.group("prefix") + _keep_trailing_space(m.group("cred")), text)
    text = _BEARER_RE.sub(lambda m: m.group("prefix") + REDACTED, text)
    text = _COOKIE_HEADER_RE.sub(_redact_cookie_header, text)
    text = _QUOTED_KV_RE.sub(lambda m: f"{m.group('prefix')}{REDACTED}{m.group('vq')}", text)
    text = _TUPLE_KV_RE.sub(lambda m: f"{m.group('prefix')}{REDACTED}{m.group('vq')}", text)
    text = _HTML_CELL_KV_RE.sub(lambda m: m.group("prefix") + REDACTED, text)
    text = _SQL_SECRET_RE.sub(lambda m: f"{m.group('prefix')}{REDACTED}{m.group('vq')}", text)
    text = _UNQUOTED_KV_RE.sub(lambda m: m.group("prefix") + _keep_trailing_space(m.group("value")), text)
    text = _TOKEN_RE.sub(REDACTED, text)
    return text


# --- Güvenli görüntüleme/kalıcılık URL'si ---
# Sorgu parametresi adı bu ifadeyle TAMAMEN eşleşirse değeri gizlidir. Kanıt
# anahtarlarına ek olarak imzalı URL (S3/Azure SAS) ve OAuth parametreleri.
_SECRET_PARAM_NAME_RE = re.compile(
    rf"{_KEY_CHARS}*{_SECRET_WORD}{_KEY_CHARS}*"
    rf"|{_KEY_CHARS}*(?<![A-Za-z0-9])pass(?![A-Za-z0-9]){_KEY_CHARS}*"
    r"|x-amz-(?:signature|security-token|credential)|sig|signature|auth|authorization|credentials?",
    re.IGNORECASE,
)


_URL_PLACEHOLDER = "LILITHREDACTEDPLACEHOLDER"


def _redact_url_params(params: str) -> str:
    out = []
    for part in params.split("&"):
        name, sep, value = part.partition("=")
        already = value in (REDACTED, _URL_PLACEHOLDER)
        if sep and value and not already and _SECRET_PARAM_NAME_RE.fullmatch(unquote_plus(name)):
            out.append(f"{name}={REDACTED}")
        else:
            out.append(part)
    return "&".join(out)


def redact_sensitive_url(url):
    """Görüntüleme / kalıcılık / log için güvenli URL.

    AĞ URL'si DEĞİLDİR — scanner'lar her zaman orijinal URL'yi kullanır. Şema, host,
    port, path ve gizli olmayan sorgu parametreleri korunur; userinfo parolası ve
    yüksek güvenli gizli sorgu/fragment parametre değerleri redakte edilir:

        https://admin:secret@example.com/api?token=abc&lang=en
        → https://admin:[REDACTED]@example.com/api?token=[REDACTED]&lang=en

    İdempotenttir. Ayrıştırılamayan değerler metin redaksiyonuna düşer.
    """
    if not url or not isinstance(url, str):
        return url
    # urlsplit köşeli parantezi IPv6 host sanar: önceden redakte edilmiş userinfo
    # ("user:[REDACTED]@host") ayrıştırma sırasında köşeli parantezsiz yer tutucuyla taşınır
    placeholder_url = url.replace(REDACTED, _URL_PLACEHOLDER)
    try:
        parts = urlsplit(placeholder_url)
    except ValueError:
        # URL fonksiyonuna geri dönmeyen metin redaksiyonu (sonsuz özyineleme yok)
        return _redact_text(url, include_urls=False)

    netloc = parts.netloc
    if "@" in netloc:
        userinfo, _, hostport = netloc.rpartition("@")
        user, has_password, _password = userinfo.partition(":")
        user = redact_sensitive_text(user)  # bilinen token formatında kullanıcı adı (ör. ghp_...)
        netloc = f"{user}:{REDACTED}@{hostport}" if has_password else f"{user}@{hostport}"
    query = _redact_url_params(parts.query) if parts.query else parts.query
    fragment = _redact_url_params(parts.fragment) if "=" in parts.fragment else parts.fragment

    if (netloc, query, fragment) == (parts.netloc, parts.query, parts.fragment):
        return url  # değişiklik yoksa orijinal biçim aynen korunur
    rebuilt = urlunsplit((parts.scheme, netloc, parts.path, query, fragment))
    return rebuilt.replace(_URL_PLACEHOLDER, REDACTED)


def redact_then_truncate(value: str, max_len: int) -> str:
    """Önce redakte eder, SONRA kırpar — kırpma bir anahtarı değerinden ayırıp
    gizli değeri tanınmaz hale getiremez."""
    if not value:
        return value
    return redact_sensitive_text(value[:_MAX_TRUNCATION_INPUT])[:max_len]
