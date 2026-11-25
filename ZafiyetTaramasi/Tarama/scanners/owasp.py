"""
OWASP Top 10:2025 — kategori tanımlarının TEK kaynağı (P0-5).

Kaynak: https://top10.owasp.org/2025/ (kategori kimlikleri ve adları resmi dizindeki
"Axx:2025 - Name" biçimindedir).

Eşleme ilkeleri (bulgu bazında, tarayıcı bazında değil):
1. Bir davranışı yalnızca TEK bir kategorinin resmi açıklaması / örnek senaryosu / önleme
   metni açıkça adlandırıyorsa o kategori kullanılır (ör. CORS → A01, HSTS → A04). Bu,
   LILITH'İN YORUMUDUR — resmi OWASP CWE listesi ataması olmak zorunda değildir.
2. Aksi halde (açık ad yok veya birden fazla kategori) resmi "List of Mapped CWEs"
   eşlemesi kullanılır (ör. CWE-209 → A10, CWE-538 → A01, CWE-1275 → A01).
3. Teknoloji keşfi (sürüm / generator / banner) ve yalnızca erişilebilirlik (açık port) zafiyet
   değildir → OWASP kategorisi ATANMAZ (owasp=None). OWASP Top 10 kapsamı dışındaki
   altyapı bulguları (SPF/DMARC, DNS zone transfer) da zorla eşlenmez.
CWE yalnızca gözlenen kanıt anlamını destekliyorsa verilir; aksi halde doğru genel CWE
veya None (ör. HSTS bulguları CWE-523 DEĞİL — kimlik bilgisi taşınması gözlenmez).
4. A06 (Insecure Design) ve A09 (Security Logging and Alerting Failures) dış tarama ile
   değerlendirilemez; hiçbir bulgu bu kategorilere atanmaz.

Geçmiş kayıtlar: P0-5 öncesi ScanFinding satırları "Axx:2021 - …" dizgilerini korur
(veri migrasyonu yok). Yıl dizgide yer aldığı için 2021 ve 2025 etiketleri her zaman ayırt
edilebilir; "A05:2021" (Misconfiguration) ile "A05:2025" (Injection) çakışmaz.
"""
import re

OWASP_2025_EDITION = "2025"

A01_BROKEN_ACCESS_CONTROL = "A01:2025 - Broken Access Control"
A02_SECURITY_MISCONFIGURATION = "A02:2025 - Security Misconfiguration"
A03_SOFTWARE_SUPPLY_CHAIN_FAILURES = "A03:2025 - Software Supply Chain Failures"
A04_CRYPTOGRAPHIC_FAILURES = "A04:2025 - Cryptographic Failures"
A05_INJECTION = "A05:2025 - Injection"
A06_INSECURE_DESIGN = "A06:2025 - Insecure Design"
A07_AUTHENTICATION_FAILURES = "A07:2025 - Authentication Failures"
A08_SOFTWARE_OR_DATA_INTEGRITY_FAILURES = "A08:2025 - Software or Data Integrity Failures"
A09_SECURITY_LOGGING_AND_ALERTING_FAILURES = "A09:2025 - Security Logging and Alerting Failures"
A10_MISHANDLING_OF_EXCEPTIONAL_CONDITIONS = "A10:2025 - Mishandling of Exceptional Conditions"

OWASP_TOP10_2025 = (
    A01_BROKEN_ACCESS_CONTROL,
    A02_SECURITY_MISCONFIGURATION,
    A03_SOFTWARE_SUPPLY_CHAIN_FAILURES,
    A04_CRYPTOGRAPHIC_FAILURES,
    A05_INJECTION,
    A06_INSECURE_DESIGN,
    A07_AUTHENTICATION_FAILURES,
    A08_SOFTWARE_OR_DATA_INTEGRITY_FAILURES,
    A09_SECURITY_LOGGING_AND_ALERTING_FAILURES,
    A10_MISHANDLING_OF_EXCEPTIONAL_CONDITIONS,
)

_LABEL_RE = re.compile(r"^A(?:0[1-9]|10):(?P<edition>\d{4})\b")


def owasp_edition(label) -> str | None:
    """'A05:2021 - …' → '2021', 'A05:2025 - …' → '2025'; eşlenmemiş/geçersiz → None.
    Geçmiş (2021) kayıtları yeni (2025) bulgulardan ayırt etmek içindir."""
    if not isinstance(label, str):
        return None
    match = _LABEL_RE.match(label.strip())
    return match.group("edition") if match else None


def is_owasp_2025(label) -> bool:
    return label in OWASP_TOP10_2025
