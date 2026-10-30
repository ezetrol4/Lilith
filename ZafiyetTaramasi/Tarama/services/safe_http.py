"""
Lilith giden HTTP katmanı — scanner'ların yaptığı HER HTTP/HTTPS isteği SSRF
politikasından (ssrf_guard.py) ağa çıkmadan hemen önce geçer.

Üç katmanlı denetim:
  1. SafeSession      — yönlendirmeleri kendisi takip eder; ilk URL ve HER yönlendirme
                        hedefi için şema/host/IP-literal kontrolü (DNS'siz).
  2. SSRFGuardAdapter — requests'in gönderdiği her istekte host'u çözümler ve tüm
                        adresleri doğrular (DNS yeniden doğrulaması).
  3. Pinned bağlantı  — urllib3 soketi açarken host'u tekrar çözümler, adresleri
                        doğrular ve YALNIZCA doğrulanmış IP'ye bağlanır (check ile
                        connect arasındaki DNS rebinding penceresini kapatır).

requests global olarak monkey-patch edilmez. İç requests.Session çağrı anında
oluşturulur; mevcut testler scanner modülündeki requests.Session'ı mock'lamaya
devam edebilir.
"""
import logging
import socket
import threading
from contextlib import contextmanager
from urllib.parse import urljoin, urlsplit

import requests
from requests.adapters import HTTPAdapter
from requests.utils import requote_uri
from urllib3.connection import HTTPConnection, HTTPSConnection
from urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool
from urllib3.exceptions import ConnectTimeoutError, NameResolutionError, NewConnectionError
from urllib3.util import connection as urllib3_connection

from .ssrf_guard import (
    HostResolutionError, SSRFError, check_url_target, resolve_and_validate_host, validate_url,
)

logger = logging.getLogger(__name__)

MAX_REDIRECTS = 10
# Aynı (method, URL) çiftinin bir yönlendirme zincirinde en fazla kaç kez istenebileceği.
# 2: "cookie set et → kendine yönlendir" gibi meşru akışlara izin verir, döngüleri keser.
_MAX_VISITS_PER_URL = 2

_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
_BODY_KWARGS = ("data", "json", "files")

# Frontend'e/API'ye dönebilecek sabit mesaj — iç IP/host detayı içermez.
OUTBOUND_BLOCKED_MESSAGE = (
    "Hedef, güvenlik politikası tarafından engellenen bir adrese erişim gerektirdi; "
    "istek gönderilmedi."
)


class OutboundRequestBlocked(requests.exceptions.ConnectionError):
    """SSRF politikası bir giden isteği engelledi.

    requests.RequestException alt sınıfıdır — scanner'ların mevcut
    `except requests.RequestException` blokları bu isteği başarısız bir istek gibi
    atlar. str() sabit, sanitize edilmiş mesajdır; tanı detayı yalnızca `reason`'da.
    """

    def __init__(self, reason: str = ""):
        super().__init__(OUTBOUND_BLOCKED_MESSAGE)
        self.reason = reason


# --- Engellenen istek takibi (orchestrator raporlaması için) ---

_tracking = threading.local()


class BlockTracker:
    def __init__(self):
        self.blocked = 0


@contextmanager
def track_blocked_requests():
    """Bu thread'de context süresince engellenen istekleri sayar."""
    previous = getattr(_tracking, "tracker", None)
    tracker = BlockTracker()
    _tracking.tracker = tracker
    try:
        yield tracker
    finally:
        _tracking.tracker = previous


def record_blocked_destination(destination: str, reason: str) -> None:
    """Engellenen giden bağlantıyı loglar ve (varsa) bu thread'in sayacını artırır."""
    # Tanı bilgisi (çözümlenen IP dahil) yalnızca sunucu loguna yazılır.
    logger.warning("SSRF policy blocked outbound request to %s: %s", destination, reason)
    tracker = getattr(_tracking, "tracker", None)
    if tracker is not None:
        tracker.blocked += 1


def _describe(url: str) -> str:
    """Log için URL'nin yalnızca şema://host:port kısmı (payload'lar loga taşınmaz)."""
    try:
        parts = urlsplit(url)
        return f"{parts.scheme}://{parts.hostname}" + (f":{parts.port}" if parts.port else "")
    except ValueError:
        return "<geçersiz URL>"


# --- Katman 3: IP sabitlemeli urllib3 bağlantıları ---

class _PinnedConnectionMixin:
    """Soketi açmadan hemen önce host'u çözümler, TÜM adresleri doğrular ve yalnızca
    doğrulanmış bir IP'ye bağlanır. TLS SNI / sertifika doğrulaması hostname ile
    yapılmaya devam eder (HTTPSConnection self.host'u kullanır)."""

    def _new_conn(self) -> socket.socket:
        try:
            addresses = resolve_and_validate_host(self._dns_host)
        except HostResolutionError as e:
            raise NameResolutionError(self.host, self, e) from e
        except SSRFError as e:
            record_blocked_destination(f"{self._dns_host}:{self.port}", str(e))
            raise NewConnectionError(
                self, "Failed to establish a new connection: blocked by Lilith SSRF policy"
            ) from None

        last_error: OSError | None = None
        for address in addresses:
            try:
                return urllib3_connection.create_connection(
                    (address, self.port),
                    self.timeout,
                    source_address=self.source_address,
                    socket_options=self.socket_options,
                )
            except socket.timeout as e:
                raise ConnectTimeoutError(
                    self,
                    f"Connection to {self.host} timed out. (connect timeout={self.timeout})",
                ) from e
            except OSError as e:
                last_error = e

        raise NewConnectionError(
            self, f"Failed to establish a new connection: {last_error}"
        ) from last_error


class _PinnedHTTPConnection(_PinnedConnectionMixin, HTTPConnection):
    pass


class _PinnedHTTPSConnection(_PinnedConnectionMixin, HTTPSConnection):
    pass


class _PinnedHTTPConnectionPool(HTTPConnectionPool):
    ConnectionCls = _PinnedHTTPConnection


class _PinnedHTTPSConnectionPool(HTTPSConnectionPool):
    ConnectionCls = _PinnedHTTPSConnection


# --- Katman 2: her gönderimde DNS yeniden doğrulaması ---

class SSRFGuardAdapter(HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
        super().init_poolmanager(*args, **kwargs)
        self.poolmanager.pool_classes_by_scheme = {
            "http": _PinnedHTTPConnectionPool,
            "https": _PinnedHTTPSConnectionPool,
        }

    def send(self, request, *args, **kwargs):
        try:
            validate_url(request.url)
        except HostResolutionError as e:
            # Çözümlenemeyen host politika engeli değildir — requests'teki gibi bağlantı hatası
            raise requests.exceptions.ConnectionError(str(e), request=request) from None
        except SSRFError as e:
            record_blocked_destination(_describe(request.url), str(e))
            raise OutboundRequestBlocked(str(e)) from None
        return super().send(request, *args, **kwargs)


# --- Katman 1: kontrollü yönlendirme takibi ---

class SafeSession:
    """requests.Session ile uyumlu (scanner'ların kullandığı alt küme), SSRF
    politikasını her istekte uygulayan dar arayüzlü istemci."""

    def __init__(self, inner: requests.Session):
        self._inner = inner
        # Ortamdaki HTTP(S)_PROXY / ALL_PROXY, .netrc ve CA bundle değişkenleri miras
        # alınmaz: proxy, çözümlemeyi ve bağlantıyı Lilith'in doğrulama/IP sabitleme
        # katmanının dışına taşırdı. Lilith'in belgelenmiş bir proxy özelliği yoktur.
        self._inner.trust_env = False
        adapter = SSRFGuardAdapter()
        self._inner.mount("http://", adapter)
        self._inner.mount("https://", adapter)

    @property
    def headers(self):
        return self._inner.headers

    @property
    def cookies(self):
        return self._inner.cookies

    def get(self, url, **kwargs):
        kwargs.setdefault("allow_redirects", True)
        return self.request("GET", url, **kwargs)

    def post(self, url, **kwargs):
        kwargs.setdefault("allow_redirects", True)
        return self.request("POST", url, **kwargs)

    def options(self, url, **kwargs):
        kwargs.setdefault("allow_redirects", True)
        return self.request("OPTIONS", url, **kwargs)

    def head(self, url, **kwargs):
        kwargs.setdefault("allow_redirects", False)
        return self.request("HEAD", url, **kwargs)

    def request(self, method, url, **kwargs):
        follow = kwargs.pop("allow_redirects", True)
        method = method.upper()
        current_url = url
        history = []
        visits: dict[tuple[str, str], int] = {}

        while True:
            current_url = self._check(current_url)
            key = (method, current_url)
            visits[key] = visits.get(key, 0) + 1
            if visits[key] > _MAX_VISITS_PER_URL:
                raise requests.TooManyRedirects("Redirect loop detected.", response=history[-1])

            response = self._send(method, current_url, kwargs)

            next_url = self._redirect_target(response, current_url) if follow else None
            if next_url is None:
                if history:
                    response.history = history
                return response

            history.append(response)
            if len(history) > MAX_REDIRECTS:
                raise requests.TooManyRedirects(
                    f"Exceeded {MAX_REDIRECTS} redirects.", response=response
                )
            response.close()
            method, kwargs = self._rebuild_for_redirect(
                method, response.status_code, current_url, next_url, kwargs
            )
            current_url = next_url

    def close(self):
        self._inner.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    # --- iç yardımcılar ---

    @staticmethod
    def _check(url) -> str:
        # requests ile aynı: URL str'e çevrilir; şemasız URL politika engeli değil,
        # geçersiz URL'dir (requests de MissingSchema fırlatır).
        url = url.decode("utf8") if isinstance(url, bytes) else str(url)
        try:
            has_scheme = bool(urlsplit(url).scheme)
        except ValueError:
            raise requests.exceptions.InvalidURL(f"Invalid URL {url!r}") from None
        if not has_scheme:
            raise requests.exceptions.MissingSchema(f"Invalid URL {url!r}: No scheme supplied.")

        try:
            check_url_target(url)
        except SSRFError as e:
            record_blocked_destination(_describe(url), str(e))
            raise OutboundRequestBlocked(str(e)) from None
        return url

    def _send(self, method: str, url: str, kwargs: dict):
        # Mevcut get/post/options/head/request ayrımı korunur — tek fark
        # yönlendirmelerin requests'e bırakılmamasıdır.
        call_kwargs = dict(kwargs, allow_redirects=False)
        if method == "GET":
            return self._inner.get(url, **call_kwargs)
        if method == "POST":
            return self._inner.post(url, **call_kwargs)
        if method == "OPTIONS":
            return self._inner.options(url, **call_kwargs)
        if method == "HEAD":
            return self._inner.head(url, **call_kwargs)
        return self._inner.request(method, url, **call_kwargs)

    @staticmethod
    def _redirect_target(response, current_url: str) -> str | None:
        status = getattr(response, "status_code", None)
        if not isinstance(status, int) or status not in _REDIRECT_STATUSES:
            return None
        location = response.headers.get("location")
        if not isinstance(location, str) or not location:
            return None
        try:
            # requests ile aynı: header latin-1 olarak gelir, UTF-8 olarak yorumlanır
            location = location.encode("latin1").decode("utf8")
        except UnicodeError:
            pass
        return requote_uri(urljoin(current_url, location))

    @staticmethod
    def _rebuild_for_redirect(method: str, status: int, current_url: str,
                              next_url: str, kwargs: dict) -> tuple[str, dict]:
        """requests.Session.rebuild_method / resolve_redirects / rebuild_auth ile aynı kurallar."""
        new_kwargs = {k: v for k, v in kwargs.items() if k != "params"}

        if (status in (302, 303) and method != "HEAD") or (status == 301 and method == "POST"):
            method = "GET"
        if status not in (307, 308):
            # requests: 301/302/303'te gövde, yöntem değişmese bile (ör. PUT + 301) gönderilmez
            for name in _BODY_KWARGS:
                new_kwargs.pop(name, None)

        if urlsplit(current_url).hostname != urlsplit(next_url).hostname:
            # Farklı host'a yönlendirmede Authorization taşınmaz (None, session
            # seviyesindeki değeri de requests'te siler).
            new_kwargs.pop("auth", None)
            new_kwargs["headers"] = {**(new_kwargs.get("headers") or {}), "Authorization": None}

        return method, new_kwargs


def safe_session(inner: requests.Session | SafeSession | None = None) -> SafeSession:
    """Scanner'lar için tek giriş noktası. Dışarıdan verilen bir requests.Session da
    sarmalanır — SSRF politikası atlanamaz."""
    if isinstance(inner, SafeSession):
        return inner
    return SafeSession(inner if inner is not None else requests.Session())
