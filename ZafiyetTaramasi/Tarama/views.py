from django.http import JsonResponse
from django.shortcuts import render, redirect
from django.views.decorators.csrf import csrf_protect, ensure_csrf_cookie

from .scanners.headers import HeaderScanner
from .scanners.ports import PortScanner
from .scanners.sql import SqlInjectionScanner
from .scanners.xss import XssScanner
from .scanners.base import summarize_findings
from .services.evidence_redaction import redact_sensitive_text, redact_sensitive_url
from .services.ssrf_guard import validate_url, SSRFError
from .services.scan_runner import start_scan
from .models import ScanJob


def _normalize_url(url: str) -> str:
    url = url.strip()
    if url and not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    return url


def _parse_target(request) -> tuple[str, None] | tuple[None, str]:
    """Returns (url, None) on success or (None, error_message) on failure."""
    url = _normalize_url(request.POST.get('url_param', ''))
    if not url:
        return None, "URL boş olamaz."
    try:
        validate_url(url)
    except SSRFError as e:
        return None, str(e)
    return url, None


@ensure_csrf_cookie
def index(request):
    return render(request, "Baslangic/index.html")


def Ana(request):
    """Dashboard — yalnızca scan_id ile açılır.

    Ham hedef URL'si hiçbir zaman tarayıcı URL'sine konmaz (adres çubuğu, geçmiş, istek
    logları): landing sayfası hedefi /api/scan/ isteğinin GÖVDESİNDE gönderir ve buraya
    yalnızca scan_id ile gelir. Eski `?url=` gezinmesi kaldırıldı; değeri okunmaz,
    render edilmez, loglanmaz — istek landing'e yönlendirilir.
    """
    scan_id = request.GET.get('scan_id', '')
    if not (scan_id.isascii() and scan_id.isdigit()):
        return redirect('/index')
    try:
        job = ScanJob.objects.get(id=int(scan_id))
    except ScanJob.DoesNotExist:
        return redirect('/index')
    return render(request, "Baslangic/Ana.html", {
        "scan_id": job.id,
        # Kalıcı (zaten güvenli) hedeften; P0-2 öncesi ham kayıtlar için yeniden redakte edilir
        "target_display_url": redact_sensitive_url(job.target),
    })


@csrf_protect
def check_headers(request):
    if request.method != 'POST':
        return JsonResponse({"error": "Sadece POST istekleri kabul edilir."}, status=400)

    url, err = _parse_target(request)
    if err:
        return JsonResponse({"error": err}, status=400)

    result = HeaderScanner().scan(url)

    return JsonResponse({
        "url_param": redact_sensitive_url(result.target),
        "error": redact_sensitive_text(result.error),
        "findings": [f.to_dict() for f in result.findings],
    })


@csrf_protect
def scan_test(request):
    if request.method != 'POST':
        return JsonResponse({"error": "Sadece POST istekleri kabul edilir."}, status=400)

    url, err = _parse_target(request)
    if err:
        return JsonResponse({"error": err}, status=400)

    result = PortScanner().scan(url)

    return JsonResponse({
        "target": redact_sensitive_url(result.target),
        "error": redact_sensitive_text(result.error),
        "findings": [f.to_dict() for f in result.findings],
    })


@csrf_protect
def check_sql_scan(request):
    if request.method != 'POST':
        return JsonResponse({"error": "Sadece POST istekleri kabul edilir."}, status=400)

    url, err = _parse_target(request)
    if err:
        return JsonResponse({"error": err}, status=400)

    result = SqlInjectionScanner().scan(url)

    forms_count = next((int(f.evidence) for f in result.findings if f.title == "forms_detected"), 0)
    report = [
        [f.title, f.evidence or ""]
        for f in result.findings
        if f.title != "forms_detected"
    ]

    return JsonResponse({
        "sql_scanurl": redact_sensitive_url(result.target),
        "info_test": f"[+] Detected {forms_count} forms on {redact_sensitive_url(result.target)}.",
        "sqlscan_report": report,
    })


@csrf_protect
def check_xss_scan(request):
    if request.method != 'POST':
        return JsonResponse({"error": "Sadece POST istekleri kabul edilir."}, status=400)

    url, err = _parse_target(request)
    if err:
        return JsonResponse({"error": err}, status=400)

    result = XssScanner().scan(url)

    forms_count = next((int(f.evidence) for f in result.findings if f.title == "forms_detected"), 0)

    return JsonResponse({
        "xss_scanurl": redact_sensitive_url(result.target),
        "xss_infotest": f"[+] {redact_sensitive_url(result.target)} adresinde {forms_count} form bulundu.",
        "error": redact_sensitive_text(result.error),
        "findings": [
            f.to_dict()
            for f in result.findings
            if f.title != "forms_detected"
        ],
    })


# --- Async Scan API ---

@csrf_protect
def create_scan(request):
    """POST: Yeni bir tarama işi başlatır, hemen job_id döner."""
    if request.method != 'POST':
        return JsonResponse({"error": "Sadece POST istekleri kabul edilir."}, status=400)

    url, err = _parse_target(request)
    if err:
        return JsonResponse({"error": err}, status=400)

    job = start_scan(url)
    return JsonResponse({"job_id": job.id, "status": job.status, "target": redact_sensitive_url(job.target)}, status=201)


def scan_status(request, job_id):
    """GET: Tarama işinin durumunu ve bulgularını döner."""
    try:
        job = ScanJob.objects.get(id=job_id)
    except ScanJob.DoesNotExist:
        return JsonResponse({"error": "Tarama bulunamadı."}, status=404)

    # ThreadPoolExecutor tamamlanma sırası deterministik değildir — API çıktısı için
    # gerçek risk sırasına göre (CRITICAL→INFO), eşitlikte scanner/title/affected_url/
    # parameter'a göre sabit bir sıralama uygulanır (CLAUDE.md §5).
    findings = sorted(
        job.findings.all(),
        key=lambda f: (
            f.severity_rank,
            f.scanner,
            f.title,
            f.affected_url or "",
            f.parameter or "",
        ),
    )

    return JsonResponse({
        "job_id": job.id,
        "target": redact_sensitive_url(job.target),
        "status": job.status,
        "error": job.error,
        "duration_seconds": job.duration_seconds,
        "created_at": job.created_at.isoformat(),
        "completed_at": job.completed_at.isoformat() if job.completed_at else None,
        "summary": summarize_findings(findings),
        "findings": [f.to_dict() for f in findings],
    })


def scan_history(request):
    """GET: Son 20 tarama işini listeler."""
    jobs = ScanJob.objects.all()[:20]
    return JsonResponse({
        "scans": [
            {
                "job_id": j.id,
                "target": redact_sensitive_url(j.target),
                "status": j.status,
                "duration_seconds": j.duration_seconds,
                "created_at": j.created_at.isoformat(),
                "completed_at": j.completed_at.isoformat() if j.completed_at else None,
            }
            for j in jobs
        ]
    })
