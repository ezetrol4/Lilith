from django.urls import path
from . import views

urlpatterns = [
    path("", views.index),
    path("index", views.index),
    path("Ana/", views.Ana),
    path("Ana/check_headers", views.check_headers, name="check_headers"),
    path("Ana/scan_test", views.scan_test, name="scan_test"),
    path("Ana/check_sql_scan", views.check_sql_scan, name="check_sql_scan"),
    path("Ana/check_xss_scan", views.check_xss_scan, name="check_xss_scan"),
    # Async Scan API
    path("api/scan/", views.create_scan, name="create_scan"),
    path("api/scan/history/", views.scan_history, name="scan_history"),
    path("api/scan/<int:job_id>/", views.scan_status, name="scan_status"),
]
