from __future__ import annotations

from datetime import datetime, timezone
from io import BytesIO
from typing import Any

from app.core.config import Settings

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.pdfgen import canvas
except Exception:  # pragma: no cover - optional import guard
    A4 = (595.27, 841.89)
    canvas = None
    mm = 2.8346456693


def _text(payload: dict[str, Any], key: str) -> str:
    value = payload.get(key)
    if value is None:
        return "-"
    clean = str(value).strip()
    return clean or "-"


def _num(payload: dict[str, Any], key: str) -> str:
    value = payload.get(key)
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str) and value.strip():
        return value.strip()
    return "0"


def build_analysis_report_pdf(analysis: dict[str, Any], settings: Settings) -> bytes:
    if canvas is None:
        raise RuntimeError("PDF generator dependency is unavailable. Install reportlab.")

    buffer = BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4
    margin = 16 * mm
    y = height - margin

    title = f"{settings.report_pdf_title_prefix} - {_text(analysis, 'project_key')}"
    generated_at = datetime.now(timezone.utc).isoformat()
    status = _text(analysis, "status")
    quality_gate = analysis.get("quality_gate", {})
    measures = analysis.get("measures", {})
    dependency_summary = analysis.get("dependency_scan_summary", {})

    def line(label: str, value: str, spacing: float = 6.5 * mm) -> None:
        nonlocal y
        pdf.setFont("Helvetica-Bold", 10)
        pdf.drawString(margin, y, f"{label}:")
        pdf.setFont("Helvetica", 10)
        pdf.drawString(margin + 42 * mm, y, value)
        y -= spacing

    pdf.setTitle(title)
    pdf.setAuthor(settings.report_pdf_author)
    pdf.setFont("Helvetica-Bold", 16)
    pdf.drawString(margin, y, title)
    y -= 10 * mm
    pdf.setFont("Helvetica", 9)
    pdf.drawString(margin, y, f"Generated at: {generated_at}")
    y -= 10 * mm

    pdf.setFont("Helvetica-Bold", 12)
    pdf.drawString(margin, y, "Overview")
    y -= 7 * mm
    line("Repository", _text(analysis, "repository_full_name"))
    line("Branch", _text(analysis, "branch"))
    line("Commit", _text(analysis, "commit_sha"))
    line("Execution Status", status)
    line("Quality Gate", _text(quality_gate if isinstance(quality_gate, dict) else {}, "status"))
    line("Analysis Key", _text(analysis, "analysis_key"))
    line("CE Task ID", _text(analysis, "ce_task_id"))

    y -= 3 * mm
    pdf.setFont("Helvetica-Bold", 12)
    pdf.drawString(margin, y, "Code Quality Metrics")
    y -= 7 * mm
    metrics = measures if isinstance(measures, dict) else {}
    line("Bugs", _num(metrics, "bugs"))
    line("Vulnerabilities", _num(metrics, "vulnerabilities"))
    line("Security Hotspots", _num(metrics, "security_hotspots"))
    line("Code Smells", _num(metrics, "code_smells"))
    line("Coverage (%)", _num(metrics, "coverage"))
    line("Duplication (%)", _num(metrics, "duplicated_lines_density"))

    y -= 3 * mm
    pdf.setFont("Helvetica-Bold", 12)
    pdf.drawString(margin, y, "Dependency Scan (Trivy)")
    y -= 7 * mm
    dep = dependency_summary if isinstance(dependency_summary, dict) else {}
    line("Tool", _text(dep, "tool"))
    line("Mode", _text(dep, "scan_mode"))
    line("Vulnerability Count", _num(dep, "vulnerability_count"))
    line("Lockfiles Scanned", _num(dep, "lockfiles_count"))
    line("Cache Hit", "true" if analysis.get("dependency_cache_hit") is True else "false")

    warnings = analysis.get("warning_message")
    if isinstance(warnings, str) and warnings.strip():
        y -= 3 * mm
        pdf.setFont("Helvetica-Bold", 12)
        pdf.drawString(margin, y, "Warnings")
        y -= 7 * mm
        pdf.setFont("Helvetica", 10)
        wrapped = warnings.strip()
        pdf.drawString(margin, y, wrapped[:120])

    pdf.showPage()
    pdf.save()
    return buffer.getvalue()
