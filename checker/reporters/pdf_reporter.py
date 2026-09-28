"""
checker/reporters/pdf_reporter.py

Generates a PDF security report using ReportLab.
Sections: title page, executive summary, methodology, findings table,
detailed findings with evidence, appendix of passing checks.
"""

from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime, timezone
from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
    SimpleDocTemplate,
    HRFlowable,
)

# ---------------------------------------------------------------------------
# Color palette
# ---------------------------------------------------------------------------
_RED = colors.HexColor("#ef4444")
_ORANGE = colors.HexColor("#f97316")
_YELLOW = colors.HexColor("#eab308")
_GREEN = colors.HexColor("#22c55e")
_BLUE = colors.HexColor("#3b82f6")
_GRAY_LIGHT = colors.HexColor("#f3f4f6")
_GRAY_MID = colors.HexColor("#d1d5db")
_DARK = colors.HexColor("#111827")
_HEADER_BG = colors.HexColor("#1e3a5f")

_SEVERITY_COLORS = {
    "HIGH": _RED,
    "MEDIUM": _ORANGE,
    "LOW": _YELLOW,
    "INFO": _BLUE,
}

_VERDICT_COLORS = {
    "NEEDS_FIX": _RED,
    "PASSES": _GREEN,
    "INCONCLUSIVE": _YELLOW,
}

# ---------------------------------------------------------------------------
# Styles
# ---------------------------------------------------------------------------

def _build_styles():
    base = getSampleStyleSheet()
    styles = {}

    styles["title"] = ParagraphStyle(
        "ReportTitle", parent=base["Title"],
        fontSize=28, leading=34, textColor=_DARK, spaceAfter=6,
    )
    styles["subtitle"] = ParagraphStyle(
        "ReportSubtitle", parent=base["Normal"],
        fontSize=13, leading=16, textColor=colors.HexColor("#6b7280"), spaceAfter=4,
    )
    styles["h1"] = ParagraphStyle(
        "H1", parent=base["Heading1"],
        fontSize=16, leading=20, textColor=_HEADER_BG, spaceAfter=6, spaceBefore=14,
    )
    styles["h2"] = ParagraphStyle(
        "H2", parent=base["Heading2"],
        fontSize=13, leading=16, textColor=_HEADER_BG, spaceAfter=4, spaceBefore=10,
    )
    styles["body"] = ParagraphStyle(
        "Body", parent=base["Normal"],
        fontSize=9, leading=13, spaceAfter=4,
    )
    styles["code"] = ParagraphStyle(
        "Code", parent=base["Code"],
        fontSize=7.5, leading=10, fontName="Courier",
        backColor=_GRAY_LIGHT, leftIndent=6, rightIndent=6,
        spaceBefore=4, spaceAfter=4,
    )
    styles["small"] = ParagraphStyle(
        "Small", parent=base["Normal"],
        fontSize=7.5, leading=10, textColor=colors.HexColor("#6b7280"),
    )
    styles["remediation"] = ParagraphStyle(
        "Remediation", parent=base["Normal"],
        fontSize=8.5, leading=12,
        backColor=colors.HexColor("#fef9c3"),
        leftIndent=8, rightIndent=8, spaceBefore=4, spaceAfter=6,
        borderPad=4,
    )
    return styles


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def generate_pdf(scan: dict, results: list[dict]) -> bytes:
    buf = BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=20 * mm,
        rightMargin=20 * mm,
        topMargin=20 * mm,
        bottomMargin=20 * mm,
        title="Authorization Check Report",
        author="BOLA Checker",
    )

    styles = _build_styles()
    story: list = []

    findings = [r for r in results if r.get("verdict") == "NEEDS_FIX"]
    passes = [r for r in results if r.get("verdict") == "PASSES"]
    inconclusive = [r for r in results if r.get("verdict") == "INCONCLUSIVE"]

    _add_title_page(story, styles, scan)
    story.append(PageBreak())
    _add_executive_summary(story, styles, scan, findings, passes, inconclusive)
    story.append(PageBreak())
    _add_methodology(story, styles)
    story.append(PageBreak())
    _add_findings_table(story, styles, findings)
    story.append(PageBreak())
    _add_detailed_findings(story, styles, findings)
    if passes:
        story.append(PageBreak())
        _add_appendix_passes(story, styles, passes)

    doc.build(story)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Section builders
# ---------------------------------------------------------------------------

def _add_title_page(story, styles, scan):
    story.append(Spacer(1, 30 * mm))
    story.append(Paragraph("Authorization Check Report", styles["title"]))
    story.append(Paragraph("BOLA / IDOR Security Assessment", styles["subtitle"]))
    story.append(HRFlowable(width="100%", thickness=2, color=_HEADER_BG))
    story.append(Spacer(1, 10 * mm))

    meta_data = [
        ["Target URL", scan.get("target_url", "—")],
        ["Spec Source", scan.get("spec_source", "—").capitalize()],
        ["Scan ID", (scan.get("id") or "—")[:16] + "…"],
        ["Started", _fmt_dt(scan.get("started_at"))],
        ["Completed", _fmt_dt(scan.get("completed_at"))],
        ["Generated", _fmt_dt(datetime.now(timezone.utc).isoformat())],
    ]
    t = Table(meta_data, colWidths=[50 * mm, 110 * mm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), _GRAY_LIGHT),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.5, _GRAY_MID),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, _GRAY_LIGHT]),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(t)
    story.append(Spacer(1, 6 * mm))
    story.append(Paragraph(
        "⚠ This report was generated by an automated authorization checker "
        "for educational and authorised testing purposes only. All findings "
        "relate to a self-contained demo application.",
        styles["small"],
    ))


def _add_executive_summary(story, styles, scan, findings, passes, inconclusive):
    story.append(Paragraph("Executive Summary", styles["h1"]))
    story.append(HRFlowable(width="100%", thickness=1, color=_GRAY_MID))
    story.append(Spacer(1, 3 * mm))

    total = len(findings) + len(passes) + len(inconclusive)
    story.append(Paragraph(
        f"The checker performed {total} authorization checks against "
        f"<b>{scan.get('target_url', '—')}</b>. "
        f"The table below summarises the results by verdict and severity.",
        styles["body"],
    ))
    story.append(Spacer(1, 3 * mm))

    # Verdict summary table
    verdict_data = [
        ["Verdict", "Count", "Meaning"],
        ["NEEDS FIX", str(len(findings)), "Authorization gap confirmed — requires remediation"],
        ["PASSES", str(len(passes)), "Access correctly denied or behavior correct"],
        ["INCONCLUSIVE", str(len(inconclusive)), "Ambiguous result — manual review recommended"],
        ["TOTAL", str(total), ""],
    ]
    vt = Table(verdict_data, colWidths=[40 * mm, 20 * mm, 100 * mm])
    vt.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), _HEADER_BG),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.5, _GRAY_MID),
        ("BACKGROUND", (0, 1), (-1, 1), colors.HexColor("#fee2e2")),
        ("BACKGROUND", (0, 2), (-1, 2), colors.HexColor("#dcfce7")),
        ("BACKGROUND", (0, 3), (-1, 3), colors.HexColor("#fef9c3")),
        ("BACKGROUND", (0, 4), (-1, 4), _GRAY_LIGHT),
        ("FONTNAME", (0, 4), (-1, 4), "Helvetica-Bold"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(vt)
    story.append(Spacer(1, 4 * mm))

    # Severity breakdown
    by_sev: dict[str, int] = defaultdict(int)
    for r in findings:
        by_sev[r.get("severity", "INFO")] += 1

    story.append(Paragraph("Findings by Severity (NEEDS FIX only)", styles["h2"]))
    sev_data = [["Severity", "Count"]]
    for sev in ["HIGH", "MEDIUM", "LOW", "INFO"]:
        sev_data.append([sev, str(by_sev.get(sev, 0))])
    st = Table(sev_data, colWidths=[50 * mm, 30 * mm])
    st.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), _HEADER_BG),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.5, _GRAY_MID),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(st)


def _add_methodology(story, styles):
    story.append(Paragraph("Methodology", styles["h1"]))
    story.append(HRFlowable(width="100%", thickness=1, color=_GRAY_MID))
    story.append(Spacer(1, 3 * mm))
    story.append(Paragraph(
        "The checker implements 10 distinct authorization check modules targeting "
        "the OWASP API Security Top 10 category API1:2023 — Broken Object Level "
        "Authorization (BOLA/IDOR). Each module is applied to every applicable "
        "endpoint discovered from the provided specification.",
        styles["body"],
    ))
    story.append(Spacer(1, 3 * mm))

    modules = [
        ["Module", "Description", "Severity"],
        ["HorizontalBOLA", "User A's token accessing User B's resource IDs", "HIGH"],
        ["VerticalPrivilege", "Non-admin role accessing admin-only endpoints", "HIGH"],
        ["MissingAuth", "Unauthenticated request to protected endpoint", "HIGH"],
        ["MalformedAuth", "Invalid/empty/wrong-scheme auth tokens", "MEDIUM"],
        ["IDManipulation", "Boundary, negative, string, and adjacent ID fuzzing", "MEDIUM"],
        ["MassAssignment", "Injecting role/is_admin/privilege fields in request body", "HIGH"],
        ["MethodSubstitution", "Alternate HTTP verbs on defined routes", "LOW"],
        ["ResponseLeakage", "Denial responses checked for stack traces / other-user data", "MEDIUM"],
        ["CrossEndpointGraph", "IDs from one endpoint's response probed on related endpoints", "HIGH"],
        ["QueryParamSubstitution", "?user_id= and ?admin= query params honored by server", "HIGH"],
    ]
    mt = Table(modules, colWidths=[50 * mm, 95 * mm, 20 * mm])
    mt.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), _HEADER_BG),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.5, _GRAY_MID),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, _GRAY_LIGHT]),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(mt)


def _add_findings_table(story, styles, findings):
    story.append(Paragraph("Findings Overview", styles["h1"]))
    story.append(HRFlowable(width="100%", thickness=1, color=_GRAY_MID))
    story.append(Spacer(1, 3 * mm))

    if not findings:
        story.append(Paragraph("✓ No authorization gaps found. All checks passed.", styles["body"]))
        return

    story.append(Paragraph(
        f"{len(findings)} authorization gap(s) identified. All require remediation.",
        styles["body"],
    ))
    story.append(Spacer(1, 2 * mm))

    headers = ["#", "Severity", "Endpoint", "Method", "Module", "Actual Status"]
    rows = [headers]
    for i, r in enumerate(findings, 1):
        rows.append([
            str(i),
            r.get("severity", "—"),
            _truncate(r.get("endpoint", "—"), 35),
            r.get("method", "—"),
            r.get("module_name", "—"),
            str(r.get("actual_status", "—")),
        ])

    col_widths = [8 * mm, 22 * mm, 55 * mm, 18 * mm, 42 * mm, 20 * mm]
    t = Table(rows, colWidths=col_widths, repeatRows=1)
    style_cmds = [
        ("BACKGROUND", (0, 0), (-1, 0), _HEADER_BG),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.5, _GRAY_MID),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, _GRAY_LIGHT]),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]
    # Color-code severity column
    for i, r in enumerate(findings, 1):
        sev = r.get("severity", "INFO")
        c = _SEVERITY_COLORS.get(sev, _BLUE)
        style_cmds.append(("TEXTCOLOR", (1, i), (1, i), c))
        style_cmds.append(("FONTNAME", (1, i), (1, i), "Helvetica-Bold"))
    t.setStyle(TableStyle(style_cmds))
    story.append(t)


def _add_detailed_findings(story, styles, findings):
    story.append(Paragraph("Detailed Findings", styles["h1"]))
    story.append(HRFlowable(width="100%", thickness=1, color=_GRAY_MID))

    for i, r in enumerate(findings, 1):
        story.append(Spacer(1, 4 * mm))
        sev = r.get("severity", "INFO")
        sev_color = _SEVERITY_COLORS.get(sev, _BLUE)

        # Finding header
        story.append(Paragraph(
            f"<b>Finding #{i} — {sev} — {r.get('module_name', '?')}</b>",
            ParagraphStyle("FindingH", parent=styles["h2"], textColor=sev_color),
        ))
        story.append(Paragraph(
            f"<b>Endpoint:</b> {r.get('method', '')} {r.get('endpoint', '')}",
            styles["body"],
        ))
        story.append(Paragraph(
            f"<b>Expected Status:</b> {r.get('expected_status', '?')} &nbsp;&nbsp; "
            f"<b>Actual Status:</b> {r.get('actual_status', '?')}",
            styles["body"],
        ))

        # Payload
        payload = r.get("payload_json") or r.get("payload") or {}
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except Exception:
                pass
        if payload:
            story.append(Paragraph("<b>Request Payload:</b>", styles["body"]))
            story.append(Paragraph(
                json.dumps(payload, indent=2)[:600],
                styles["code"],
            ))

        # Response snippet
        resp_snip = r.get("response_snippet", "")
        if resp_snip:
            story.append(Paragraph("<b>Response Body (snippet):</b>", styles["body"]))
            story.append(Paragraph(_escape(resp_snip[:500]), styles["code"]))

        # Evidence diff
        diff = r.get("evidence_diff", "")
        if diff:
            story.append(Paragraph("<b>Evidence:</b>", styles["body"]))
            story.append(Paragraph(_escape(diff[:400]), styles["code"]))

        # Remediation
        rem = r.get("remediation", "")
        if rem:
            story.append(Paragraph(f"💡 <b>Remediation:</b> {rem}", styles["remediation"]))

        story.append(HRFlowable(width="100%", thickness=0.5, color=_GRAY_MID, spaceAfter=3))


def _add_appendix_passes(story, styles, passes):
    story.append(Paragraph("Appendix — Passing Checks", styles["h1"]))
    story.append(HRFlowable(width="100%", thickness=1, color=_GRAY_MID))
    story.append(Spacer(1, 3 * mm))
    story.append(Paragraph(
        f"{len(passes)} check(s) confirmed correct authorization behavior.",
        styles["body"],
    ))
    story.append(Spacer(1, 2 * mm))

    rows = [["Endpoint", "Method", "Module", "Status"]]
    for r in passes[:100]:  # cap at 100 in appendix
        rows.append([
            _truncate(r.get("endpoint", "—"), 40),
            r.get("method", "—"),
            r.get("module_name", "—"),
            str(r.get("actual_status", "—")),
        ])
    t = Table(rows, colWidths=[70 * mm, 18 * mm, 50 * mm, 20 * mm], repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), _HEADER_BG),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 7.5),
        ("GRID", (0, 0), (-1, -1), 0.5, _GRAY_MID),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, _GRAY_LIGHT]),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    story.append(t)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fmt_dt(dt_str: str | None) -> str:
    if not dt_str:
        return "—"
    try:
        dt = datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M UTC")
    except Exception:
        return str(dt_str)


def _truncate(s: str, n: int) -> str:
    return s if len(s) <= n else s[:n - 1] + "…"


def _escape(s: str) -> str:
    """Escape XML special chars for ReportLab Paragraph."""
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
