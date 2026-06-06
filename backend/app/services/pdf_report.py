from __future__ import annotations

from datetime import datetime, timezone
from html import escape
from io import BytesIO
import json
import re
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    Flowable,
    HRFlowable,
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from app.schemas.results import AnalysisResponse, SourceResult

BRAND_NAVY = colors.HexColor("#0f172a")
BRAND_CYAN = colors.HexColor("#0891b2")
BRAND_TEAL = colors.HexColor("#0f766e")
BRAND_AMBER = colors.HexColor("#d97706")
BRAND_ROSE = colors.HexColor("#be123c")
INK = colors.HexColor("#18181b")
MUTED = colors.HexColor("#52525b")
RULE = colors.HexColor("#d4d4d8")
SURFACE = colors.HexColor("#f8fafc")


def build_analysis_report_pdf(result: AnalysisResponse) -> bytes:
    """Create an executive PDF report for a completed threat analysis."""
    generated_at = datetime.now(timezone.utc)
    buffer = BytesIO()
    document = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=0.58 * inch,
        rightMargin=0.58 * inch,
        topMargin=0.68 * inch,
        bottomMargin=0.62 * inch,
        title="Threat Intelligence Executive Report",
        author="Threat Intelligence Dashboard",
        subject=f"Threat analysis report for {result.ioc.normalized_value}",
        creator="Threat Intelligence Dashboard",
        pageCompression=0,
    )

    styles = _build_styles()
    story: list[Flowable] = []
    story.extend(_cover_panel(result, generated_at, styles))
    story.extend(_executive_summary(result, styles))
    story.extend(_recommended_actions(result, styles))
    story.extend(_evidence_table(result, styles))
    story.extend(_source_coverage(result, styles))
    story.extend(_source_appendix(result, styles))

    document.build(
        story,
        onFirstPage=lambda canvas, doc: _draw_page_frame(canvas, doc, result, generated_at),
        onLaterPages=lambda canvas, doc: _draw_page_frame(canvas, doc, result, generated_at),
    )
    return buffer.getvalue()


def report_filename(result: AnalysisResponse) -> str:
    target = re.sub(r"[^a-zA-Z0-9.-]+", "-", result.ioc.normalized_value).strip("-")
    target = target[:48] or "indicator"
    return f"threat-report-{target}-{str(result.analysis_id)[:8]}.pdf"


def _cover_panel(result: AnalysisResponse, generated_at: datetime, styles: dict[str, ParagraphStyle]) -> list[Flowable]:
    report = result.risk_report
    severity_color = _severity_color(report.severity)
    status_counts = _source_status_counts(result)
    generated_text = _format_datetime(generated_at)
    analyzed_text = _format_datetime(result.created_at)

    title = Paragraph("Threat Intelligence Executive Report", styles["cover_title"])
    subtitle = Paragraph(
        "Executive summary, risk decision support, source coverage, and analyst evidence for the submitted indicator.",
        styles["cover_subtitle"],
    )
    label = Paragraph("ENTERPRISE THREAT ASSESSMENT", styles["cover_label"])

    hero_copy = [
        label,
        Spacer(1, 0.08 * inch),
        title,
        Spacer(1, 0.08 * inch),
        subtitle,
        Spacer(1, 0.18 * inch),
        _metadata_table(
            [
                ("Indicator type", result.ioc.input_type.upper()),
                ("Normalized indicator", result.ioc.normalized_value),
                ("Analysis ID", str(result.analysis_id)),
                ("Generated", generated_text),
            ],
            styles,
            dark=True,
        ),
    ]
    score_panel = [
        Paragraph("Risk Posture", styles["score_label"]),
        RiskGauge(report.score, report.severity, severity_color),
        Paragraph(f"{report.score}/100", styles["score_value"]),
        Paragraph(report.severity.upper(), _badge_style(styles, severity_color)),
        Spacer(1, 0.08 * inch),
        Paragraph(
            f"{status_counts['success']} of {status_counts['total']} sources returned usable signal.",
            styles["score_note"],
        ),
    ]

    panel = Table(
        [[hero_copy, score_panel]],
        colWidths=[4.45 * inch, 2.25 * inch],
        style=[
            ("BACKGROUND", (0, 0), (-1, -1), BRAND_NAVY),
            ("BOX", (0, 0), (-1, -1), 0.75, BRAND_NAVY),
            ("LINEBEFORE", (1, 0), (1, 0), 1, colors.HexColor("#334155")),
            ("LEFTPADDING", (0, 0), (-1, -1), 18),
            ("RIGHTPADDING", (0, 0), (-1, -1), 18),
            ("TOPPADDING", (0, 0), (-1, -1), 18),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 18),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ],
    )

    facts = Table(
        [
            [
                _fact_block("Severity", report.severity, severity_color, styles),
                _fact_block("Score", f"{report.score}/100", BRAND_CYAN, styles),
                _fact_block("Status", result.status.title(), BRAND_TEAL, styles),
                _fact_block("Analyzed", analyzed_text, BRAND_AMBER, styles),
            ]
        ],
        colWidths=[1.68 * inch, 1.68 * inch, 1.68 * inch, 1.68 * inch],
        style=[
            ("BACKGROUND", (0, 0), (-1, -1), SURFACE),
            ("BOX", (0, 0), (-1, -1), 0.5, RULE),
            ("INNERGRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#e4e4e7")),
            ("LEFTPADDING", (0, 0), (-1, -1), 12),
            ("RIGHTPADDING", (0, 0), (-1, -1), 12),
            ("TOPPADDING", (0, 0), (-1, -1), 11),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 11),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ],
    )

    return [panel, Spacer(1, 0.16 * inch), facts, Spacer(1, 0.24 * inch)]


def _executive_summary(result: AnalysisResponse, styles: dict[str, ParagraphStyle]) -> list[Flowable]:
    report = result.risk_report
    rows = [
        ("Risk decision", _decision_language(report.severity, report.score)),
        ("Indicator", result.ioc.normalized_value),
        ("Submitted value", result.ioc.submitted_value),
        ("Source coverage", _coverage_sentence(result.source_results)),
    ]
    return [
        _section_heading("Executive Summary", styles),
        Paragraph(_safe_paragraph(report.summary), styles["body"]),
        Spacer(1, 0.12 * inch),
        _metadata_table(rows, styles),
        Spacer(1, 0.22 * inch),
    ]


def _recommended_actions(result: AnalysisResponse, styles: dict[str, ParagraphStyle]) -> list[Flowable]:
    actions = result.risk_report.recommended_actions or ["Preserve this report and re-run analysis if new evidence appears."]
    rows: list[list[Any]] = [[Paragraph("Priority", styles["table_header"]), Paragraph("Recommended action", styles["table_header"])]]
    for index, action in enumerate(actions, start=1):
        rows.append(
            [
                Paragraph(f"{index}", styles["priority_number"]),
                Paragraph(_safe_paragraph(action), styles["table_body"]),
            ]
        )

    table = Table(
        rows,
        colWidths=[0.75 * inch, 5.95 * inch],
        repeatRows=1,
        style=_standard_table_style(header_background=BRAND_TEAL),
    )
    return [_section_heading("Recommended Actions", styles), table, Spacer(1, 0.22 * inch)]


def _evidence_table(result: AnalysisResponse, styles: dict[str, ParagraphStyle]) -> list[Flowable]:
    rows: list[list[Any]] = [
        [
            Paragraph("Source", styles["table_header"]),
            Paragraph("Points", styles["table_header"]),
            Paragraph("Reason", styles["table_header"]),
        ]
    ]
    contributions = result.risk_report.contributions
    if contributions:
        for item in contributions:
            rows.append(
                [
                    Paragraph(_safe_paragraph(item.source_name), styles["table_body_bold"]),
                    Paragraph(str(item.points), styles["table_body_center"]),
                    Paragraph(_safe_paragraph(item.reason), styles["table_body"]),
                ]
            )
    else:
        rows.append(["-", "0", Paragraph("No score evidence was returned by configured sources.", styles["table_body"])])

    table = Table(
        rows,
        colWidths=[1.45 * inch, 0.7 * inch, 4.55 * inch],
        repeatRows=1,
        style=_standard_table_style(header_background=BRAND_CYAN),
    )
    return [_section_heading("Score Evidence", styles), table, Spacer(1, 0.22 * inch)]


def _source_coverage(result: AnalysisResponse, styles: dict[str, ParagraphStyle]) -> list[Flowable]:
    rows: list[list[Any]] = [
        [
            Paragraph("Source", styles["table_header"]),
            Paragraph("Status", styles["table_header"]),
            Paragraph("Signal snapshot", styles["table_header"]),
        ]
    ]
    for source in result.source_results:
        rows.append(
            [
                Paragraph(_safe_paragraph(source.source_name), styles["table_body_bold"]),
                Paragraph(source.status.replace("_", " ").title(), _status_style(styles, source.status)),
                Paragraph(_safe_paragraph(_source_snapshot(source)), styles["table_body"]),
            ]
        )

    table = Table(
        rows,
        colWidths=[1.35 * inch, 1.2 * inch, 4.15 * inch],
        repeatRows=1,
        style=_standard_table_style(header_background=BRAND_NAVY),
    )
    return [_section_heading("Source Coverage", styles), table, Spacer(1, 0.22 * inch)]


def _source_appendix(result: AnalysisResponse, styles: dict[str, ParagraphStyle]) -> list[Flowable]:
    blocks: list[Flowable] = [_section_heading("Appendix: Normalized Evidence", styles)]
    if not result.source_results:
        blocks.extend([Paragraph("No normalized source evidence was captured.", styles["body"]), Spacer(1, 0.12 * inch)])
        return blocks

    for source in result.source_results:
        detail = _compact_json(source.normalized)
        if source.error_message:
            detail = f"Error: {source.error_message}\n{detail}" if detail else f"Error: {source.error_message}"
        blocks.append(
            KeepTogether(
                [
                    Paragraph(_safe_paragraph(source.source_name), styles["appendix_title"]),
                    Paragraph(_safe_paragraph(detail or "No normalized fields returned."), styles["mono"]),
                    Spacer(1, 0.1 * inch),
                ]
            )
        )
    return blocks


def _section_heading(title: str, styles: dict[str, ParagraphStyle]) -> Flowable:
    return KeepTogether(
        [
            Paragraph(title, styles["section_title"]),
            HRFlowable(width="100%", thickness=0.7, color=RULE, spaceBefore=4, spaceAfter=9),
        ]
    )


def _metadata_table(rows: list[tuple[str, str]], styles: dict[str, ParagraphStyle], dark: bool = False) -> Table:
    label_style = styles["meta_label_dark"] if dark else styles["meta_label"]
    value_style = styles["meta_value_dark"] if dark else styles["meta_value"]
    table_rows = [
        [Paragraph(_safe_paragraph(label), label_style), Paragraph(_safe_paragraph(value), value_style)]
        for label, value in rows
    ]
    style = [
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LINEBELOW", (0, 0), (-1, -2), 0.35, colors.HexColor("#334155") if dark else colors.HexColor("#e4e4e7")),
    ]
    return Table(table_rows, colWidths=[1.35 * inch, 2.75 * inch], style=style)


def _fact_block(label: str, value: str, accent: colors.Color, styles: dict[str, ParagraphStyle]) -> list[Flowable]:
    return [
        Paragraph(_safe_paragraph(label.upper()), styles["fact_label"]),
        Spacer(1, 0.03 * inch),
        Paragraph(_safe_paragraph(value), ParagraphStyle("fact_value_accent", parent=styles["fact_value"], textColor=accent)),
    ]


def _build_styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "cover_label": ParagraphStyle(
            "cover_label",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=7.5,
            leading=9,
            textColor=colors.HexColor("#67e8f9"),
            alignment=TA_LEFT,
        ),
        "cover_title": ParagraphStyle(
            "cover_title",
            parent=base["Title"],
            fontName="Helvetica-Bold",
            fontSize=24,
            leading=28,
            textColor=colors.white,
            spaceAfter=0,
        ),
        "cover_subtitle": ParagraphStyle(
            "cover_subtitle",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=9.5,
            leading=14,
            textColor=colors.HexColor("#cbd5e1"),
        ),
        "score_label": ParagraphStyle(
            "score_label",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=8,
            leading=10,
            textColor=colors.HexColor("#cbd5e1"),
            alignment=TA_CENTER,
        ),
        "score_value": ParagraphStyle(
            "score_value",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=23,
            leading=25,
            textColor=colors.white,
            alignment=TA_CENTER,
        ),
        "score_note": ParagraphStyle(
            "score_note",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=7.5,
            leading=10,
            textColor=colors.HexColor("#cbd5e1"),
            alignment=TA_CENTER,
        ),
        "section_title": ParagraphStyle(
            "section_title",
            parent=base["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=13,
            leading=16,
            textColor=BRAND_NAVY,
            spaceAfter=0,
        ),
        "body": ParagraphStyle(
            "body",
            parent=base["BodyText"],
            fontName="Helvetica",
            fontSize=9,
            leading=13.2,
            textColor=INK,
        ),
        "meta_label": ParagraphStyle(
            "meta_label",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=7,
            leading=9,
            textColor=MUTED,
        ),
        "meta_value": ParagraphStyle(
            "meta_value",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=7.8,
            leading=10,
            textColor=INK,
        ),
        "meta_label_dark": ParagraphStyle(
            "meta_label_dark",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=7,
            leading=9,
            textColor=colors.HexColor("#94a3b8"),
        ),
        "meta_value_dark": ParagraphStyle(
            "meta_value_dark",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=7.8,
            leading=10,
            textColor=colors.HexColor("#f8fafc"),
        ),
        "fact_label": ParagraphStyle(
            "fact_label",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=6.6,
            leading=8,
            textColor=MUTED,
        ),
        "fact_value": ParagraphStyle(
            "fact_value",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=10.5,
            leading=13,
            textColor=INK,
        ),
        "table_header": ParagraphStyle(
            "table_header",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=7.5,
            leading=9,
            textColor=colors.white,
        ),
        "table_body": ParagraphStyle(
            "table_body",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=7.6,
            leading=10.2,
            textColor=INK,
        ),
        "table_body_bold": ParagraphStyle(
            "table_body_bold",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=7.6,
            leading=10.2,
            textColor=INK,
        ),
        "table_body_center": ParagraphStyle(
            "table_body_center",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=7.8,
            leading=10,
            textColor=INK,
            alignment=TA_CENTER,
        ),
        "priority_number": ParagraphStyle(
            "priority_number",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=9,
            leading=11,
            textColor=BRAND_TEAL,
            alignment=TA_CENTER,
        ),
        "appendix_title": ParagraphStyle(
            "appendix_title",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=8.5,
            leading=11,
            textColor=BRAND_NAVY,
            spaceAfter=3,
        ),
        "mono": ParagraphStyle(
            "mono",
            parent=base["Code"],
            fontName="Courier",
            fontSize=6.5,
            leading=8.2,
            textColor=colors.HexColor("#27272a"),
            backColor=colors.HexColor("#f4f4f5"),
            borderColor=colors.HexColor("#e4e4e7"),
            borderWidth=0.4,
            borderPadding=5,
            wordWrap="CJK",
        ),
    }


def _standard_table_style(header_background: colors.Color) -> TableStyle:
    return TableStyle(
        [
            ("BACKGROUND", (0, 0), (-1, 0), header_background),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("BACKGROUND", (0, 1), (-1, -1), colors.white),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
            ("BOX", (0, 0), (-1, -1), 0.5, RULE),
            ("INNERGRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#e4e4e7")),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]
    )


def _badge_style(styles: dict[str, ParagraphStyle], color: colors.Color) -> ParagraphStyle:
    return ParagraphStyle(
        "severity_badge",
        parent=styles["score_note"],
        fontName="Helvetica-Bold",
        textColor=colors.white,
        backColor=color,
        borderPadding=(4, 8, 4),
        alignment=TA_CENTER,
    )


def _status_style(styles: dict[str, ParagraphStyle], status: str) -> ParagraphStyle:
    status_color = {
        "success": BRAND_TEAL,
        "partial": BRAND_AMBER,
        "failed": BRAND_ROSE,
        "restricted": BRAND_AMBER,
        "not_configured": MUTED,
        "pending": BRAND_CYAN,
        "stubbed": MUTED,
    }.get(status, MUTED)
    return ParagraphStyle(
        f"status_{status}",
        parent=styles["table_body"],
        fontName="Helvetica-Bold",
        textColor=status_color,
    )


def _draw_page_frame(canvas, document, result: AnalysisResponse, generated_at: datetime) -> None:
    canvas.saveState()
    width, height = letter
    canvas.setTitle("Threat Intelligence Executive Report")
    canvas.setAuthor("Threat Intelligence Dashboard")
    canvas.setSubject(f"Threat analysis report for {result.ioc.normalized_value}")

    canvas.setFillColor(BRAND_NAVY)
    canvas.rect(0, height - 0.32 * inch, width, 0.32 * inch, fill=1, stroke=0)
    canvas.setFillColor(BRAND_CYAN)
    canvas.rect(0, height - 0.35 * inch, width, 0.035 * inch, fill=1, stroke=0)

    canvas.setFont("Helvetica-Bold", 7.5)
    canvas.setFillColor(colors.white)
    canvas.drawString(0.58 * inch, height - 0.205 * inch, "Threat Intelligence Dashboard")
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(colors.HexColor("#cbd5e1"))
    canvas.drawRightString(width - 0.58 * inch, height - 0.205 * inch, f"Report ID {str(result.analysis_id)[:8]}")

    canvas.setStrokeColor(RULE)
    canvas.setLineWidth(0.35)
    canvas.line(0.58 * inch, 0.43 * inch, width - 0.58 * inch, 0.43 * inch)
    canvas.setFont("Helvetica", 6.8)
    canvas.setFillColor(MUTED)
    canvas.drawString(0.58 * inch, 0.27 * inch, f"Generated {_format_datetime(generated_at)} UTC")
    canvas.drawCentredString(width / 2, 0.27 * inch, "For authorized security analysis and internal decision support.")
    canvas.drawRightString(width - 0.58 * inch, 0.27 * inch, f"Page {document.page}")
    canvas.restoreState()


class RiskGauge(Flowable):
    def __init__(self, score: int, severity: str, accent: colors.Color):
        super().__init__()
        self.width = 1.85 * inch
        self.height = 0.82 * inch
        self.score = max(0, min(100, score))
        self.severity = severity
        self.accent = accent

    def draw(self) -> None:
        canvas = self.canv
        canvas.saveState()
        x = 0.13 * inch
        y = 0.08 * inch
        arc_width = 1.58 * inch
        arc_height = 1.1 * inch
        canvas.setLineCap(1)
        canvas.setLineWidth(9)
        canvas.setStrokeColor(colors.HexColor("#334155"))
        canvas.arc(x, y, x + arc_width, y + arc_height, 0, 180)
        if self.score > 0:
            canvas.setStrokeColor(self.accent)
            canvas.arc(x, y, x + arc_width, y + arc_height, 180 - (180 * self.score / 100), 180 * self.score / 100)

        needle_angle = 180 - (180 * self.score / 100)
        canvas.translate(x + arc_width / 2, y + 0.02 * inch)
        canvas.rotate(needle_angle)
        canvas.setStrokeColor(colors.white)
        canvas.setLineWidth(1.5)
        canvas.line(0, 0, arc_width / 2 - 9, 0)
        canvas.setFillColor(colors.white)
        canvas.circle(0, 0, 3.1, fill=1, stroke=0)
        canvas.restoreState()


def _source_status_counts(result: AnalysisResponse) -> dict[str, int]:
    successes = sum(1 for source in result.source_results if source.status in {"success", "partial"})
    return {"success": successes, "total": len(result.source_results)}


def _coverage_sentence(sources: list[SourceResult]) -> str:
    if not sources:
        return "No external sources were applicable to this indicator."
    counts: dict[str, int] = {}
    for source in sources:
        counts[source.status] = counts.get(source.status, 0) + 1
    return ", ".join(f"{count} {status.replace('_', ' ')}" for status, count in sorted(counts.items()))


def _decision_language(severity: str, score: int) -> str:
    if severity in {"Critical", "High"}:
        return f"{severity} risk at {score}/100. Treat as an escalation candidate pending internal corroboration."
    if severity == "Medium":
        return f"Medium risk at {score}/100. Review evidence and search internal telemetry before enforcement."
    return f"Low risk at {score}/100. Preserve as context and monitor for future signal changes."


def _source_snapshot(source: SourceResult) -> str:
    if source.error_message:
        return source.error_message
    if not source.normalized:
        return "No normalized fields returned."
    important_items = []
    for key, value in source.normalized.items():
        if len(important_items) >= 4:
            break
        important_items.append(f"{key}: {_short_value(value)}")
    return "; ".join(important_items)


def _compact_json(value: Any) -> str:
    try:
        text = json.dumps(value, indent=2, sort_keys=True, default=str)
    except TypeError:
        text = str(value)
    text = text[:3500]
    if len(text) == 3500:
        text += "\n... truncated for report readability"
    return text


def _short_value(value: Any) -> str:
    if isinstance(value, list):
        return ", ".join(str(item) for item in value[:4]) or "none"
    if isinstance(value, dict):
        return ", ".join(f"{key}={val}" for key, val in list(value.items())[:3]) or "none"
    return str(value)


def _safe_paragraph(value: Any) -> str:
    return escape(_safe_text(value)).replace("\n", "<br/>")


def _safe_text(value: Any) -> str:
    text = str(value)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    return text.encode("latin-1", "replace").decode("latin-1")


def _severity_color(severity: str) -> colors.Color:
    return {
        "Critical": BRAND_ROSE,
        "High": colors.HexColor("#ea580c"),
        "Medium": BRAND_AMBER,
        "Low": BRAND_TEAL,
    }.get(severity, BRAND_CYAN)


def _format_datetime(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M")
