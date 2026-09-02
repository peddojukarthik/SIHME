"""
fir_pdf.py
Creates the official FIR PDF.

IMPORTANT:
ReportLab Paragraph is used for formatted text. This prevents literal
<b>...</b> tags from appearing in the generated PDF.
"""

from io import BytesIO
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)


def _safe(value) -> str:
    """
    Escape user-entered data before placing it inside a ReportLab
    Paragraph. Newlines become HTML line breaks.
    """
    return (
        escape(str(value or ""))
        .replace("\r\n", "<br/>")
        .replace("\n", "<br/>")
        .replace("\r", "<br/>")
    )


def generate_fir_pdf(
    fir_number: str,
    filed_at: str,
    filed_by: str,
    employee_id: str,
    department: str,
    complainant_name: str,
    incident_type: str,
    incident_date: str,
    location: str,
    description: str,
) -> bytes:

    output = BytesIO()

    doc = SimpleDocTemplate(
        output,
        pagesize=A4,
        leftMargin=20 * mm,
        rightMargin=20 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        title=f"First Information Report - {fir_number}",
        author=str(filed_by),
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "FIRTitle",
        parent=styles["Title"],
        alignment=TA_CENTER,
        fontSize=19,
        leading=23,
        spaceAfter=16,
    )

    normal = ParagraphStyle(
        "FIRNormal",
        parent=styles["Normal"],
        fontSize=10.5,
        leading=15,
    )

    small = ParagraphStyle(
        "FIRSmall",
        parent=normal,
        fontSize=9,
        leading=12,
    )

    heading = ParagraphStyle(
        "FIRHeading",
        parent=normal,
        fontSize=11,
        leading=14,
        spaceBefore=7,
        spaceAfter=7,
    )

    story = []

    story.append(
        Paragraph("FIRST INFORMATION REPORT", title_style)
    )

    header = [
        [
            Paragraph("<b>FIR Number:</b>", normal),
            Paragraph(_safe(fir_number), normal),
        ],
        [
            Paragraph("<b>Date and Time Filed:</b>", normal),
            Paragraph(_safe(filed_at), normal),
        ],
        [
            Paragraph("<b>Filed By:</b>", normal),
            Paragraph(_safe(filed_by), normal),
        ],
        [
            Paragraph("<b>Employee ID:</b>", normal),
            Paragraph(_safe(employee_id), normal),
        ],
        [
            Paragraph("<b>Department:</b>", normal),
            Paragraph(_safe(department), normal),
        ],
    ]

    header_table = Table(
        header,
        colWidths=[48 * mm, 122 * mm],
    )

    header_table.setStyle(
        TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ])
    )

    story.append(header_table)
    story.append(Spacer(1, 14))

    details = [
        [
            Paragraph("<b>Particular</b>", normal),
            Paragraph("<b>Details</b>", normal),
        ],
        [
            Paragraph("Complainant Name", normal),
            Paragraph(_safe(complainant_name), normal),
        ],
        [
            Paragraph("Incident Type", normal),
            Paragraph(_safe(incident_type), normal),
        ],
        [
            Paragraph("Incident Date", normal),
            Paragraph(_safe(incident_date), normal),
        ],
        [
            Paragraph("Location", normal),
            Paragraph(_safe(location), normal),
        ],
    ]

    details_table = Table(
        details,
        colWidths=[55 * mm, 115 * mm],
        repeatRows=1,
    )

    details_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 7),
            ("RIGHTPADDING", (0, 0), (-1, -1), 7),
            ("TOPPADDING", (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ])
    )

    story.append(details_table)
    story.append(Spacer(1, 14))

    story.append(
        Paragraph("<b>Description</b>", heading)
    )

    story.append(
        Paragraph(_safe(description), normal)
    )

    story.append(Spacer(1, 28))

    story.append(
        Paragraph(
            "<b>Digital Filing Record</b>",
            heading,
        )
    )

    story.append(
        Paragraph(
            "This FIR was electronically filed and digitally signed by the submitting officer.",
            small,
        )
    )

    story.append(Spacer(1, 10))

    story.append(
        Paragraph(
            f"<b>FIR Reference:</b> {_safe(fir_number)}",
            small,
        )
    )

    doc.build(story)

    return output.getvalue()
