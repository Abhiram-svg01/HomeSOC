
"""Build downloadable HomeSOC incident reports from existing incident data."""

from datetime import datetime, timezone
from io import BytesIO
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


# ==================================================
# HOMESOC BRAND COLORS
# ==================================================

ESPRESSO = colors.HexColor("#241B16")
CHAMPAGNE = colors.HexColor("#C49A53")
EMERALD = colors.HexColor("#167B5B")
CRITICAL_RED = colors.HexColor("#E10600")

CREAM = colors.HexColor("#F8F5EF")
PALE = colors.HexColor("#EEE7DC")
INK = colors.HexColor("#322B25")
MUTED = colors.HexColor("#6D6257")


# ==================================================
# DATA HELPERS
# ==================================================

def _safe(value, fallback="Not recorded"):
    """
    Escape database text before passing it
    to a ReportLab Paragraph.
    """

    if value is None or value == "":
        value = fallback

    return escape(str(value)).replace(
        "\n",
        "<br/>"
    )


def _field(record, key, fallback="Not recorded"):
    """
    Read dictionary or sqlite3.Row data safely.
    """

    data = dict(record)

    value = data.get(key)

    if value is None or value == "":
        return fallback

    return value


# ==================================================
# REPORT TYPOGRAPHY
# ==================================================

def _styles():

    return {

        "brand": ParagraphStyle(
            "HomeSOCBrand",
            fontName="Helvetica-Bold",
            fontSize=22,
            leading=27,
            textColor=colors.HexColor("#F0D3A0"),
            spaceAfter=3,
        ),

        "subtitle": ParagraphStyle(
            "HomeSOCSubtitle",
            fontName="Helvetica",
            fontSize=10,
            leading=14,
            textColor=colors.HexColor("#E3D6C5"),
        ),

        "section": ParagraphStyle(
            "HomeSOCSection",
            fontName="Helvetica-Bold",
            fontSize=12,
            leading=16,
            textColor=ESPRESSO,
            spaceBefore=17,
            spaceAfter=9,
            keepWithNext=True,
        ),

        "body": ParagraphStyle(
            "HomeSOCBody",
            fontName="Helvetica",
            fontSize=9,
            leading=14,
            textColor=INK,
            spaceAfter=6,
            splitLongWords=True,
        ),

        "small": ParagraphStyle(
            "HomeSOCSmall",
            fontName="Helvetica",
            fontSize=8,
            leading=12,
            textColor=MUTED,
            spaceAfter=5,
            splitLongWords=True,
        ),

        "cell": ParagraphStyle(
            "HomeSOCCell",
            fontName="Helvetica",
            fontSize=8.5,
            leading=12,
            textColor=INK,
            splitLongWords=True,
        ),

        "severity": ParagraphStyle(
            "HomeSOCSeverity",
            fontName="Helvetica-Bold",
            fontSize=8.5,
            leading=12,
            textColor=CRITICAL_RED,
            splitLongWords=True,
        ),

        "cell_label": ParagraphStyle(
            "HomeSOCCellLabel",
            fontName="Helvetica-Bold",
            fontSize=7.5,
            leading=11,
            textColor=MUTED,
            splitLongWords=True,
        ),

        "table_head": ParagraphStyle(
            "HomeSOCTableHead",
            fontName="Helvetica-Bold",
            fontSize=8,
            leading=11,
            textColor=colors.white,
        ),

        "event": ParagraphStyle(
            "HomeSOCEvent",
            fontName="Helvetica-Bold",
            fontSize=9,
            leading=13,
            textColor=ESPRESSO,
            spaceBefore=9,
            spaceAfter=4,
            keepWithNext=True,
        ),

        "warning": ParagraphStyle(
            "HomeSOCWarning",
            fontName="Helvetica-Oblique",
            fontSize=8,
            leading=12,
            textColor=MUTED,
        ),
    }


# ==================================================
# PAGE FOOTER
# ==================================================

def _footer(canvas, document):

    canvas.saveState()

    width, _ = letter

    canvas.setStrokeColor(PALE)

    canvas.line(
        43,
        40,
        width - 43,
        40
    )

    canvas.setFont(
        "Helvetica",
        7.5
    )

    canvas.setFillColor(MUTED)

    canvas.drawString(
        43,
        27,
        "HOMESOC  |  LAB INCIDENT REPORT"
    )

    canvas.drawRightString(
        width - 43,
        27,
        f"Page {document.page}"
    )

    if document.page > 1:

        canvas.setFont(
            "Helvetica-Bold",
            8
        )

        canvas.setFillColor(ESPRESSO)

        canvas.drawString(
            43,
            letter[1] - 34,
            "HOMESOC  /  INCIDENT REPORT"
        )

    canvas.restoreState()


# ==================================================
# MAIN PDF GENERATOR
# ==================================================

def build_incident_pdf(
    incident,
    events,
    mitre_techniques,
    attack_progression=None
):
    """
    Generate a complete HomeSOC incident PDF.

    Accepts:
        incident: sqlite3.Row or dictionary
        events: list of sqlite3.Row or dictionaries
        mitre_techniques: list of MITRE mapping dictionaries
        attack_progression: list of attack stage names

    Returns:
        PDF file content as bytes.

    The PDF is generated in memory.
    No files are written to disk.
    """

    incident = dict(incident)

    events = [
        dict(event)
        for event in events
    ]

    mitre_techniques = [
        dict(item)
        for item in mitre_techniques
    ]

    attack_progression = list(
        attack_progression or []
    )

    incident_id = int(
        _field(
            incident,
            "id",
            0
        )
    )

    generated = datetime.now(
        timezone.utc
    ).strftime(
        "%Y-%m-%d %H:%M UTC"
    )

    severity = str(
        _field(
            incident,
            "severity",
            "UNKNOWN"
        )
    ).upper()

    styles = _styles()

    buffer = BytesIO()

    document = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=43,
        leftMargin=43,
        topMargin=52,
        bottomMargin=54,
        title=f"HomeSOC Incident {incident_id:04d} Report",
        author="HomeSOC",
    )

    usable_width = letter[0] - 86

    story = []

    # ==============================================
    # REPORT HEADER
    # ==============================================

    header = Table(
        [[
            Paragraph(
                "HOMESOC",
                styles["brand"]
            ),

            Paragraph(
                "SECURITY INCIDENT REPORT",
                styles["subtitle"]
            ),
        ]],

        colWidths=[
            usable_width * 0.47,
            usable_width * 0.53
        ],
    )

    header.setStyle(
        TableStyle([
            (
                "BACKGROUND",
                (0, 0),
                (-1, -1),
                ESPRESSO
            ),

            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "MIDDLE"
            ),

            (
                "LEFTPADDING",
                (0, 0),
                (-1, -1),
                17
            ),

            (
                "RIGHTPADDING",
                (0, 0),
                (-1, -1),
                12
            ),

            (
                "TOPPADDING",
                (0, 0),
                (-1, -1),
                18
            ),

            (
                "BOTTOMPADDING",
                (0, 0),
                (-1, -1),
                18
            ),
        ])
    )

    story.extend([
        header,
        Spacer(1, 12)
    ])

    story.append(
        Paragraph(
            f"Incident <b>#{incident_id:04d}</b>"
            f"  |  Generated {_safe(generated)}",
            styles["small"]
        )
    )

    story.append(
        Paragraph(
            "Investigation summary generated from "
            "stored HomeSOC lab telemetry.",
            styles["body"]
        )
    )

    # ==============================================
    # INCIDENT OVERVIEW
    # ==============================================

    story.append(
        Paragraph(
            "01  /  INCIDENT OVERVIEW",
            styles["section"]
        )
    )

    confidence_level = _field(
        incident,
        "confidence_level",
        "UNKNOWN"
    )

    confidence_score = _field(
        incident,
        "confidence_score",
        0
    )

    overview = [

        (
            "AFFECTED ASSET",
            _field(incident, "asset_ip"),
            "SEVERITY",
            severity
        ),

        (
            "RISK SCORE",
            _field(incident, "total_score", 0),
            "CONFIDENCE (HEURISTIC)",
            f"{confidence_score}/100 - {confidence_level}"
        ),

        (
            "FIRST EVENT",
            _field(incident, "start_time"),
            "LAST EVENT",
            _field(incident, "end_time")
        ),

        (
            "ANALYST STATUS",
            _field(incident, "status", "NEW"),
            "EVENTS / SIGNALS",
            (
                f"{_field(incident, 'event_count', 0)}"
                f" / "
                f"{_field(incident, 'signal_count', 0)}"
            )
        ),

        (
            "DATA SOURCES",
            _field(incident, "sources"),
            "SUPPRESSED DUPLICATES",
            _field(
                incident,
                "suppressed_duplicates",
                0
            )
        ),
    ]

    cells = []

    for (
        left_label,
        left_value,
        right_label,
        right_value
    ) in overview:

        right_style = styles["cell"]

        if (
            right_label == "SEVERITY"
            and severity == "CRITICAL"
        ):
            right_style = styles["severity"]

        cells.append([

            Paragraph(
                _safe(left_label),
                styles["cell_label"]
            ),

            Paragraph(
                _safe(left_value),
                styles["cell"]
            ),

            Paragraph(
                _safe(right_label),
                styles["cell_label"]
            ),

            Paragraph(
                _safe(right_value),
                right_style
            ),
        ])

    table = Table(
        cells,

        colWidths=[
            usable_width * 0.19,
            usable_width * 0.31,
            usable_width * 0.20,
            usable_width * 0.30
        ],

        hAlign="LEFT",
    )

    table.setStyle(
        TableStyle([

            (
                "BACKGROUND",
                (0, 0),
                (-1, -1),
                CREAM
            ),

            (
                "ROWBACKGROUNDS",
                (0, 0),
                (-1, -1),
                [
                    CREAM,
                    colors.white
                ]
            ),

            (
                "LINEBELOW",
                (0, 0),
                (-1, -1),
                0.4,
                PALE
            ),

            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "TOP"
            ),

            (
                "LEFTPADDING",
                (0, 0),
                (-1, -1),
                8
            ),

            (
                "RIGHTPADDING",
                (0, 0),
                (-1, -1),
                7
            ),

            (
                "TOPPADDING",
                (0, 0),
                (-1, -1),
                9
            ),

            (
                "BOTTOMPADDING",
                (0, 0),
                (-1, -1),
                9
            ),
        ])
    )

    story.append(table)

    story.append(
        Spacer(1, 8)
    )

    story.append(
        Paragraph(
            "Confidence is a rule-based correlation score, "
            "not a statistical probability that an attack occurred.",
            styles["warning"]
        )
    )

    # ==============================================
    # ATTACK PROGRESSION
    # ==============================================

    story.append(
        Paragraph(
            "02  /  ATTACK PROGRESSION",
            styles["section"]
        )
    )

    if attack_progression:

        story.append(
            Paragraph(
                _safe(
                    "  ->  ".join(
                        attack_progression
                    )
                ),
                styles["body"]
            )
        )

    else:

        story.append(
            Paragraph(
                "No attack stages were available "
                "for this incident.",
                styles["body"]
            )
        )

    # ==============================================
    # MITRE ATT&CK MAPPINGS
    # ==============================================

    story.append(
        Paragraph(
            "03  /  MITRE ATT&amp;CK CONTEXT",
            styles["section"]
        )
    )

    story.append(
        Paragraph(
            "Mappings are based on normalized event labels. "
            "Broad event types remain unmapped unless "
            "supporting evidence justifies a specific technique.",
            styles["small"]
        )
    )

    if mitre_techniques:

        mitre_rows = [[

            Paragraph(
                "EVENT TYPE",
                styles["table_head"]
            ),

            Paragraph(
                "TECHNIQUE",
                styles["table_head"]
            ),

            Paragraph(
                "TACTIC",
                styles["table_head"]
            ),

            Paragraph(
                "INTERPRETATION",
                styles["table_head"]
            ),
        ]]

        for mapping in mitre_techniques:

            mitre_rows.append([

                Paragraph(
                    _safe(
                        _field(
                            mapping,
                            "event_type"
                        )
                    ),
                    styles["cell"]
                ),

                Paragraph(
                    _safe(
                        _field(
                            mapping,
                            "technique_id",
                            "UNMAPPED"
                        )
                    ),
                    styles["cell"]
                ),

                Paragraph(
                    _safe(
                        _field(
                            mapping,
                            "tactic"
                        )
                    ),
                    styles["cell"]
                ),

                Paragraph(
                    _safe(
                        _field(
                            mapping,
                            "technique_name"
                        )
                    ),
                    styles["cell"]
                ),
            ])

        mitre_table = Table(
            mitre_rows,

            colWidths=[
                usable_width * 0.23,
                usable_width * 0.17,
                usable_width * 0.25,
                usable_width * 0.35
            ],

            repeatRows=1,
            hAlign="LEFT",
        )

        mitre_table.setStyle(
            TableStyle([

                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    ESPRESSO
                ),

                (
                    "ROWBACKGROUNDS",
                    (0, 1),
                    (-1, -1),
                    [
                        CREAM,
                        colors.white
                    ]
                ),

                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP"
                ),

                (
                    "LINEBELOW",
                    (0, 1),
                    (-1, -1),
                    0.35,
                    PALE
                ),

                (
                    "LEFTPADDING",
                    (0, 0),
                    (-1, -1),
                    8
                ),

                (
                    "RIGHTPADDING",
                    (0, 0),
                    (-1, -1),
                    7
                ),

                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    8
                ),

                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    8
                ),
            ])
        )

        story.append(
            mitre_table
        )

    else:

        story.append(
            Paragraph(
                "No MITRE mappings available.",
                styles["body"]
            )
        )

    # ==============================================
    # EVENT EVIDENCE
    # ==============================================

    story.append(
        Paragraph(
            "04  /  EVENT EVIDENCE",
            styles["section"]
        )
    )

    if not events:

        story.append(
            Paragraph(
                "No event evidence was stored.",
                styles["body"]
            )
        )

    for number, event in enumerate(
        events,
        start=1
    ):

        event_block = [

            Paragraph(
                (
                    f"EVENT {number:02d}  |  "
                    f"{_safe(_field(event, 'event_type'))}"
                ),
                styles["event"]
            ),

            Paragraph(
                (
                    f"<b>Timestamp:</b> "
                    f"{_safe(_field(event, 'timestamp'))}"
                    f"  |  <b>Source:</b> "
                    f"{_safe(_field(event, 'source'))}"
                    f"  |  <b>Severity:</b> "
                    f"{_safe(_field(event, 'severity'))}"
                    f"  |  <b>Risk:</b> "
                    f"{_safe(_field(event, 'risk_score', 0))}"
                ),
                styles["small"]
            ),

            Paragraph(
                (
                    f"<b>Network:</b> "
                    f"{_safe(_field(event, 'src_ip'))}"
                    f"  ->  "
                    f"{_safe(_field(event, 'dst_ip'))}"
                    f"  |  <b>Asset:</b> "
                    f"{_safe(_field(event, 'asset_ip'))}"
                ),
                styles["small"]
            ),

            Paragraph(
                (
                    f"<b>Evidence:</b> "
                    f"{_safe(_field(event, 'description'))}"
                ),
                styles["body"]
            ),

            HRFlowable(
                width="100%",
                thickness=0.4,
                color=PALE,
                spaceBefore=4,
                spaceAfter=4,
            ),
        ]

        story.append(
            KeepTogether(event_block)
        )

    # ==============================================
    # REPORT DISCLAIMER
    # ==============================================

    story.append(
        Spacer(1, 12)
    )

    story.append(
        Paragraph(
            "REPORT SCOPE  /  This report summarizes records "
            "in the HomeSOC demonstration database. "
            "It does not verify real-time home protection "
            "or independently confirm an intrusion.",
            styles["warning"]
        )
    )

    # ==============================================
    # GENERATE PDF
    # ==============================================

    document.build(
        story,
        onFirstPage=_footer,
        onLaterPages=_footer
    )

    return buffer.getvalue()
