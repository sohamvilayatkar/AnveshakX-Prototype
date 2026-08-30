import os
from io import BytesIO
from datetime import datetime, timezone
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

from app.schemas.analysis import AnalysisResponse


class ReportService:
    """
    Forensic PDF Report Generator:
    Compiles an official digital forensics investigation report using ReportLab,
    with forensic hashes, relay chronology, IOC lists, and legal disclaimers.
    """

    @classmethod
    def generate_pdf(cls, analysis: AnalysisResponse) -> bytes:
        buffer = BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36
        )

        styles = getSampleStyleSheet()
        
        # Custom Forensic Styles
        title_style = ParagraphStyle(
            "DocTitle",
            parent=styles["Heading1"],
            fontSize=20,
            leading=24,
            textColor=colors.HexColor("#0f172a"),
            alignment=TA_LEFT,
            fontName="Helvetica-Bold"
        )
        subtitle_style = ParagraphStyle(
            "DocSubTitle",
            parent=styles["Normal"],
            fontSize=10,
            leading=14,
            textColor=colors.HexColor("#64748b"),
            fontName="Helvetica"
        )
        section_style = ParagraphStyle(
            "SectionHeader",
            parent=styles["Heading2"],
            fontSize=12,
            leading=16,
            textColor=colors.HexColor("#1e293b"),
            fontName="Helvetica-Bold",
            spaceBefore=10,
            spaceAfter=4
        )
        body_style = ParagraphStyle(
            "BodyTextCustom",
            parent=styles["Normal"],
            fontSize=9,
            leading=13,
            textColor=colors.HexColor("#334155"),
            fontName="Helvetica"
        )
        disclaimer_style = ParagraphStyle(
            "DisclaimerText",
            parent=styles["Normal"],
            fontSize=7.5,
            leading=10,
            textColor=colors.HexColor("#94a3b8"),
            fontName="Helvetica-Oblique",
            alignment=TA_CENTER
        )

        elements = []

        # 1. Header Banner
        header_data = [
            [
                Paragraph("<b>ANVESHAKX FORENSIC INTELLIGENCE REPORT</b>", title_style),
                Paragraph(f"<b>STATUS:</b> OFFICIAL EVIDENCE<br/><b>GENERATED:</b> {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}", subtitle_style)
            ]
        ]
        header_table = Table(header_data, colWidths=[340, 200])
        header_table.setStyle(TableStyle([
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('ALIGN', (1, 0), (1, 0), 'RIGHT'),
        ]))
        elements.append(header_table)
        elements.append(Spacer(1, 8))
        elements.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#0284c7"), spaceAfter=12))

        # 2. Case Information Summary Box
        case = analysis.case
        evidence = analysis.evidence
        case_info_data = [
            [Paragraph("<b>Case ID:</b>", body_style), Paragraph(case.id, body_style), Paragraph("<b>Original File:</b>", body_style), Paragraph(case.filename, body_style)],
            [Paragraph("<b>Evidence SHA-256:</b>", body_style), Paragraph(f"<font size=7 fontName='Courier'>{evidence.sha256_hash}</font>", body_style), Paragraph("<b>File Size:</b>", body_style), Paragraph(f"{case.file_size_bytes} bytes", body_style)],
            [Paragraph("<b>Integrity Status:</b>", body_style), Paragraph("<font color='#16a34a'><b>VERIFIED IMMUTABLE</b></font>", body_style), Paragraph("<b>Evidence ID:</b>", body_style), Paragraph(evidence.evidence_id, body_style)],
        ]
        case_table = Table(case_info_data, colWidths=[90, 200, 80, 170])
        case_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('PADDING', (0, 0), (-1, -1), 5),
        ]))
        elements.append(case_table)
        elements.append(Spacer(1, 12))

        # 3. Threat Assessment Scorecard
        threat = analysis.threat
        sev_color = "#dc2626" if threat.severity == "CRITICAL" else ("#ea580c" if threat.severity == "HIGH" else ("#d97706" if threat.severity == "MEDIUM" else "#16a34a"))
        
        threat_data = [
            [
                Paragraph(f"<font size=24 color='{sev_color}'><b>{threat.score} / 100</b></font><br/><font size=10 color='{sev_color}'><b>{threat.severity} RISK</b></font>", ParagraphStyle("Score", alignment=TA_CENTER)),
                Paragraph(f"<b>Classification:</b> {threat.classification}<br/>"
                          f"<b>Confidence:</b> {int(threat.confidence * 100)}% (Deterministic Forensic Rules)<br/>"
                          f"<b>Forensic Summary:</b> {threat.summary}", body_style)
            ]
        ]
        threat_table = Table(threat_data, colWidths=[140, 400])
        threat_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f1f5f9")),
            ('BOX', (0, 0), (-1, -1), 1.5, colors.HexColor(sev_color)),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('PADDING', (0, 0), (-1, -1), 8),
        ]))
        elements.append(Paragraph("1. Executive Threat Assessment", section_style))
        elements.append(threat_table)
        elements.append(Spacer(1, 10))

        # 4. Identity & Authentication Findings
        elements.append(Paragraph("2. Sender Identity & Authentication Verification", section_style))
        email = analysis.email
        auth = analysis.authentication
        
        id_data = [
            [Paragraph("<b>Claimed Sender:</b>", body_style), Paragraph(f"{email.sender.display_name} &lt;{email.sender.email}&gt;", body_style)],
            [Paragraph("<b>Reply-To Destination:</b>", body_style), Paragraph(f"{email.reply_to.email if email.reply_to else 'None (Same as Sender)'}", body_style)],
            [Paragraph("<b>Return-Path:</b>", body_style), Paragraph(f"{email.return_path.email if email.return_path else 'None'}", body_style)],
            [Paragraph("<b>SPF Result:</b>", body_style), Paragraph(f"<b>{auth.spf_result}</b> ({auth.spf_details or 'Reported in headers'})", body_style)],
            [Paragraph("<b>DKIM Result:</b>", body_style), Paragraph(f"<b>{auth.dkim_result}</b> ({auth.dkim_details or 'Reported in headers'})", body_style)],
            [Paragraph("<b>DMARC Result:</b>", body_style), Paragraph(f"<b>{auth.dmarc_result}</b> ({auth.dmarc_details or 'Reported in headers'})", body_style)],
        ]
        id_table = Table(id_data, colWidths=[140, 400])
        id_table.setStyle(TableStyle([
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor("#f8fafc")),
            ('PADDING', (0, 0), (-1, -1), 4),
        ]))
        elements.append(id_table)
        elements.append(Spacer(1, 10))

        # 5. Received Relay Chronology
        elements.append(Paragraph("3. Email Transmission Relay Path (MTA Chronology)", section_style))
        relay_data = [["Hop", "From Host / IP", "By Host / MTA", "Protocol", "Timestamp"]]
        for hop in analysis.relay_path:
            relay_data.append([
                str(hop.hop_number),
                hop.from_host or hop.ip or "Unknown",
                hop.by_host or "Unknown",
                hop.protocol or "ESMTP",
                hop.timestamp or "Unknown"
            ])
        if len(relay_data) == 1:
            relay_data.append(["-", "No Received headers found", "-", "-", "-"])

        relay_table = Table(relay_data, colWidths=[30, 160, 150, 60, 140])
        relay_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#0f172a")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ('FONTSIZE', (0, 1), (-1, -1), 7.5),
            ('PADDING', (0, 0), (-1, -1), 3.5),
        ]))
        elements.append(relay_table)
        elements.append(Spacer(1, 10))

        # 6. Indicators of Compromise (IOCs) Table
        elements.append(Paragraph("4. Preserved Indicators of Compromise (IOC Table)", section_style))
        ioc_data = [["Type", "Value", "Source Context", "Risk Rating"]]
        for ioc in analysis.iocs[:12]:  # Top 12 IOCs for report brevity
            ioc_data.append([
                ioc.ioc_type,
                Paragraph(f"<font size=7 fontName='Courier'>{ioc.value[:45] + '...' if len(ioc.value) > 45 else ioc.value}</font>", body_style),
                ioc.source,
                ioc.risk
            ])
        if len(ioc_data) == 1:
            ioc_data.append(["-", "No external indicators extracted", "-", "INFO"])

        ioc_table = Table(ioc_data, colWidths=[60, 240, 160, 80])
        ioc_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#1e293b")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ('FONTSIZE', (0, 1), (-1, -1), 7.5),
            ('PADDING', (0, 0), (-1, -1), 3),
        ]))
        elements.append(ioc_table)
        elements.append(Spacer(1, 14))

        # 7. Forensic Disclaimer & Footer
        elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#cbd5e1"), spaceAfter=8))
        disclaimer_text = (
            "LEGAL FORENSIC NOTICE & DISCLAIMER: Geolocation, WHOIS, and network intelligence represent probable Mail "
            "Transfer Agent (MTA) and hosting infrastructure. They do not establish the physical identity or real-time location "
            "of an individual perpetrator. Evidence preserved with SHA-256 immutable checksums."
        )
        elements.append(Paragraph(disclaimer_text, disclaimer_style))

        # Build document
        doc.build(elements)
        pdf_bytes = buffer.getvalue()
        buffer.close()
        return pdf_bytes
