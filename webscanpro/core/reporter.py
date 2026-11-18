import os
from datetime import datetime
from pathlib import Path
from flask import render_template
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether, HRFlowable
)
from webscanpro import db
from webscanpro.models.finding import Finding
from config import Config

def xml_escape(text: str) -> str:
    if not text:
        return ""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )

class SecurityReportGenerator:
    """
    Generates professional, publication-quality executive PDF reports
    and standalone HTML security assessment reports.
    """

    @classmethod
    def get_report_paths(cls, scan_id: int):
        reports_dir = Path(Config.REPORTS_DIR)
        reports_dir.mkdir(parents=True, exist_ok=True)
        pdf_path = reports_dir / f"WebScanPro_Report_Scan_{scan_id}.pdf"
        html_path = reports_dir / f"WebScanPro_Report_Scan_{scan_id}.html"
        return pdf_path, html_path

    @classmethod
    def generate_pdf_report(cls, scan) -> str:
        pdf_path, _ = cls.get_report_paths(scan.id)
        doc = SimpleDocTemplate(
            str(pdf_path),
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36
        )

        styles = getSampleStyleSheet()

        # Custom Cyber-Themed Styles
        title_style = ParagraphStyle(
            "ReportTitle",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=22,
            textColor=colors.HexColor("#0f172a"),
            spaceAfter=6,
        )
        subtitle_style = ParagraphStyle(
            "ReportSubtitle",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=11,
            textColor=colors.HexColor("#0284c7"),
            spaceAfter=15,
        )
        heading1_style = ParagraphStyle(
            "SectionHeading1",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=14,
            textColor=colors.HexColor("#0f172a"),
            spaceBefore=14,
            spaceAfter=8,
        )
        heading2_style = ParagraphStyle(
            "SectionHeading2",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=11,
            textColor=colors.HexColor("#1e293b"),
            spaceBefore=8,
            spaceAfter=4,
        )
        body_style = ParagraphStyle(
            "ReportBody",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=9,
            leading=13,
            textColor=colors.HexColor("#334155"),
            spaceAfter=6,
        )
        code_style = ParagraphStyle(
            "ReportCode",
            parent=styles["Normal"],
            fontName="Courier",
            fontSize=7.5,
            leading=10,
            textColor=colors.HexColor("#0f172a"),
        )

        story = []

        # 1. Header Banner
        story.append(Paragraph("WebScanPro — Security Assessment Report", title_style))
        story.append(Paragraph("Dynamic Application Security Testing (DAST) Executive & Technical Findings", subtitle_style))
        story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0284c7"), spaceAfter=12))

        # 2. Executive Scan Metadata Table
        target_url = scan.target.base_url if scan.target else "N/A"
        date_str = scan.started_at.strftime("%Y-%m-%d %H:%M:%S UTC") if scan.started_at else datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        duration_str = f"{round(scan.duration_seconds, 2)} seconds" if scan.duration_seconds else "N/A"

        meta_data = [
            [Paragraph("<b>Target Base URL:</b>", body_style), Paragraph(target_url, body_style),
             Paragraph("<b>Scan ID:</b>", body_style), Paragraph(f"#{scan.id}", body_style)],
            [Paragraph("<b>Assessment Date:</b>", body_style), Paragraph(date_str, body_style),
             Paragraph("<b>Scan Mode:</b>", body_style), Paragraph(scan.scan_mode, body_style)],
            [Paragraph("<b>Endpoints Crawled:</b>", body_style), Paragraph(str(scan.endpoints_discovered), body_style),
             Paragraph("<b>Total Requests:</b>", body_style), Paragraph(str(scan.total_requests_sent), body_style)],
            [Paragraph("<b>Assessment Status:</b>", body_style), Paragraph(f"<font color='{ '#16a34a' if scan.status == 'COMPLETED' else '#dc2626' }'><b>{scan.status}</b></font>", body_style),
             Paragraph("<b>Duration:</b>", body_style), Paragraph(duration_str, body_style)],
        ]
        meta_table = Table(meta_data, colWidths=[100, 170, 90, 180])
        meta_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(meta_table)
        story.append(Spacer(1, 12))

        # 3. Findings Severity Summary Table
        story.append(Paragraph("Executive Severity Breakdown", heading1_style))
        summary_data = [
            ["Critical", "High", "Medium", "Low", "Informational", "Total Findings"],
            [
                str(scan.count_critical or 0),
                str(scan.count_high or 0),
                str(scan.count_medium or 0),
                str(scan.count_low or 0),
                str(scan.count_info or 0),
                str(scan.total_findings or 0),
            ]
        ]
        summary_table = Table(summary_data, colWidths=[90, 90, 90, 90, 90, 90])
        summary_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, 0), colors.HexColor("#dc2626")),
            ("BACKGROUND", (1, 0), (1, 0), colors.HexColor("#ea580c")),
            ("BACKGROUND", (2, 0), (2, 0), colors.HexColor("#d97706")),
            ("BACKGROUND", (3, 0), (3, 0), colors.HexColor("#2563eb")),
            ("BACKGROUND", (4, 0), (4, 0), colors.HexColor("#64748b")),
            ("BACKGROUND", (5, 0), (5, 0), colors.HexColor("#0f172a")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTNAME", (0, 1), (-1, 1), "Helvetica-Bold"),
            ("FONTSIZE", (0, 1), (-1, 1), 12),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 14))

        # 4. Detailed Technical Findings
        story.append(Paragraph("Detailed Security Findings", heading1_style))
        findings_list = scan.findings.order_by(
            db.case(
                {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4, "INFO": 5},
                value=Finding.severity,
                else_=6
            ).asc(),
            Finding.id.asc()
        ).all()

        if not findings_list:
            story.append(Paragraph("<i>No security weaknesses or vulnerabilities were detected during this scan session.</i>", body_style))
        else:
            for idx, f in enumerate(findings_list, start=1):
                # Severity badge color
                color_map = {
                    "CRITICAL": "#dc2626",
                    "HIGH": "#ea580c",
                    "MEDIUM": "#d97706",
                    "LOW": "#2563eb",
                    "INFO": "#64748b",
                }
                sev_color = color_map.get(f.severity, "#64748b")

                finding_elements = []
                finding_elements.append(Paragraph(
                    f"<b>#{idx}. {f.vuln_type}</b> — <font color='{sev_color}'><b>[{f.severity}]</b></font> ({f.status})",
                    heading2_style
                ))

                detail_data = [
                    [Paragraph("<b>Endpoint / Path:</b>", body_style), Paragraph(xml_escape(f.endpoint), body_style)],
                    [Paragraph("<b>Parameter:</b>", body_style), Paragraph(xml_escape(f.parameter), body_style)],
                    [Paragraph("<b>HTTP Method:</b>", body_style), Paragraph(xml_escape(f.http_method), body_style)],
                    [Paragraph("<b>OWASP Category:</b>", body_style), Paragraph(xml_escape(f.category), body_style)],
                    [Paragraph("<b>CWE ID:</b>", body_style), Paragraph(xml_escape(f.cwe_id), body_style)],
                    [Paragraph("<b>Confidence:</b>", body_style), Paragraph(xml_escape(f.confidence), body_style)],
                ]
                detail_table = Table(detail_data, colWidths=[120, 420])
                detail_table.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
                    ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                    ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#f1f5f9")),
                    ("TOPPADDING", (0, 0), (-1, -1), 3),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ]))
                finding_elements.append(detail_table)
                finding_elements.append(Spacer(1, 4))

                # Technical Explanation
                finding_elements.append(Paragraph("<b>Technical Analysis:</b>", body_style))
                finding_elements.append(Paragraph(xml_escape(f.explanation).replace("\n", "<br/>"), body_style))

                # Evidence Block
                if f.evidence:
                    finding_elements.append(Paragraph("<b>Recorded Evidence:</b>", body_style))
                    evidence_table = Table([[Paragraph(xml_escape(f.evidence).replace("\n", "<br/>"), code_style)]], colWidths=[540])
                    evidence_table.setStyle(TableStyle([
                        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#0f172a")),
                        ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#e2e8f0")),
                        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#334155")),
                        ("TOPPADDING", (0, 0), (-1, -1), 6),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                        ("LEFTPADDING", (0, 0), (-1, -1), 8),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                    ]))
                    finding_elements.append(evidence_table)
                    finding_elements.append(Spacer(1, 4))

                # Remediation
                finding_elements.append(Paragraph("<b>Remediation Guidance:</b>", body_style))
                finding_elements.append(Paragraph(xml_escape(f.remediation).replace("\n", "<br/>"), body_style))

                if f.manual_verification_steps:
                    finding_elements.append(Paragraph("<b>Manual Verification Steps:</b>", body_style))
                    finding_elements.append(Paragraph(xml_escape(f.manual_verification_steps).replace("\n", "<br/>"), body_style))

                finding_elements.append(Spacer(1, 10))
                finding_elements.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#cbd5e1"), spaceAfter=10))

                story.append(KeepTogether(finding_elements))

        # 5. Methodological Scope & Limitations Disclaimer
        story.append(Spacer(1, 10))
        story.append(Paragraph("Assessment Limitations & Legal Disclaimer", heading1_style))
        disclaimer_text = (
            "WebScanPro operates exclusively on authorized local target applications and labs. "
            "Automated vulnerability assessment tools provide dynamic heuristic observations, which must be "
            "manually verified by a qualified application security engineer before implementing architecture changes. "
            "This report constitutes point-in-time security testing evidence and does not guarantee that other undetected "
            "vulnerabilities are absent."
        )
        story.append(Paragraph(disclaimer_text, body_style))

        # Build document
        doc.build(story)
        return str(pdf_path)
