import io
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from src.assets.domain.entities import AssetEntity
from src.vulnerabilities.domain.entities import VulnerabilityEntity
from typing import List

def generate_vulnerability_pdf(
    asset: AssetEntity, 
    vulnerabilities: List[VulnerabilityEntity], 
    executive_summary: str,
    scanner_company_name: str = "Kerubiscan Security",
    target_company_name: str = "Client Company"
) -> bytes:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )

    styles = getSampleStyleSheet()
    # Custom styles
    title_style = ParagraphStyle(
        'TitleStyle', 
        parent=styles['Heading1'], 
        fontSize=24, 
        alignment=1, # Center
        spaceAfter=20,
        textColor=colors.HexColor("#1e3a8a")
    )
    heading_style = ParagraphStyle(
        'HeadingStyle', 
        parent=styles['Heading2'], 
        fontSize=14, 
        spaceBefore=15, 
        spaceAfter=10,
        textColor=colors.HexColor("#1e40af")
    )
    normal_style = styles['Normal']
    normal_style.fontSize = 10
    normal_style.leading = 14

    story = []

    # 1. Title Page / Header
    header_data = [
        [Paragraph(f"<b>Scanner:</b><br/>{scanner_company_name}", normal_style),
         Paragraph(f"<b>Target:</b><br/>{target_company_name}", normal_style)]
    ]
    header_table = Table(header_data, colWidths=[260, 260])
    header_table.setStyle(TableStyle([
        ('ALIGN', (0, 0), (0, 0), 'LEFT'),
        ('ALIGN', (1, 0), (1, 0), 'RIGHT'),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 20),
    ]))
    story.append(header_table)
    story.append(Spacer(1, 40))

    story.append(Paragraph("Vulnerability Assessment Report", title_style))
    story.append(Paragraph(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ParagraphStyle('Date', parent=normal_style, alignment=1)))
    story.append(Spacer(1, 40))

    # 2. Target Context
    story.append(Paragraph("Target Asset Details", heading_style))
    
    context_data = [
        ["Property", "Value"],
        ["Hostname", asset.name or "N/A"],
        ["IP Address", asset.ip_address or "N/A"],
        ["MAC Address", getattr(asset, "mac_address", "N/A") or "N/A"],
        ["Operating System", asset.operating_system or "N/A"],
        ["Network Zone", asset.network_zone or "N/A"],
        ["Open Ports", asset.ports or "None detected"]
    ]
    
    t_context = Table(context_data, colWidths=[150, 370])
    t_context.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (1, 0), colors.HexColor("#1e3a8a")),
        ('TEXTCOLOR', (0, 0), (1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor("#f8fafc")),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1"))
    ]))
    story.append(t_context)
    story.append(Spacer(1, 20))

    # 3. Executive Summary
    story.append(Paragraph("Executive Summary", heading_style))
    if executive_summary:
        story.append(Paragraph(executive_summary.replace('\n', '<br/>'), normal_style))
    else:
        story.append(Paragraph("No executive summary provided for this report.", normal_style))
    story.append(Spacer(1, 20))
    
    # Severity breakdown
    crit_count = sum(1 for v in vulnerabilities if getattr(v.severity, "value", str(v.severity)) == "Critical")
    high_count = sum(1 for v in vulnerabilities if getattr(v.severity, "value", str(v.severity)) == "High")
    med_count = sum(1 for v in vulnerabilities if getattr(v.severity, "value", str(v.severity)) == "Medium")
    low_count = sum(1 for v in vulnerabilities if getattr(v.severity, "value", str(v.severity)) in ["Low", "Info"])
    
    breakdown_data = [
        ["Severity", "Count"],
        ["Critical", crit_count],
        ["High", high_count],
        ["Medium", med_count],
        ["Low / Info", low_count],
        ["Total", len(vulnerabilities)]
    ]
    t_breakdown = Table(breakdown_data, colWidths=[150, 100])
    t_breakdown.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (1, 0), colors.HexColor("#334155")),
        ('TEXTCOLOR', (0, 0), (1, 0), colors.whitesmoke),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ('BACKGROUND', (0, 1), (1, 1), colors.HexColor("#fee2e2")), 
        ('BACKGROUND', (0, 2), (1, 2), colors.HexColor("#ffedd5")), 
        ('BACKGROUND', (0, 3), (1, 3), colors.HexColor("#fef9c3")), 
        ('BACKGROUND', (0, 4), (1, 4), colors.HexColor("#f1f5f9")), 
        ('FONTNAME', (0, 5), (1, 5), 'Helvetica-Bold'), 
    ]))
    story.append(t_breakdown)

    story.append(PageBreak())

    # 4. Vulnerability Summary Table
    story.append(Paragraph("Vulnerabilities Discovered", heading_style))
    
    if vulnerabilities:
        vuln_summary_data = [["Title", "Severity", "CVSS"]]
        
        for v in sorted(vulnerabilities, key=lambda x: x.cvss_base_score or 0, reverse=True):
            sev_str = getattr(v.severity, "value", str(v.severity))
            vuln_summary_data.append([
                Paragraph(v.title, normal_style), 
                sev_str, 
                str(v.cvss_base_score or "N/A")
            ])
            
        t_vulns = Table(vuln_summary_data, colWidths=[380, 80, 60], repeatRows=1)
        t_vulns.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#1e3a8a")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(t_vulns)
        story.append(PageBreak())
        
        # 5. Detailed Findings
        story.append(Paragraph("Detailed Findings", heading_style))
        
        for idx, v in enumerate(sorted(vulnerabilities, key=lambda x: x.cvss_base_score or 0, reverse=True)):
            story.append(Paragraph(f"{idx+1}. {v.title}", ParagraphStyle('VulnTitle', parent=styles['Heading3'], textColor=colors.HexColor("#0f172a"))))
            
            sev_str = getattr(v.severity, "value", str(v.severity))
            details_data = [
                ["Severity:", sev_str, "CVSS Score:", str(v.cvss_base_score or "N/A")],
                ["CVE ID:", v.cve_id or "N/A", "Status:", getattr(v.status, "value", str(v.status))],
                ["First Detected:", v.first_detected_at.strftime('%Y-%m-%d %H:%M') if v.first_detected_at else "N/A", "Scanner Engine:", v.source_engine]
            ]
            t_details = Table(details_data, colWidths=[90, 170, 90, 170])
            t_details.setStyle(TableStyle([
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTNAME', (2, 0), (2, -1), 'Helvetica-Bold'),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ]))
            story.append(t_details)
            story.append(Spacer(1, 10))
            
            story.append(Paragraph("<b>Description:</b>", normal_style))
            desc_text = v.description or "No description provided."
            story.append(Paragraph(desc_text.replace('\n', '<br/>'), normal_style))
            story.append(Spacer(1, 8))
            
            story.append(Paragraph("<b>Remediation:</b>", normal_style))
            rem_text = v.remediation or "No remediation provided."
            story.append(Paragraph(rem_text.replace('\n', '<br/>'), normal_style))
            
            story.append(Spacer(1, 20))
            
    else:
        story.append(Paragraph("No vulnerabilities were discovered on this asset.", normal_style))

    doc.build(story)
    return buffer.getvalue()
