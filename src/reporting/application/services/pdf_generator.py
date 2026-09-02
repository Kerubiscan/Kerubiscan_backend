import io
import html
import json
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
        rightMargin=40, leftMargin=40,
        topMargin=40, bottomMargin=40
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'TitleStyle', parent=styles['Heading1'], fontSize=28, alignment=1, spaceAfter=30, textColor=colors.HexColor("#1e3a8a")
    )
    heading_style = ParagraphStyle(
        'HeadingStyle', parent=styles['Heading2'], fontSize=16, spaceBefore=20, spaceAfter=10, textColor=colors.HexColor("#1e40af"),
        borderPadding=5, backColor=colors.HexColor("#f1f5f9")
    )
    subheading_style = ParagraphStyle(
        'SubHeadingStyle', parent=styles['Heading3'], fontSize=12, spaceBefore=15, spaceAfter=8, textColor=colors.HexColor("#0f172a")
    )
    normal_style = styles['Normal']
    normal_style.fontSize = 10
    normal_style.leading = 14

    story = []

    # ---------------------------------------------------------
    # 1. PAGE DE GARDE (COVER PAGE)
    # ---------------------------------------------------------
    story.append(Spacer(1, 100))
    story.append(Paragraph("RAPPORT D'AUDIT DE VULNÉRABILITÉS", title_style))
    story.append(Spacer(1, 40))

    cover_data = [
        ["Cible / Scope :", f"{asset.name} ({asset.ip_address})"],
        ["Client :", target_company_name],
        ["Auditeur :", scanner_company_name],
        ["Date de génération :", datetime.now().strftime('%Y-%m-%d %H:%M:%S')],
        ["Moteur(s) de scan :", "Multi-engine (Nmap, Nuclei, OpenVAS)"],
        ["Classification :", "CONFIDENTIEL - USAGE INTERNE"]
    ]
    t_cover = Table(cover_data, colWidths=[150, 300])
    t_cover.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
        ('TEXTCOLOR', (0, -1), (-1, -1), colors.HexColor("#dc2626")), # Classification in red
    ]))
    story.append(t_cover)
    story.append(PageBreak())

    # ---------------------------------------------------------
    # 2. RÉSUMÉ EXÉCUTIF (EXECUTIVE SUMMARY)
    # ---------------------------------------------------------
    story.append(Paragraph("1. Résumé Exécutif & Plan Stratégique (IA)", heading_style))
    if executive_summary:
        story.append(Paragraph(html.escape(executive_summary).replace('\n', '<br/>'), normal_style))
    else:
        story.append(Paragraph("Aucun résumé exécutif généré par l'IA n'a été fourni.", normal_style))
    story.append(Spacer(1, 20))

    # ---------------------------------------------------------
    # 3. STATISTIQUES ET VUE D'ENSEMBLE
    # ---------------------------------------------------------
    story.append(Paragraph("2. Statistiques et Vue d'Ensemble", heading_style))
    
    crit_count = sum(1 for v in vulnerabilities if getattr(v.severity, "value", str(v.severity)) == "Critical")
    high_count = sum(1 for v in vulnerabilities if getattr(v.severity, "value", str(v.severity)) == "High")
    med_count = sum(1 for v in vulnerabilities if getattr(v.severity, "value", str(v.severity)) == "Medium")
    low_count = sum(1 for v in vulnerabilities if getattr(v.severity, "value", str(v.severity)) in ["Low", "Info"])
    
    breakdown_data = [
        ["Sévérité", "Nombre", "Niveau de Risque"],
        ["Critique", crit_count, "Urgence absolue"],
        ["Haute", high_count, "Priorité élevée"],
        ["Moyenne", med_count, "À planifier"],
        ["Basse / Info", low_count, "Informationnel"]
    ]
    t_breakdown = Table(breakdown_data, colWidths=[150, 100, 200])
    t_breakdown.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#1e293b")),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ('BACKGROUND', (0, 1), (-1, 1), colors.HexColor("#fee2e2")), 
        ('BACKGROUND', (0, 2), (-1, 2), colors.HexColor("#ffedd5")), 
        ('BACKGROUND', (0, 3), (-1, 3), colors.HexColor("#fef9c3")), 
        ('BACKGROUND', (0, 4), (-1, 4), colors.HexColor("#f1f5f9")), 
    ]))
    story.append(t_breakdown)
    story.append(Spacer(1, 20))

    story.append(Paragraph("Top 5 Vulnérabilités (Plus Récentes)", subheading_style))
    top_vulns = sorted(vulnerabilities, key=lambda x: x.first_detected_at or datetime.min, reverse=True)[:5]
    if top_vulns:
        tv_data = [["CVE", "Titre", "CVSS"]]
        for v in top_vulns:
            tv_data.append([v.cve_id or "-", Paragraph(html.escape(v.title[:60])+"...", normal_style), str(v.cvss_base_score)])
        t_tv = Table(tv_data, colWidths=[80, 320, 50])
        t_tv.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#475569")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ]))
        story.append(t_tv)
    
    story.append(PageBreak())

    # ---------------------------------------------------------
    # 4. DÉTAIL PAR HOST / ASSET
    # ---------------------------------------------------------
    story.append(Paragraph("3. Détail de l'Asset (Cible)", heading_style))
    
    context_data = [
        ["Propriété", "Valeur"],
        ["Hostname / Nom", asset.name or "N/A"],
        ["Adresse IP", asset.ip_address or "N/A"],
        ["Adresse MAC", getattr(asset, "mac_address", "N/A") or "N/A"],
        ["Système d'exploitation", asset.operating_system or "N/A"],
        ["Zone Réseau", asset.network_zone or "N/A"],
        ["Ports Ouverts Détectés", asset.ports or "Aucun"]
    ]
    t_context = Table(context_data, colWidths=[150, 350])
    t_context.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (1, 0), colors.HexColor("#1e3a8a")),
        ('TEXTCOLOR', (0, 0), (1, 0), colors.whitesmoke),
        ('FONTNAME', (0, 0), (1, 0), 'Helvetica-Bold'),
        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor("#f8fafc")),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(t_context)
    story.append(Spacer(1, 10))
    story.append(Paragraph(f"<b>Total des vulnérabilités actives sur cet asset :</b> {len(vulnerabilities)}", normal_style))
    story.append(PageBreak())

    # ---------------------------------------------------------
    # 5. DÉTAIL PAR VULNÉRABILITÉ
    # ---------------------------------------------------------
    story.append(Paragraph("4. Détail par Vulnérabilité (Findings)", heading_style))
    
    if not vulnerabilities:
        story.append(Paragraph("Aucune vulnérabilité n'a été détectée ou toutes ont été corrigées.", normal_style))
    
    for idx, v in enumerate(sorted(vulnerabilities, key=lambda x: x.first_detected_at or datetime.min, reverse=True)):
        sev_str = getattr(v.severity, "value", str(v.severity))
        story.append(Paragraph(f"{idx+1}. {html.escape(v.title)}", ParagraphStyle('VulnTitle', parent=styles['Heading3'], textColor=colors.HexColor("#0f172a"), backColor=colors.HexColor("#e2e8f0"), borderPadding=4)))
        
        details_data = [
            ["ID / CVE:", v.cve_id or "N/A", "Sévérité:", sev_str],
            ["Score CVSS:", str(v.cvss_base_score or "N/A"), "Statut:", getattr(v.status, "value", str(v.status))],
            ["Moteur:", v.source_engine or "Inconnu", "Date Détection:", v.first_detected_at.strftime('%Y-%m-%d') if v.first_detected_at else "N/A"]
        ]
        t_details = Table(details_data, colWidths=[90, 160, 90, 160])
        t_details.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (2, 0), (2, -1), 'Helvetica-Bold'),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        story.append(t_details)
        story.append(Spacer(1, 10))
        
        story.append(Paragraph("<b>Description Technique:</b>", normal_style))
        desc_text = v.description or "Aucune description fournie."
        story.append(Paragraph(html.escape(desc_text).replace('\n', '<br/>'), normal_style))
        story.append(Spacer(1, 8))
        
        story.append(Paragraph("<b>Impact Potentiel:</b>", normal_style))
        story.append(Paragraph("L'exploitation de cette vulnérabilité pourrait compromettre la confidentialité, l'intégrité ou la disponibilité du système affecté.", normal_style))
        story.append(Spacer(1, 8))

        story.append(Paragraph("<b>Preuve (Output Scanner):</b>", normal_style))
        proof_text = "Détails techniques non disponibles dans les logs bruts."
        if getattr(asset, 'last_scan_raw_output', None):
            proof_text = "Preuve capturée dans l'historique du scanner (voir interface web)."
        story.append(Paragraph(f"<i>{proof_text}</i>", normal_style))
        story.append(Spacer(1, 8))
        
        story.append(Paragraph("<b>Recommandation (Remédiation):</b>", normal_style))
        rem_text = v.remediation or "Aucune recommandation fournie. Appliquer les correctifs de sécurité de l'éditeur."
        story.append(Paragraph(html.escape(rem_text).replace('\n', '<br/>'), normal_style))
        
        story.append(Spacer(1, 20))

    story.append(PageBreak())

    # ---------------------------------------------------------
    # 6. ANNEXES
    # ---------------------------------------------------------
    story.append(Paragraph("5. Annexes", heading_style))
    
    story.append(Paragraph("Méthodologie du Scan", subheading_style))
    story.append(Paragraph("Ce rapport a été généré via la plateforme Kerubiscan en utilisant une combinaison de scanners (ex: Nmap, Nuclei, OpenVAS) orchestrés de manière séquentielle. Les vulnérabilités sont dé-doublonnées et unifiés selon leur CVE.", normal_style))
    story.append(Spacer(1, 10))

    story.append(Paragraph("Glossaire", subheading_style))
    glossary = [
        ["CVSS", "Common Vulnerability Scoring System (Score de sévérité standard)"],
        ["CVE", "Common Vulnerabilities and Exposures (Identifiant public de vulnérabilité)"],
        ["Faux Positif", "Vulnérabilité signalée par le scanner mais non applicable dans le contexte réel"]
    ]
    t_gloss = Table(glossary, colWidths=[100, 400])
    t_gloss.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
    ]))
    story.append(t_gloss)

    doc.build(story)
    return buffer.getvalue()
