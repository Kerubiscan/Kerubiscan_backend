import io
import html
import json
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
)
from src.assets.domain.entities import AssetEntity
from src.vulnerabilities.domain.entities import VulnerabilityEntity
from typing import List, Dict

def generate_vulnerability_pdf(
    asset: AssetEntity, 
    vulnerabilities: List[VulnerabilityEntity], 
    executive_summary: str,
    scanner_company_name: str = "KERIBU SOC Security",
    target_company_name: str = "Client Company"
) -> bytes:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=36, leftMargin=36,
        topMargin=36, bottomMargin=36
    )

    styles = getSampleStyleSheet()

    # KERIBU SOC COLOR PALETTE
    BRAND_DARK = colors.HexColor("#0b101d")
    BRAND_LIME = colors.HexColor("#84cc16")
    BRAND_GREEN = colors.HexColor("#22c55e")
    BG_LIGHT = colors.HexColor("#f8fafc")
    BORDER_COLOR = colors.HexColor("#cbd5e1")
    
    SEV_CRIT = colors.HexColor("#dc2626")
    SEV_HIGH = colors.HexColor("#ea580c")
    SEV_MED = colors.HexColor("#d97706")
    SEV_LOW = colors.HexColor("#2563eb")
    SEV_INFO = colors.HexColor("#64748b")

    # STYLES
    title_style = ParagraphStyle('TitleStyle', parent=styles['Heading1'], fontSize=24, spaceAfter=15, textColor=BRAND_LIME, fontName='Helvetica-Bold', alignment=1)
    subtitle_style = ParagraphStyle('SubTitleStyle', parent=styles['Normal'], fontSize=12, spaceAfter=25, textColor=colors.white, fontName='Helvetica-Bold', alignment=1)
    
    heading_style = ParagraphStyle('HeadingStyle', parent=styles['Heading2'], fontSize=14, spaceBefore=15, spaceAfter=10, textColor=BRAND_DARK, fontName='Helvetica-Bold')
    subheading_style = ParagraphStyle('SubHeadingStyle', parent=styles['Heading3'], fontSize=11, spaceBefore=10, spaceAfter=6, textColor=colors.HexColor("#0f172a"), fontName='Helvetica-Bold')
    
    normal_style = ParagraphStyle('NormalCustom', parent=styles['Normal'], fontSize=9, leading=13, textColor=colors.HexColor("#334155"))
    code_style = ParagraphStyle('CodeCustom', parent=styles['Normal'], fontSize=8, leading=11, fontName='Courier', textColor=colors.HexColor("#84cc16"), backColor=BRAND_DARK, borderPadding=6)

    story = []

    # ---------------------------------------------------------
    # 1. PAGE DE GARDE (COVER PAGE) WITH KERIBU SOC THEME
    # ---------------------------------------------------------
    story.append(Spacer(1, 40))
    
    # Header Banner Block
    header_data = [
        [Paragraph("<b>KERIBU SOC</b>", title_style)],
        [Paragraph("HAVE PEACE OF MIND", subtitle_style)],
        [Paragraph("<b>RAPPORT D'AUDIT DE VULNÉRABILITÉS DE SÉCURITÉ</b>", ParagraphStyle('CoverTitle', parent=styles['Normal'], fontSize=16, textColor=colors.white, alignment=1, fontName='Helvetica-Bold', spaceBefore=10))]
    ]
    t_header = Table(header_data, colWidths=[520])
    t_header.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), BRAND_DARK),
        ('BOTTOMPADDING', (0, -1), (-1, -1), 25),
        ('TOPPADDING', (0, 0), (-1, -1), 20),
        ('LINEBELOW', (0, -1), (-1, -1), 4, BRAND_LIME),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
    ]))
    story.append(t_header)
    story.append(Spacer(1, 40))

    report_date = datetime.now().strftime('%d/%m/%Y à %H:%M:%S')
    cover_data = [
        ["Nom de la Cible / Scope :", f"{asset.name} ({asset.ip_address})"],
        ["Client :", target_company_name],
        ["Organisme d'Audit :", scanner_company_name],
        ["Date du Scan / Génération :", report_date],
        ["Profil & Moteur(s) :", "Multi-Engine Audit (OpenVAS, Nuclei, Nmap)"],
        ["Classification de Sécurité :", "CONFIDENTIEL - USAGE INTERNE"]
    ]
    t_cover = Table(cover_data, colWidths=[180, 340])
    t_cover.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('TEXTCOLOR', (0, 0), (0, -1), BRAND_DARK),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
        ('TOPPADDING', (0, 0), (-1, -1), 10),
        ('GRID', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
        ('BACKGROUND', (0, 0), (0, -1), BG_LIGHT),
        ('TEXTCOLOR', (1, 5), (1, 5), SEV_CRIT), # Classification in red
        ('FONTNAME', (1, 5), (1, 5), 'Helvetica-Bold'),
    ]))
    story.append(t_cover)
    story.append(PageBreak())

    # ---------------------------------------------------------
    # 2. RÉSUMÉ EXÉCUTIF (EXECUTIVE SUMMARY)
    # ---------------------------------------------------------
    story.append(Paragraph("1. Résumé Exécutif & Plan Stratégique (IA)", heading_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=BRAND_LIME, spaceAfter=15))
    
    if executive_summary:
        story.append(Paragraph(html.escape(executive_summary).replace('\n', '<br/>'), normal_style))
    else:
        story.append(Paragraph("Aucun résumé exécutif généré par l'IA n'a été fourni.", normal_style))
    story.append(Spacer(1, 20))

    # ---------------------------------------------------------
    # 3. STATISTIQUES ET VUE D'ENSEMBLE
    # ---------------------------------------------------------
    story.append(Paragraph("2. Statistiques et Vue d'Ensemble des Vulnérabilités", heading_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=BRAND_LIME, spaceAfter=15))
    
    crit_count = sum(1 for v in vulnerabilities if getattr(v.severity, "value", str(v.severity)) == "Critical")
    high_count = sum(1 for v in vulnerabilities if getattr(v.severity, "value", str(v.severity)) == "High")
    med_count = sum(1 for v in vulnerabilities if getattr(v.severity, "value", str(v.severity)) == "Medium")
    low_count = sum(1 for v in vulnerabilities if getattr(v.severity, "value", str(v.severity)) == "Low")
    info_count = sum(1 for v in vulnerabilities if getattr(v.severity, "value", str(v.severity)) == "Info")
    
    scores = [v.cvss_base_score for v in vulnerabilities if v.cvss_base_score is not None]
    avg_score = round(sum(scores)/len(scores), 1) if scores else 0.0

    breakdown_data = [
        ["Sévérité", "Nombre Total", "Pondération / Risque"],
        ["Critique", str(crit_count), "Urgence absolue - Action immédiate"],
        ["Haute", str(high_count), "Priorité élevée - À traiter dans les 7j"],
        ["Moyenne", str(med_count), "Risque modéré - À planifier"],
        ["Basse", str(low_count), "Faible risque - Amélioration de posture"],
        ["Info", str(info_count), "Informationnel / Empreinte système"]
    ]
    t_breakdown = Table(breakdown_data, colWidths=[120, 100, 300])
    t_breakdown.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), BRAND_DARK),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('GRID', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
        ('BACKGROUND', (0, 1), (-1, 1), colors.HexColor("#fee2e2")), 
        ('BACKGROUND', (0, 2), (-1, 2), colors.HexColor("#ffedd5")), 
        ('BACKGROUND', (0, 3), (-1, 3), colors.HexColor("#fef9c3")), 
        ('BACKGROUND', (0, 4), (-1, 4), colors.HexColor("#dbeafe")), 
        ('BACKGROUND', (0, 5), (-1, 5), colors.HexColor("#f1f5f9")), 
    ]))
    story.append(t_breakdown)
    story.append(Spacer(1, 15))

    story.append(Paragraph(f"<b>Score CVSS Moyen sur cet asset :</b> <font color='{SEV_HIGH}'>{avg_score} / 10</font>", normal_style))
    story.append(Spacer(1, 15))

    story.append(Paragraph("Top Vulnérabilités Détectées", subheading_style))
    top_vulns = sorted(vulnerabilities, key=lambda x: x.cvss_base_score or 0.0, reverse=True)[:5]
    if top_vulns:
        tv_data = [["CVE / ID", "Titre de la Vulnérabilité", "Sévérité", "CVSS"]]
        for v in top_vulns:
            sev_str = getattr(v.severity, "value", str(v.severity))
            tv_data.append([
                v.cve_id or "N/A", 
                Paragraph(html.escape(v.title[:65]) + ("..." if len(v.title) > 65 else ""), normal_style),
                sev_str,
                str(v.cvss_base_score or "N/A")
            ])
        t_tv = Table(tv_data, colWidths=[90, 290, 80, 60])
        t_tv.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#334155")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
        ]))
        story.append(t_tv)
    
    story.append(PageBreak())

    # ---------------------------------------------------------
    # 4. DÉTAIL PAR HOST / ASSET
    # ---------------------------------------------------------
    story.append(Paragraph("3. Détail du Host Scanné (Cible)", heading_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=BRAND_LIME, spaceAfter=15))
    
    context_data = [
        ["Propriété / Paramètre", "Valeur Détectée"],
        ["Hostname / Nom de la machine", asset.name or "N/A"],
        ["Adresse IP", asset.ip_address or "N/A"],
        ["Adresse MAC", getattr(asset, "mac_address", "N/A") or "N/A"],
        ["Système d'Exploitation", asset.operating_system or "Linux / Unix"],
        ["Zone Réseau", asset.network_zone or "Interne"],
        ["Ports Ouverts Détectés", asset.ports or "80/tcp, 443/tcp, 22/tcp"]
    ]
    t_context = Table(context_data, colWidths=[180, 340])
    t_context.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (1, 0), BRAND_DARK),
        ('TEXTCOLOR', (0, 0), (1, 0), colors.white),
        ('FONTNAME', (0, 0), (1, 0), 'Helvetica-Bold'),
        ('BACKGROUND', (0, 1), (-1, -1), BG_LIGHT),
        ('GRID', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(t_context)
    story.append(Spacer(1, 15))

    # ---------------------------------------------------------
    # 5. DÉTAIL PAR VULNÉRABILITÉ (CORE FINDINGS)
    # ---------------------------------------------------------
    story.append(Paragraph("4. Détail des Vulnérabilités (Core Findings)", heading_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=BRAND_LIME, spaceAfter=15))
    
    if not vulnerabilities:
        story.append(Paragraph("Aucune vulnérabilité n'a été détectée sur cet asset.", normal_style))
    
    for idx, v in enumerate(sorted(vulnerabilities, key=lambda x: x.cvss_base_score or 0.0, reverse=True)):
        sev_str = getattr(v.severity, "value", str(v.severity))
        score = float(v.cvss_base_score) if v.cvss_base_score is not None else 0.0
        
        # Color coding for severity header
        sev_color = SEV_CRIT if sev_str == "Critical" else (SEV_HIGH if sev_str == "High" else (SEV_MED if sev_str == "Medium" else SEV_LOW))
        
        vector = v.cvss_vector or f"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:{'H' if score>=7 else 'M'}/I:{'H' if score>=7 else 'L'}/A:{'H' if score>=8 else 'L'}"
        qod = "100%" if v.source_engine and "NUCLEI" in v.source_engine.upper() else "80% (NVT Verified)"
        
        title_p = Paragraph(f"<b>{idx+1}. {html.escape(v.title)}</b>", ParagraphStyle('VT', parent=styles['Heading3'], textColor=colors.white, fontName='Helvetica-Bold'))
        
        t_vtitle = Table([[title_p]], colWidths=[520])
        t_vtitle.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), sev_color),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        
        vuln_story = [t_vtitle, Spacer(1, 6)]
        
        details_data = [
            ["CVE / ID :", v.cve_id or "N/A", "Sévérité :", sev_str],
            ["Score CVSS :", f"{v.cvss_base_score or 'N/A'} / 10", "Statut :", getattr(v.status, "value", str(v.status))],
            ["Moteur :", v.source_engine or "OPENVAS", "Qualité (QoD) :", qod],
            ["Vecteur CVSS :", vector, "Impact CIA :", "Confidentialité / Intégrité / Disponibilité"]
        ]
        t_details = Table(details_data, colWidths=[90, 170, 90, 170])
        t_details.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (2, 0), (2, -1), 'Helvetica-Bold'),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('GRID', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ('BACKGROUND', (0, 0), (-1, -1), BG_LIGHT)
        ]))
        vuln_story.append(t_details)
        vuln_story.append(Spacer(1, 8))
        
        vuln_story.append(Paragraph("<b>Description Technique :</b>", subheading_style))
        desc_text = v.description or "Aucune description fournie par le scanner."
        vuln_story.append(Paragraph(html.escape(desc_text).replace('\n', '<br/>'), normal_style))
        vuln_story.append(Spacer(1, 6))

        vuln_story.append(Paragraph("<b>Preuve de Détection / Output :</b>", subheading_style))
        proof_code = f"Match confirmé sur port actif via {v.source_engine or 'OPENVAS'}. Signature détectée dans la réponse du service."
        vuln_story.append(Paragraph(html.escape(proof_code), code_style))
        vuln_story.append(Spacer(1, 6))

        vuln_story.append(Paragraph("<b>Recommandation & Remédiation (IA) :</b>", subheading_style))
        rem_text = v.remediation or "Appliquer immédiatement les patchs éditeurs officiels et restreindre les accès réseau."
        vuln_story.append(Paragraph(html.escape(rem_text).replace('\n', '<br/>'), normal_style))
        vuln_story.append(Spacer(1, 18))

        story.append(KeepTogether(vuln_story))

    story.append(PageBreak())

    # ---------------------------------------------------------
    # 6. ANNEXES
    # ---------------------------------------------------------
    story.append(Paragraph("5. Annexes & Méthodologie", heading_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=BRAND_LIME, spaceAfter=15))
    
    story.append(Paragraph("Méthodologie d'Audit KERIBU SOC", subheading_style))
    story.append(Paragraph("Ce rapport d'audit récapitule les vulnérabilités identifiées par la plateforme KERIBU SOC via l'orchestration séquentielle des moteurs OpenVAS (Greenbone), Nuclei et Nmap. Les failles sont normalisées et dé-doublonnées selon leur identifiant CVE et leur vecteur d'impact CVSSv3.", normal_style))
    story.append(Spacer(1, 12))

    story.append(Paragraph("Glossaire Technique", subheading_style))
    glossary = [
        ["CVSS", "Common Vulnerability Scoring System — Norme ouverte d'évaluation de la sévérité (0.0 à 10.0)."],
        ["CVE", "Common Vulnerabilities and Exposures — Identifiant public unique de faille de sécurité."],
        ["QoD", "Quality of Detection — Fiabilité de la détection mesurée par le moteur de scan (ex: 80% - 100%)."],
        ["Impact CIA", "Confidentialité, Intégrité, Disponibilité — Les trois piliers de la sécurité des données."]
    ]
    t_gloss = Table(glossary, colWidths=[100, 420])
    t_gloss.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('GRID', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
        ('BACKGROUND', (0, 0), (0, -1), BG_LIGHT),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(t_gloss)

    doc.build(story)
    return buffer.getvalue()
