# ============================================
# Adaptive Cyber Resilience and Automated
# Threat Neutralization System (ACRTS)
# Team  : Jahnavi Singh, Darsh Bindra,
#          Aayushi Malik, Mohini
# Repo  : https://github.com/jahnavi-37
# Version: 1.0
# ============================================

from datetime import datetime
from typing import Dict, List

from fpdf import FPDF

import database


PALETTE = {
    "bg": (12, 17, 28),
    "panel": (20, 26, 38),
    "accent": (72, 149, 239),
    "success": (71, 201, 145),
    "warning": (255, 193, 79),
    "danger": (239, 71, 111),
    "text": (230, 235, 245),
    "muted": (150, 160, 175),
}


class Report(FPDF):
    def header(self):
        self.set_font("Helvetica", "B", 11)
        self.set_text_color(*PALETTE["text"])
        self.cell(0, 8, "ACRTS Incident Report", ln=1, align="R")
        self.set_draw_color(*PALETTE["accent"])
        self.set_line_width(0.4)
        self.line(10, 18, 200, 18)
        self.ln(2)


def _fill_background(pdf: Report, color: tuple[int, int, int]) -> None:
    pdf.set_fill_color(*color)
    pdf.rect(0, 0, 210, 297, "F")


def _title_block(pdf: Report, title: str, subtitle: str = "") -> None:
    pdf.set_font("Helvetica", "B", 18)
    pdf.set_text_color(*PALETTE["text"])
    pdf.cell(0, 12, title, ln=1, align="L")
    if subtitle:
        pdf.set_font("Helvetica", "", 11)
        pdf.set_text_color(*PALETTE["muted"])
        pdf.multi_cell(0, 7, subtitle)
    pdf.ln(4)


def _stat_pill(pdf: Report, label: str, value: str, color: tuple[int, int, int]) -> None:
    pdf.set_fill_color(*color)
    pdf.set_text_color(12, 17, 28)
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(45, 10, label, border=0, ln=0, align="L", fill=True)
    pdf.set_text_color(*PALETTE["text"])
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(20, 10, value, ln=0, align="C")
    pdf.ln(12)


def _cover_page(pdf: Report) -> None:
    pdf.add_page()
    _fill_background(pdf, PALETTE["bg"])
    pdf.set_y(35)
    _title_block(
        pdf,
        "Adaptive Cyber Resilience and",
        "Automated Threat Neutralization System",
    )
    pdf.set_font("Helvetica", "", 11)
    pdf.set_text_color(*PALETTE["muted"])
    pdf.cell(0, 8, "Minor Project | Version 1.0", ln=1, align="L")
    pdf.ln(6)
    pdf.set_text_color(*PALETTE["text"])
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, "Team", ln=1)
    pdf.set_font("Helvetica", "", 10)
    team_lines = [
        "Jahnavi Singh - Lead Developer & System Architect",
        "Darsh Bindra - Backend Developer & Detection Engine",
        "Aayushi Malik - Database & Report Module Developer",
        "Mohini - Dashboard & Frontend Developer",
    ]
    for line in team_lines:
        pdf.cell(0, 7, line, ln=1)
    pdf.ln(10)
    pdf.set_text_color(*PALETTE["muted"])
    pdf.cell(0, 8, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=1)


def _add_summary(pdf: Report, incidents: List[Dict[str, str]]) -> None:
    pdf.add_page()
    _fill_background(pdf, PALETTE["bg"])
    pdf.set_y(20)
    _title_block(pdf, "Executive Summary", "Snapshot of ACRTS detections and automated response outcomes.")

    total = len(incidents)
    critical = sum(1 for inc in incidents if inc.get("severity") == "CRITICAL")
    high = sum(1 for inc in incidents if inc.get("severity") == "HIGH")
    unique_ips = len({inc.get("ip_address", "") for inc in incidents})

    _stat_pill(pdf, "Total", str(total), PALETTE["accent"])
    _stat_pill(pdf, "Critical", str(critical), PALETTE["danger"])
    _stat_pill(pdf, "High", str(high), PALETTE["warning"])
    _stat_pill(pdf, "Unique IPs", str(unique_ips), PALETTE["success"])

    pdf.ln(4)
    pdf.set_text_color(*PALETTE["muted"])
    pdf.set_font("Helvetica", "", 10)
    pdf.multi_cell(
        0,
        7,
        "ACRTS ingested the provided sample logs, mapped behaviors to MITRE ATT&CK, scored risk, and took automated responses against higher-severity findings.",
    )


def _add_incidents_table(pdf: Report, incidents: List[Dict[str, str]]) -> None:
    pdf.add_page()
    _fill_background(pdf, PALETTE["bg"])
    pdf.set_y(20)
    _title_block(pdf, "Incident Details", "Severity-highlighted table of parsed alerts with MITRE context and response state.")

    headers = [
        "Time",
        "Source",
        "Threat",
        "IP",
        "Severity",
        "Risk",
        "MITRE",
        "Tactic",
        "Action",
    ]
    col_widths = [25, 18, 30, 26, 18, 12, 18, 18, 20]

    pdf.set_font("Helvetica", "B", 9)
    pdf.set_text_color(*PALETTE["text"])
    for header, width in zip(headers, col_widths):
        pdf.cell(width, 9, header, border=1, align="C", fill=False)
    pdf.ln()

    pdf.set_font("Helvetica", "", 8)
    for inc in incidents:
        severity = inc.get("severity", "")
        if severity == "CRITICAL":
            fill = PALETTE["danger"]
        elif severity == "HIGH":
            fill = PALETTE["warning"]
        elif severity == "MEDIUM":
            fill = (78, 161, 215)
        else:
            fill = PALETTE["panel"]

        row = [
            str(inc.get("timestamp", ""))[:16],
            inc.get("log_source", ""),
            inc.get("threat_type", ""),
            inc.get("ip_address", ""),
            inc.get("severity", ""),
            str(inc.get("risk_score", "")),
            inc.get("mitre_technique_id", ""),
            inc.get("mitre_tactic", ""),
            inc.get("action_taken", ""),
        ]

        for value, width in zip(row, col_widths):
            if value == severity:
                pdf.set_fill_color(*fill)
                pdf.set_text_color(12, 17, 28)
                pdf.cell(width, 8, value[:15], border=1, align="C", fill=True)
                pdf.set_text_color(*PALETTE["text"])
            else:
                pdf.set_fill_color(*PALETTE["panel"])
                pdf.cell(width, 8, value[:20], border=1, align="C", fill=True)
        pdf.ln()


def _add_mitre(pdf: Report, incidents: List[Dict[str, str]]) -> None:
    pdf.add_page()
    _fill_background(pdf, PALETTE["bg"])
    pdf.set_y(20)
    _title_block(pdf, "MITRE ATT&CK Coverage", "Techniques observed across parsed incidents with mapped tactics.")

    pdf.set_font("Helvetica", "B", 10)
    pdf.set_fill_color(*PALETTE["panel"])
    pdf.set_text_color(*PALETTE["text"])

    seen: dict[str, str] = {}
    for inc in incidents:
        tech = inc.get("mitre_technique_id", "N/A")
        tactic = inc.get("mitre_tactic", "")
        seen[tech] = tactic

    for tech_id, tactic in seen.items():
        pdf.set_fill_color(*PALETTE["panel"])
        pdf.cell(0, 12, f"Technique {tech_id}", ln=1, align="L", fill=True)
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(*PALETTE["muted"])
        pdf.multi_cell(0, 7, f"Tactic: {tactic} | Detection: Observed in sample logs")
        pdf.ln(2)
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_text_color(*PALETTE["text"])


def _add_recommendations(pdf: Report, incidents: List[Dict[str, str]]) -> None:
    pdf.add_page()
    _fill_background(pdf, PALETTE["bg"])
    pdf.set_y(20)
    _title_block(pdf, "Recommendations", "Operator actions to harden controls and reduce future blast radius.")

    recs = [
        "Tighten account lockout thresholds for repeated SSH failures and enforce MFA on admin accounts.",
        "Baseline RDP usage and alert on new geolocations or after-hours administrative sessions.",
        "Deploy WAF rules for injection patterns; block user-agents issuing enumeration-style requests.",
        "Correlate process lineage for office-spawned PowerShell and terminate anomalous parent chains.",
    ]

    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(*PALETTE["text"])
    for rec in recs:
        pdf.set_fill_color(*PALETTE["panel"])
        pdf.multi_cell(0, 8, f"- {rec}", fill=True)
        pdf.ln(1)

    pdf.ln(4)
    pdf.set_text_color(*PALETTE["muted"])
    pdf.set_font("Helvetica", "", 9)
    pdf.multi_cell(0, 7, "ACRTS auto-blocks high-risk indicators; keep tuning thresholds based on environment.")


def generate_pdf(output_path: str = "acrt_report.pdf") -> str:
    incidents = database.get_all_incidents()
    pdf = Report()
    pdf.set_margins(10, 15, 10)
    pdf.set_auto_page_break(auto=True, margin=12)
    _cover_page(pdf)
    _add_summary(pdf, incidents)
    _add_incidents_table(pdf, incidents)
    _add_mitre(pdf, incidents)
    _add_recommendations(pdf, incidents)
    pdf.output(output_path)
    return output_path
