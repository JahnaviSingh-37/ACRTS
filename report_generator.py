# ============================================
# Adaptive Cyber Resilience and Automated
# Threat Neutralization System (ACRTS)
# Team  : Jahnavi Singh, Darsh Bindra,
#          Aayushi Malik, Mohini
# Repo  : https://github.com/jahnavi-37
# Version: 1.0
# ============================================

from datetime import datetime
from typing import List, Dict, Union

from fpdf import FPDF

import database


class Report(FPDF):
    def header(self):
        self.set_font("Helvetica", "B", 12)
        self.cell(170, 10, "ACRTS Incident Report", ln=1, align="C")
        self.ln(5)


def _add_cover(pdf: Report):
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 20)
    pdf.cell(170, 15, "Adaptive Cyber Resilience and", ln=1, align="C")
    pdf.cell(170, 15, "Automated Threat Neutralization System", ln=1, align="C")
    pdf.ln(10)
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(170, 10, "A Minor Project by", ln=1, align="C")
    pdf.ln(4)
    team_lines = [
        "Jahnavi Singh - Lead Developer & System Architect",
        "Darsh Bindra - Backend Developer & Detection Engine",
        "Aayushi Malik - Database & Report Module Developer",
        "Mohini - Dashboard & Frontend Developer",
    ]
    for line in team_lines:
        pdf.cell(170, 8, line, ln=1, align="C")
    pdf.ln(6)
    pdf.cell(170, 8, f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=1, align="C")


def _add_summary(pdf: Report, incidents: List[Dict]):
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(170, 10, "Executive Summary", ln=1)
    pdf.set_font("Helvetica", "", 10)
    pdf.multi_cell(170, 8, "We ran ACRTS on our sample logs and captured the incidents below. This PDF is a snapshot of what the system saw, how it mapped to MITRE, and what we plan to improve.")
    pdf.ln(4)
    pdf.cell(170, 8, f"Total Incidents: {len(incidents)}", ln=1)


def _add_incidents_table(pdf: Report, incidents: List[Dict]):
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(170, 10, "Incidents", ln=1)
    pdf.set_font("Helvetica", "", 9)
    headers = [
        "Time",
        "Source",
        "Threat",
        "IP",
        "Severity",
        "Risk",
        "MITRE ID",
        "Tactic",
        "Action",
    ]
    col_width = 18
    for header in headers:
        pdf.cell(col_width, 8, header, border=1)
    pdf.ln()
    for inc in incidents:
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
        for col in row:
            pdf.cell(col_width, 8, col[:18], border=1)
        pdf.ln()


def _add_top_ips(pdf: Report, incidents: List[Dict]):
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(170, 10, "Top 5 Dangerous IPs", ln=1)
    pdf.set_font("Helvetica", "", 10)
    counts = {}
    for inc in incidents:
        ip = inc.get("ip_address", "")
        counts[ip] = counts.get(ip, 0) + 1
    for ip, count in sorted(counts.items(), key=lambda x: x[1], reverse=True)[:5]:
        pdf.cell(170, 8, f"{ip} -> {count} hits", ln=1)


def _add_mitre(pdf: Report, incidents: List[Dict]):
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(170, 10, "MITRE Techniques Detected", ln=1)
    pdf.set_font("Helvetica", "", 10)
    seen = {}
    for inc in incidents:
        key = inc.get("mitre_technique_id", "N/A")
        if key not in seen:
            seen[key] = inc.get("mitre_tactic", "")
    for tech_id, tactic in seen.items():
        pdf.cell(170, 8, f"{tech_id} - {tactic}", ln=1)


def _add_recommendations(pdf: Report):
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(170, 10, "Recommendations", ln=1)
    pdf.set_font("Helvetica", "", 10)
    recs = [
        "Tighten account lockout for repeated failures.",
        "Alert on RDP logons from new locations.",
        "Inspect web inputs with a WAF rule set.",
        "Baseline process launches and flag suspicious parents.",
    ]
    for rec in recs:
        pdf.multi_cell(170, 8, f"- {rec}")


def generate_pdf(output_path: str = "acrt_report.pdf") -> str:
    incidents = database.get_all_incidents()
    pdf = Report()
    pdf.set_margins(15, 15, 15)
    pdf.set_auto_page_break(auto=True, margin=15)
    _add_cover(pdf)
    _add_summary(pdf, incidents)
    _add_incidents_table(pdf, incidents)
    _add_top_ips(pdf, incidents)
    _add_mitre(pdf, incidents)
    _add_recommendations(pdf)
    pdf.output(output_path)
    return output_path
