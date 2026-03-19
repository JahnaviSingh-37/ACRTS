# ============================================
# Adaptive Cyber Resilience and Automated
# Threat Neutralization System (ACRTS)
# Team  : Jahnavi Singh, Darsh Bindra,
#          Aayushi Malik, Mohini
# Repo  : https://github.com/jahnavi-37
# Version: 1.0
# ============================================

from datetime import datetime

import pandas as pd
import plotly.express as px
import streamlit as st

import config
import database
import log_parser
import report_generator
from detector import detect_threats
from responder import block_ip, send_email_alert, terminate_process


st.set_page_config(page_title="ACRTS - SOC Dashboard", layout="wide", initial_sidebar_state="expanded")

DARK_BG = "#0b1324"
PANEL = "#131c2e"
ACCENT = "#4895ef"
CRIT = "#ef476f"
HIGH = "#ffc34f"
MED = "#4ea1d7"
LOW = "#21cfa7"

st.markdown(
    f"""
    <style>
    body {{background-color:{DARK_BG}; color:#e6ebf5;}}
    .metric-card {{padding:12px 14px;border-radius:12px;background:{PANEL};border:1px solid #1f2a3d;}}
    .pill {{display:inline-block;padding:6px 10px;border-radius:20px;font-weight:700;}}
    .pill-green {{background:#1ed760;color:#0b1324;}}
    .pill-red {{background:{CRIT};color:#0b1324;}}
    .pill-amber {{background:{HIGH};color:#0b1324;}}
    .pill-blue {{background:{ACCENT};color:#0b1324;}}
    </style>
    """,
    unsafe_allow_html=True,
)


def run_detection() -> dict:
    database.init_db()
    paths = [config.WINDOWS_LOG, config.LINUX_LOG, config.APACHE_LOG]
    combined: list[dict] = []
    for path in paths:
        combined.extend(log_parser.parse_log(path))
    if not combined:
        return {"handled": 0, "critical": 0, "high": 0}

    incidents = detect_threats(combined)
    handled: list[dict] = []
    for incident in incidents:
        action_taken = "NO ACTION"
        status = "DETECTED"
        if incident.get("severity") in {"HIGH", "CRITICAL"}:
            if incident.get("threat_type") in {"Brute Force", "Port Scanning", "SQL Injection", "RDP Tunneling", "C2C Activity", "Reconnaissance Whisper"}:
                action_taken = block_ip(incident.get("ip_address", ""))
                status = "BLOCKED"
            elif incident.get("threat_type") == "Privilege Escalation":
                action_taken = terminate_process(incident.get("threat_type", ""))
                status = "BLOCKED"
        incident["action_taken"] = action_taken
        incident["status"] = status
        if incident.get("severity") in config.ALERT_ON_SEVERITY:
            send_email_alert(incident)
        database.save_incident(incident)
        handled.append(incident)

    critical = sum(1 for inc in handled if inc.get("severity") == "CRITICAL")
    high = sum(1 for inc in handled if inc.get("severity") == "HIGH")
    return {"handled": len(handled), "critical": critical, "high": high}


incidents = database.get_all_incidents()
df = pd.DataFrame(incidents)
if df.empty:
    st.info("No incidents yet. Run the Live Detection button or execute python3 main.py first.")
    st.stop()

severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
df["severity"] = pd.Categorical(df["severity"], categories=severity_order, ordered=True)

with st.sidebar:
    st.title("SOC Controls")
    if st.button("Run Live Detection", use_container_width=True):
        result = run_detection()
        st.success(f"Detection run complete. New incidents: {result['handled']} (Critical: {result['critical']} | High: {result['high']})")
    severity_filter = st.multiselect("Severity", severity_order, default=severity_order)
    threat_filter = st.multiselect("Threat Type", sorted(df["threat_type"].unique()), default=list(df["threat_type"].unique()))
    filtered = df[df["severity"].isin(severity_filter) & df["threat_type"].isin(threat_filter)]
    path = report_generator.generate_pdf()
    with open(path, "rb") as f:
        st.download_button("Download PDF Report", data=f, file_name="acrt_report.pdf", use_container_width=True)
    st.caption("PDF reflects current incidents with dark SOC styling.")

st.markdown("<div class='pill pill-green'>SOC ACTIVE</div>", unsafe_allow_html=True)
st.title("ACRTS Security Operations Console")
st.caption("Real-time detections, MITRE coverage, and automated response outcomes")

col1, col2, col3, col4 = st.columns(4)
col1.markdown(f"<div class='metric-card'><div style='font-size:13px;'>Total Incidents</div><div style='font-size:26px;font-weight:700;'>{len(filtered)}</div></div>", unsafe_allow_html=True)
col2.markdown(f"<div class='metric-card'><div style='font-size:13px;'>Critical</div><div style='font-size:26px;font-weight:700;color:{CRIT};'>{int((filtered['severity'] == 'CRITICAL').sum())}</div></div>", unsafe_allow_html=True)
col3.markdown(f"<div class='metric-card'><div style='font-size:13px;'>High</div><div style='font-size:26px;font-weight:700;color:{HIGH};'>{int((filtered['severity'] == 'HIGH').sum())}</div></div>", unsafe_allow_html=True)
most_ip = filtered["ip_address"].value_counts().idxmax() if not filtered.empty else "N/A"
col4.markdown(f"<div class='metric-card'><div style='font-size:13px;'>Most Attacked IP</div><div style='font-size:20px;font-weight:700;'>{most_ip}</div></div>", unsafe_allow_html=True)

st.markdown("### Incident Feed")
feed_cols = ["timestamp", "log_source", "threat_type", "ip_address", "severity", "risk_score", "status"]
styled = filtered[feed_cols].sort_values("timestamp", ascending=False).head(20).style.apply(
    lambda s: [
        "background-color: %s; color: #0b1324; font-weight:700;" % (
            CRIT if v == "CRITICAL" else HIGH if v == "HIGH" else MED if v == "MEDIUM" else LOW
        )
        if s.name == "severity"
        else ""
        for v in s
    ],
    axis=0,
)
st.dataframe(styled, use_container_width=True, hide_index=True)

st.markdown("### Threat Landscape")
col_a, col_b = st.columns(2)
threat_chart = px.bar(
    filtered,
    x="threat_type",
    color="severity",
    color_discrete_map={
        "CRITICAL": CRIT,
        "HIGH": HIGH,
        "MEDIUM": MED,
        "LOW": LOW,
    },
    template="plotly_dark",
)
threat_chart.update_layout(paper_bgcolor=PANEL, plot_bgcolor=PANEL, height=320, margin=dict(t=30, b=40, l=40, r=20))
col_a.plotly_chart(threat_chart, use_container_width=True)

tmp = filtered.copy()
tmp["timestamp"] = pd.to_datetime(tmp["timestamp"], errors="coerce")
tmp = tmp.dropna(subset=["timestamp"])
tmp["hour"] = tmp["timestamp"].dt.hour
trend_df = tmp.groupby("hour").size().reset_index(name="count")
trend_chart = px.line(trend_df, x="hour", y="count", markers=True, template="plotly_dark")
trend_chart.update_layout(paper_bgcolor=PANEL, plot_bgcolor=PANEL, height=320, margin=dict(t=30, b=40, l=40, r=20))
trend_chart.update_yaxes(title_text="Count")
trend_chart.update_xaxes(title_text="Hour of Day")
col_b.plotly_chart(trend_chart, use_container_width=True)

st.markdown("### Critical Event Timeline")
timeline = filtered[filtered["severity"].isin(["CRITICAL", "HIGH"])]
timeline = timeline.sort_values("timestamp", ascending=False).head(10)
for _, row in timeline.iterrows():
    color = CRIT if row["severity"] == "CRITICAL" else HIGH
    st.markdown(
        f"<div style='padding:10px;margin-bottom:6px;border-radius:10px;background:{PANEL};border-left:4px solid {color};'>"
        f"<div style='font-weight:700;color:{color};'>{row['severity']} • {row['threat_type']}</div>"
        f"<div style='color:#cdd4e0;font-size:13px;'>{row['timestamp']} | IP {row['ip_address']} | {row['log_source']}</div>"
        f"<div style='color:#9aa3b5;font-size:12px;'>MITRE {row['mitre_technique_id']} · {row['mitre_tactic']} · Action: {row['action_taken']}</div>"
        f"</div>",
        unsafe_allow_html=True,
    )

st.markdown("### MITRE ATT&CK Coverage")
mitre_table = filtered[["threat_type", "mitre_technique_id", "mitre_tactic"]].drop_duplicates()
st.dataframe(mitre_table, use_container_width=True, hide_index=True)

st.markdown("---")
st.caption("ACRTS | Team: Jahnavi Singh, Darsh Bindra, Aayushi Malik, Mohini | github.com/jahnavi-37")
