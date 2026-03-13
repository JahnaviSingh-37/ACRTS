# ============================================
# Adaptive Cyber Resilience and Automated
# Threat Neutralization System (ACRTS)
# Team  : Jahnavi Singh, Darsh Bindra,
#          Aayushi Malik, Mohini
# Repo  : https://github.com/jahnavi-37
# Version: 1.0
# ============================================

import pandas as pd
import streamlit as st
import altair as alt

import database
import report_generator

st.set_page_config(page_title="ACRTS - Threat Neutralization System", layout="wide")

st.title("ACRTS - Threat Neutralization System")
st.markdown("<div style='padding:6px;background:#e0f5e0;color:#0a6c0a;font-weight:600;'>System Status: Active and Monitoring</div>", unsafe_allow_html=True)

incidents = database.get_all_incidents()
df = pd.DataFrame(incidents)

if df.empty:
    st.info("No incidents yet. Run python main.py first.")
    st.stop()

severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
df["severity"] = pd.Categorical(df["severity"], categories=severity_order, ordered=True)

with st.sidebar:
    st.header("Filters")
    severity_filter = st.multiselect("Severity", severity_order, default=severity_order)
    threat_filter = st.multiselect("Threat Type", sorted(df["threat_type"].unique()), default=list(df["threat_type"].unique()))
    filtered = df[df["severity"].isin(severity_filter) & df["threat_type"].isin(threat_filter)]
    path = report_generator.generate_pdf()
    with open(path, "rb") as f:
        st.download_button("Download PDF", data=f, file_name="acrt_report.pdf")

col1, col2, col3, col4 = st.columns(4)
col1.metric("Total Incidents", len(filtered))
col2.metric("Critical", int((filtered["severity"] == "CRITICAL").sum()))
col3.metric("High", int((filtered["severity"] == "HIGH").sum()))
most_ip = filtered["ip_address"].value_counts().idxmax() if not filtered.empty else "N/A"
col4.metric("Most Attacked IP", most_ip)

st.markdown("<div style='padding:6px;background:#ffdddd;color:#8b0000;font-weight:700;'>CRITICAL alerts are highlighted below</div>", unsafe_allow_html=True)

st.subheader("Incidents")
st.dataframe(
    filtered[["timestamp", "log_source", "threat_type", "ip_address", "severity", "risk_score", "mitre_technique_id", "mitre_tactic", "action_taken", "status"]]
)

st.subheader("Threats by Type")
threat_chart = (
    alt.Chart(filtered)
    .mark_bar(color="#1f77b4")
    .encode(x="threat_type:N", y="count()", tooltip=["count()"])
)
st.altair_chart(threat_chart, use_container_width=True)

st.subheader("Severity Distribution")
pie = (
    alt.Chart(filtered)
    .mark_arc()
    .encode(theta="count()", color="severity:N")
)
st.altair_chart(pie, use_container_width=True)

st.subheader("Threats per Hour")
if "timestamp" in filtered:
    tmp = filtered.copy()
    tmp["hour"] = pd.to_datetime(tmp["timestamp"], errors="coerce").dt.hour
    line = alt.Chart(tmp.dropna(subset=["hour"])).mark_line(point=True).encode(x="hour:O", y="count()")
    st.altair_chart(line, use_container_width=True)

st.subheader("Top Attacked IPs")
top_ips = filtered["ip_address"].value_counts().reset_index()
top_ips.columns = ["ip", "count"]
bar_ips = alt.Chart(top_ips).mark_bar(color="#e67e22").encode(x="ip:N", y="count:Q")
st.altair_chart(bar_ips, use_container_width=True)

st.subheader("MITRE ATT&CK Techniques")
mitre_table = filtered[["threat_type", "mitre_technique_id", "mitre_tactic"]].drop_duplicates()
st.table(mitre_table)

st.markdown("---")
st.markdown("ACRTS | Team: Jahnavi Singh, Darsh Bindra, Aayushi Malik, Mohini | github.com/jahnavi-37")
