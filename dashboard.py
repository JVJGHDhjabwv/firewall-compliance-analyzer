import streamlit as st
import pandas as pd
import openpyxl
from io import BytesIO
from datetime import date

from firewall_compliance_analyzer import (
    load_firewall_rules,
    analyze_firewall_rules,
    create_summary,
    create_rule_status_summary,
    export_report,
    SEVERITY_ORDER,
    SEVERITY_COLORS
)

# ============================================================
# Page Configuration
# ============================================================

st.set_page_config(
    page_title="Firewall Compliance Analyzer",
    page_icon="🔥",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ============================================================
# Custom CSS
# ============================================================

st.markdown("""
<style>
    /* Metric cards */
    div[data-testid="metric-container"] {
        background-color: #1e2130;
        border: 1px solid #2e3250;
        border-radius: 8px;
        padding: 16px;
        text-align: center;
    }

    div[data-testid="metric-container"] label {
        color: #a0aec0;
        font-size: 13px;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }

    div[data-testid="metric-container"] div[data-testid="metric-value"] {
        color: #ffffff;
        font-size: 28px;
        font-weight: 700;
    }

    /* Section headers */
    h2, h3 {
        color: #e2e8f0;
        margin-top: 1.5rem;
    }

    /* Severity badge styling via dataframe cell color is handled in Python */
    .stAlert {
        border-radius: 8px;
    }

    /* Sidebar */
    section[data-testid="stSidebar"] {
        background-color: #0f1117;
    }

    /* Download button */
    div[data-testid="stDownloadButton"] button {
        background-color: #2563eb;
        color: white;
        border: none;
        border-radius: 6px;
        padding: 0.5rem 1.25rem;
        font-weight: 600;
    }

    div[data-testid="stDownloadButton"] button:hover {
        background-color: #1d4ed8;
    }
</style>
""", unsafe_allow_html=True)


# ============================================================
# Severity Color Map for Dashboard
# ============================================================

SEVERITY_BG = {
    "Critical": "#C00000",
    "High":     "#FF0000",
    "Medium":   "#FF8C00",
    "Low":      "#FFD700"
}

SEVERITY_TEXT = {
    "Critical": "#ffffff",
    "High":     "#ffffff",
    "Medium":   "#ffffff",
    "Low":      "#000000"
}

STATUS_BG = {
    "Pass": "#70AD47",
    "Fail": "#C00000"
}


# ============================================================
# Helpers
# ============================================================

def load_uploaded_file(uploaded_file):
    """
    Loads a CSV or Excel file uploaded via Streamlit.
    Strips column name whitespace for consistency.
    """
    name = uploaded_file.name.lower()

    if name.endswith(".csv"):
        df = pd.read_csv(uploaded_file, dtype=str)
    elif name.endswith((".xlsx", ".xls")):
        df = pd.read_excel(uploaded_file, dtype=str)
    else:
        raise ValueError(
            "Unsupported file type. Please upload a CSV or Excel file."
        )

    df.columns = df.columns.astype(str).str.strip()
    df = df.reset_index(drop=True)

    return df


def generate_excel_report_bytes(original_df, findings_df):
    """
    Generates the styled Excel report in memory and returns bytes
    for the Streamlit download button.
    Uses export_report() from the analyzer so styling is consistent.
    """
    buffer = BytesIO()
    export_report(original_df, findings_df, buffer)
    buffer.seek(0)
    return buffer


def severity_badge(severity):
    """
    Returns an HTML badge string for a severity label.
    """
    bg = SEVERITY_BG.get(severity, "#888888")
    fg = SEVERITY_TEXT.get(severity, "#ffffff")
    return (
        f'<span style="background-color:{bg};color:{fg};'
        f'padding:2px 10px;border-radius:4px;font-weight:700;'
        f'font-size:12px;">{severity}</span>'
    )


def count_by_severity(findings_df, severity):
    if findings_df.empty:
        return 0
    return int((findings_df["Severity"] == severity).sum())


def get_compliance_score(total_rules, failed_rules):
    """
    Returns a 0-100 compliance score.
    """
    if total_rules == 0:
        return 100
    return round(((total_rules - failed_rules) / total_rules) * 100, 1)


def score_color(score):
    if score >= 80:
        return "#70AD47"
    if score >= 50:
        return "#FF8C00"
    return "#C00000"


# ============================================================
# Sidebar
# ============================================================

def render_sidebar():
    with st.sidebar:
        st.markdown("## ⚙️ Analysis Options")
        st.markdown("---")

        run_shadow = st.toggle(
            "Shadowed rule detection",
            value=True,
            help=(
                "Detect rules that are superseded by a broader preceding rule. "
                "Disable for faster analysis on large rulebases (500+ rules)."
            )
        )

        st.markdown("---")
        st.markdown("### Severity Filter")

        selected_severities = []

        for sev in SEVERITY_ORDER:
            bg = SEVERITY_BG.get(sev, "#888")
            checked = st.checkbox(
                sev,
                value=True,
                key=f"sev_filter_{sev}",
                help=f"Show {sev} findings"
            )
            if checked:
                selected_severities.append(sev)

        st.markdown("---")
        st.markdown("### About")
        st.caption(
            "Firewall Compliance Analyzer checks your firewall rulebase "
            "for security misconfigurations, missing governance fields, "
            "expired rules, risky services, and duplicate or shadowed rules."
        )
        st.caption(f"Report date: {date.today().strftime('%d %B %Y')}")

    return run_shadow, selected_severities


# ============================================================
# Metric Cards
# ============================================================

def render_metric_cards(
    total_rules,
    passed_rules,
    failed_rules,
    total_findings,
    compliance_score
):
    st.markdown("### Overview")

    col1, col2, col3, col4, col5 = st.columns(5)

    col1.metric("Total Rules",      total_rules)
    col2.metric("Passed Rules",     passed_rules)
    col3.metric("Failed Rules",     failed_rules)
    col4.metric("Total Findings",   total_findings)

    score_html = (
        f'<div style="background-color:#1e2130;border:1px solid #2e3250;'
        f'border-radius:8px;padding:16px;text-align:center;">'
        f'<div style="color:#a0aec0;font-size:13px;font-weight:600;'
        f'text-transform:uppercase;letter-spacing:0.05em;">Compliance Score</div>'
        f'<div style="color:{score_color(compliance_score)};font-size:28px;'
        f'font-weight:700;">{compliance_score}%</div>'
        f'</div>'
    )
    col5.markdown(score_html, unsafe_allow_html=True)


def render_severity_cards(findings_df):
    st.markdown("### Findings by Severity")

    cols = st.columns(4)

    for i, sev in enumerate(SEVERITY_ORDER):
        count = count_by_severity(findings_df, sev)
        bg = SEVERITY_BG[sev]
        fg = SEVERITY_TEXT[sev]

        card_html = (
            f'<div style="background-color:{bg};border-radius:8px;'
            f'padding:16px;text-align:center;">'
            f'<div style="color:{fg};font-size:13px;font-weight:600;'
            f'text-transform:uppercase;letter-spacing:0.05em;">{sev}</div>'
            f'<div style="color:{fg};font-size:32px;font-weight:700;">{count}</div>'
            f'</div>'
        )
        cols[i].markdown(card_html, unsafe_allow_html=True)


# ============================================================
# Charts
# ============================================================

def render_severity_chart(summary_df):
    st.markdown("### Severity Distribution")

    if summary_df["Count"].sum() == 0:
        st.info("No findings to chart.")
        return

    chart_df = summary_df.set_index("Severity")[["Count"]]
    st.bar_chart(chart_df, use_container_width=True)


def render_issue_breakdown(findings_df):
    """
    Shows a horizontal bar chart of the top 10 most common issues.
    """
    if findings_df.empty:
        return

    st.markdown("### Top Issues")

    top_issues = (
        findings_df["Issue"]
        .value_counts()
        .head(10)
        .reset_index()
    )
    top_issues.columns = ["Issue", "Count"]

    st.bar_chart(
        top_issues.set_index("Issue")["Count"],
        use_container_width=True
    )


# ============================================================
# Rule Status Table
# ============================================================

def render_rule_status(rule_status_df):
    st.markdown("### Rule Compliance Status")

    display_df = rule_status_df.copy()

    st.dataframe(
        display_df,
        use_container_width=True,
        hide_index=True,
        column_config={
            "Rule_ID": st.column_config.TextColumn("Rule ID", width="small"),
            "Rule_Name": st.column_config.TextColumn("Rule Name", width="medium"),
            "Compliance_Status": st.column_config.TextColumn(
                "Status",
                width="small",
                help="Pass = no findings. Fail = one or more findings."
            ),
            "Finding_Count": st.column_config.NumberColumn(
                "Findings",
                width="small"
            ),
            "Highest_Severity": st.column_config.TextColumn(
                "Highest Severity",
                width="small"
            )
        }
    )


# ============================================================
# Findings Table
# ============================================================

def render_findings(findings_df, selected_severities):
    st.markdown("### Detailed Findings")

    if findings_df.empty:
        st.success("✅ No compliance issues found. All rules passed.")
        return

    filtered = findings_df[
        findings_df["Severity"].isin(selected_severities)
    ].copy()

    if filtered.empty:
        st.info("No findings match the selected severity filters.")
        return

    st.caption(
        f"Showing {len(filtered)} of {len(findings_df)} findings "
        f"({', '.join(selected_severities)})"
    )

    display_columns = [
        "Rule_ID",
        "Rule_Name",
        "Issue",
        "Severity",
        "Source_Zone",
        "Source",
        "Source_IP",
        "Destination_Zone",
        "Destination",
        "Destination_IP",
        "Service",
        "Protocol",
        "Port",
        "Action",
        "Risk_Explanation",
        "Recommendation"
    ]

    display_columns = [
        col for col in display_columns if col in filtered.columns
    ]

    st.dataframe(
        filtered[display_columns],
        use_container_width=True,
        hide_index=True,
        column_config={
            "Rule_ID": st.column_config.TextColumn("Rule ID", width="small"),
            "Rule_Name": st.column_config.TextColumn("Rule Name", width="medium"),
            "Issue": st.column_config.TextColumn("Issue", width="large"),
            "Severity": st.column_config.TextColumn("Severity", width="small"),
            "Source_Zone": st.column_config.TextColumn("Src Zone", width="small"),
            "Source": st.column_config.TextColumn("Source", width="small"),
            "Source_IP": st.column_config.TextColumn("Src IP", width="small"),
            "Destination_Zone": st.column_config.TextColumn("Dst Zone", width="small"),
            "Destination": st.column_config.TextColumn("Destination", width="small"),
            "Destination_IP": st.column_config.TextColumn("Dst IP", width="small"),
            "Service": st.column_config.TextColumn("Service", width="small"),
            "Protocol": st.column_config.TextColumn("Protocol", width="small"),
            "Port": st.column_config.TextColumn("Port", width="small"),
            "Action": st.column_config.TextColumn("Action", width="small"),
            "Risk_Explanation": st.column_config.TextColumn(
                "Risk", width="large"
            ),
            "Recommendation": st.column_config.TextColumn(
                "Recommendation", width="large"
            )
        }
    )

    # Per-severity expanders for focused review
    st.markdown("#### Findings by Severity")

    for sev in SEVERITY_ORDER:
        if sev not in selected_severities:
            continue

        sev_findings = filtered[filtered["Severity"] == sev]

        if sev_findings.empty:
            continue

        bg = SEVERITY_BG[sev]
        fg = SEVERITY_TEXT[sev]

        with st.expander(
            f"{sev} — {len(sev_findings)} finding(s)",
            expanded=(sev in ("Critical", "High"))
        ):
            for _, row in sev_findings.iterrows():
                st.markdown(
                    f'<div style="border-left:4px solid {bg};'
                    f'padding:10px 14px;margin-bottom:10px;'
                    f'background-color:#1a1d2e;border-radius:0 6px 6px 0;">'
                    f'<b style="color:#e2e8f0;">Rule:</b> '
                    f'<span style="color:#a0aec0;">'
                    f'{row.get("Rule_ID","")} — {row.get("Rule_Name","")}</span><br>'
                    f'<b style="color:#e2e8f0;">Issue:</b> '
                    f'<span style="color:#f7c948;">{row.get("Issue","")}</span><br>'
                    f'<b style="color:#e2e8f0;">Risk:</b> '
                    f'<span style="color:#a0aec0;">'
                    f'{row.get("Risk_Explanation","")}</span><br>'
                    f'<b style="color:#e2e8f0;">Recommendation:</b> '
                    f'<span style="color:#68d391;">'
                    f'{row.get("Recommendation","")}</span>'
                    f'</div>',
                    unsafe_allow_html=True
                )


# ============================================================
# Original Rules Table
# ============================================================

def render_original_rules(df):
    with st.expander("View Original Firewall Rules", expanded=False):
        st.dataframe(
            df,
            use_container_width=True,
            hide_index=True
        )


# ============================================================
# Download Section
# ============================================================

def render_download(original_df, findings_df):
    st.markdown("### Export Report")

    report_bytes = generate_excel_report_bytes(original_df, findings_df)
    report_date = date.today().strftime("%Y%m%d")
    filename = f"firewall_compliance_report_{report_date}.xlsx"

    col1, col2 = st.columns([1, 3])

    with col1:
        st.download_button(
            label="⬇️ Download Excel Report",
            data=report_bytes,
            file_name=filename,
            mime=(
                "application/vnd.openxmlformats-"
                "officedocument.spreadsheetml.sheet"
            ),
            use_container_width=True
        )

    with col2:
        st.caption(
            "The report includes: Summary, Rule Status, "
            "Detailed Findings, and Original Rules — "
            "with severity color coding and auto-fit columns."
        )


# ============================================================
# Main App
# ============================================================

def main():
    run_shadow, selected_severities = render_sidebar()

    st.title("🔥 Firewall Compliance Analyzer")
    st.markdown(
        "Upload a firewall rule file to analyze compliance issues, "
        "risk severity, and recommendations."
    )
    st.markdown("---")

    uploaded_file = st.file_uploader(
        "Upload firewall rule file (CSV, XLSX, or XLS)",
        type=["csv", "xlsx", "xls"],
        help="Your file must contain all required columns. "
             "Download the sample template below if needed."
    )

    if uploaded_file is None:
        st.info("📂 Upload a firewall rule file above to begin.")

        with st.expander("Required columns"):
            from firewall_compliance_analyzer import REQUIRED_COLUMNS
            st.code(", ".join(REQUIRED_COLUMNS))

        return

    try:
        with st.spinner("Loading file..."):
            df = load_uploaded_file(uploaded_file)

        st.success(
            f"✅ File loaded: **{uploaded_file.name}** "
            f"— {len(df)} rules"
        )

        with st.spinner("Running compliance analysis..."):
            findings_df = analyze_firewall_rules(df)

        if run_shadow and not df.empty:
            with st.spinner("Running shadowed rule detection..."):
                from firewall_compliance_analyzer import check_shadowed_rules

                shadow_findings = []
                check_shadowed_rules(df, shadow_findings)

                if shadow_findings:
                    shadow_df = pd.DataFrame(shadow_findings)

                    if findings_df.empty:
                        findings_df = shadow_df
                    else:
                        findings_df = pd.concat(
                            [findings_df, shadow_df],
                            ignore_index=True
                        )

        summary_df = create_summary(findings_df)
        rule_status_df = create_rule_status_summary(df, findings_df)

        total_rules = len(df)
        total_findings = len(findings_df)
        failed_rules = int(
            (rule_status_df["Compliance_Status"] == "Fail").sum()
        )
        passed_rules = total_rules - failed_rules
        compliance_score = get_compliance_score(total_rules, failed_rules)

        st.markdown("---")

        render_metric_cards(
            total_rules,
            passed_rules,
            failed_rules,
            total_findings,
            compliance_score
        )

        st.markdown("---")
        render_severity_cards(findings_df)

        st.markdown("---")

        chart_col, issue_col = st.columns(2)

        with chart_col:
            render_severity_chart(summary_df)

        with issue_col:
            render_issue_breakdown(findings_df)

        st.markdown("---")
        render_rule_status(rule_status_df)

        st.markdown("---")
        render_findings(findings_df, selected_severities)

        st.markdown("---")
        render_original_rules(df)

        st.markdown("---")
        render_download(df, findings_df)

    except ValueError as e:
        st.error(f"❌ Validation error: {e}")

    except Exception as e:
        st.error("❌ An unexpected error occurred during analysis.")
        with st.expander("Error details"):
            st.exception(e)


if __name__ == "__main__":
    main()