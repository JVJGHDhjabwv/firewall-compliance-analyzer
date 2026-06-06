import streamlit as st
import pandas as pd
from io import BytesIO

from firewall_compliance_analyzer import (
    analyze_firewall_rules,
    create_summary,
    create_rule_status_summary
)


st.set_page_config(
    page_title="Firewall Compliance Analyzer",
    layout="wide"
)


def load_uploaded_file(uploaded_file):
    """
    Load uploaded CSV or Excel file.
    """
    file_name = uploaded_file.name.lower()

    if file_name.endswith(".csv"):
        return pd.read_csv(uploaded_file)

    if file_name.endswith(".xlsx") or file_name.endswith(".xls"):
        return pd.read_excel(uploaded_file)

    raise ValueError("Unsupported file type. Please upload CSV or Excel file.")


def generate_excel_report(original_df, findings_df):
    """
    Generate Excel report in memory for dashboard download.
    """
    output = BytesIO()

    summary_df = create_summary(findings_df)
    rule_status_df = create_rule_status_summary(original_df, findings_df)

    with pd.ExcelWriter(output, engine="openpyxl") as writer:
        original_df.to_excel(writer, sheet_name="Original Rules", index=False)
        rule_status_df.to_excel(writer, sheet_name="Rule Status", index=False)
        summary_df.to_excel(writer, sheet_name="Summary", index=False)

        if findings_df.empty:
            no_findings_df = pd.DataFrame({
                "Result": ["No compliance issues found."]
            })
            no_findings_df.to_excel(writer, sheet_name="Findings", index=False)
        else:
            findings_df.to_excel(writer, sheet_name="Findings", index=False)

    output.seek(0)
    return output


st.title("Firewall Compliance Analyzer Dashboard")

st.write(
    "Upload a firewall rule CSV or Excel file to analyse compliance issues, "
    "risk severity, explanations, and recommendations."
)

uploaded_file = st.file_uploader(
    "Upload firewall rule file",
    type=["csv", "xlsx", "xls"]
)

if uploaded_file is not None:
    try:
        df = load_uploaded_file(uploaded_file)

        st.success("File uploaded successfully.")

        findings_df = analyze_firewall_rules(df)
        summary_df = create_summary(findings_df)
        rule_status_df = create_rule_status_summary(df, findings_df)

        total_rules = len(df)
        total_findings = len(findings_df)
        failed_rules = len(rule_status_df[rule_status_df["Compliance_Status"] == "Fail"])
        passed_rules = len(rule_status_df[rule_status_df["Compliance_Status"] == "Pass"])

        critical_count = 0
        high_count = 0
        medium_count = 0
        low_count = 0

        if not findings_df.empty:
            critical_count = len(findings_df[findings_df["Severity"] == "Critical"])
            high_count = len(findings_df[findings_df["Severity"] == "High"])
            medium_count = len(findings_df[findings_df["Severity"] == "Medium"])
            low_count = len(findings_df[findings_df["Severity"] == "Low"])

        st.subheader("Dashboard Summary")

        col1, col2, col3, col4 = st.columns(4)

        col1.metric("Total Rules", total_rules)
        col2.metric("Passed Rules", passed_rules)
        col3.metric("Failed Rules", failed_rules)
        col4.metric("Total Findings", total_findings)

        col5, col6, col7, col8 = st.columns(4)

        col5.metric("Critical", critical_count)
        col6.metric("High", high_count)
        col7.metric("Medium", medium_count)
        col8.metric("Low", low_count)

        st.subheader("Findings by Severity")

        st.bar_chart(
            summary_df.set_index("Severity")["Count"]
        )

        st.subheader("Rule Compliance Status")

        st.dataframe(
            rule_status_df,
            use_container_width=True
        )

        st.subheader("Detailed Findings")

        if findings_df.empty:
            st.success("No compliance issues found.")
        else:
            severity_filter = st.multiselect(
                "Filter by severity",
                options=["Critical", "High", "Medium", "Low"],
                default=["Critical", "High", "Medium", "Low"]
            )

            filtered_findings = findings_df[
                findings_df["Severity"].isin(severity_filter)
            ]

            st.dataframe(
                filtered_findings,
                use_container_width=True
            )

        st.subheader("Original Firewall Rules")

        st.dataframe(
            df,
            use_container_width=True
        )

        excel_report = generate_excel_report(df, findings_df)

        st.download_button(
            label="Download Excel Compliance Report",
            data=excel_report,
            file_name="firewall_compliance_report.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        )

    except Exception as e:
        st.error("An error occurred while analysing the file.")
        st.write(str(e))

else:
    st.info("Please upload a CSV or Excel firewall rule file to begin.")