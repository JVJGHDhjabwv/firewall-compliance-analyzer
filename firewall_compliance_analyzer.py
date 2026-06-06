import pandas as pd
import os
from datetime import datetime


# ============================================================
# Firewall Compliance Analyzer
# ============================================================

REQUIRED_COLUMNS = [
    "Rule_ID",
    "Rule_Name",
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
    "Logging",
    "NAT",
    "Rule_Type",
    "Owner",
    "Department",
    "Business_Justification",
    "Ticket_Number",
    "Created_Date",
    "Last_Reviewed_Date",
    "Expiry_Date",
    "Status",
    "Environment",
    "Remarks"
]


# ============================================================
# Helper Functions
# ============================================================

def is_empty(value):
    """
    Checks whether a value is empty.
    """
    if pd.isna(value):
        return True

    value = str(value).strip()

    return value == "" or value.lower() in ["nan", "none", "null"]


def normalize(value):
    """
    Converts value to uppercase string for easier checking.
    """
    if pd.isna(value):
        return ""

    return str(value).strip().upper()


def load_firewall_rules(file_path):
    """
    Loads firewall rules from CSV or Excel.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    file_extension = os.path.splitext(file_path)[1].lower()

    if file_extension == ".csv":
        df = pd.read_csv(file_path)
    elif file_extension in [".xlsx", ".xls"]:
        df = pd.read_excel(file_path)
    else:
        raise ValueError("Unsupported file type. Please use CSV, XLSX, or XLS.")

    return df


def validate_columns(df):
    """
    Checks whether all required columns exist.
    """
    missing_columns = []

    for column in REQUIRED_COLUMNS:
        if column not in df.columns:
            missing_columns.append(column)

    if missing_columns:
        raise ValueError(
            "Missing required columns: " + ", ".join(missing_columns)
        )


def add_finding(rule, findings, issue, severity, risk_explanation, recommendation):
    """
    Adds a finding to the findings list.
    """
    findings.append({
        "Rule_ID": rule.get("Rule_ID", ""),
        "Rule_Name": rule.get("Rule_Name", ""),
        "Source_Zone": rule.get("Source_Zone", ""),
        "Source": rule.get("Source", ""),
        "Source_IP": rule.get("Source_IP", ""),
        "Destination_Zone": rule.get("Destination_Zone", ""),
        "Destination": rule.get("Destination", ""),
        "Destination_IP": rule.get("Destination_IP", ""),
        "Service": rule.get("Service", ""),
        "Protocol": rule.get("Protocol", ""),
        "Port": rule.get("Port", ""),
        "Action": rule.get("Action", ""),
        "Logging": rule.get("Logging", ""),
        "NAT": rule.get("NAT", ""),
        "Rule_Type": rule.get("Rule_Type", ""),
        "Owner": rule.get("Owner", ""),
        "Department": rule.get("Department", ""),
        "Business_Justification": rule.get("Business_Justification", ""),
        "Ticket_Number": rule.get("Ticket_Number", ""),
        "Created_Date": rule.get("Created_Date", ""),
        "Last_Reviewed_Date": rule.get("Last_Reviewed_Date", ""),
        "Expiry_Date": rule.get("Expiry_Date", ""),
        "Status": rule.get("Status", ""),
        "Environment": rule.get("Environment", ""),
        "Remarks": rule.get("Remarks", ""),
        "Issue": issue,
        "Severity": severity,
        "Risk_Explanation": risk_explanation,
        "Recommendation": recommendation
    })


# ============================================================
# Compliance Checks
# ============================================================

def check_any_source(rule, findings):
    source = normalize(rule["Source"])
    source_ip = normalize(rule["Source_IP"])
    action = normalize(rule["Action"])

    if action == "ALLOW" and (source == "ANY" or source_ip == "ANY"):
        add_finding(
            rule,
            findings,
            "Source is set to Any",
            "High",
            "The rule allows traffic from any source. This increases the attack surface because unknown or unauthorised systems may be able to reach the destination.",
            "Restrict the source to specific IP addresses, approved subnets, VPN ranges, or trusted network groups."
        )


def check_any_destination(rule, findings):
    destination = normalize(rule["Destination"])
    destination_ip = normalize(rule["Destination_IP"])
    action = normalize(rule["Action"])

    if action == "ALLOW" and (destination == "ANY" or destination_ip == "ANY"):
        add_finding(
            rule,
            findings,
            "Destination is set to Any",
            "High",
            "The rule allows traffic to any destination. This may permit unnecessary access to systems that do not require connectivity.",
            "Restrict the destination to specific approved servers, applications, or network segments."
        )


def check_any_service(rule, findings):
    service = normalize(rule["Service"])
    port = normalize(rule["Port"])
    action = normalize(rule["Action"])

    if action == "ALLOW" and (service == "ANY" or port == "ANY"):
        add_finding(
            rule,
            findings,
            "Service or port is set to Any",
            "Critical",
            "The rule allows all services or ports. This may expose unnecessary protocols and increase the chance of exploitation.",
            "Replace Any service or Any port with only the required ports and protocols."
        )


def check_any_any_any(rule, findings):
    source = normalize(rule["Source"])
    source_ip = normalize(rule["Source_IP"])
    destination = normalize(rule["Destination"])
    destination_ip = normalize(rule["Destination_IP"])
    service = normalize(rule["Service"])
    port = normalize(rule["Port"])
    action = normalize(rule["Action"])

    source_any = source == "ANY" or source_ip == "ANY"
    destination_any = destination == "ANY" or destination_ip == "ANY"
    service_any = service == "ANY" or port == "ANY"

    if action == "ALLOW" and source_any and destination_any and service_any:
        add_finding(
            rule,
            findings,
            "Any-Any-Any Allow rule detected",
            "Critical",
            "This rule allows unrestricted traffic from anywhere to anywhere using any service. It is one of the highest-risk firewall misconfigurations because it bypasses least-privilege access control.",
            "Remove the rule immediately or redesign it with specific source, destination, and service values."
        )


def check_missing_owner(rule, findings):
    if is_empty(rule["Owner"]):
        add_finding(
            rule,
            findings,
            "Missing rule owner",
            "Medium",
            "A rule without an owner has no clear accountability. This makes it difficult to confirm whether the rule is still required during firewall reviews.",
            "Assign a rule owner or responsible team."
        )


def check_missing_department(rule, findings):
    if is_empty(rule["Department"]):
        add_finding(
            rule,
            findings,
            "Missing department",
            "Low",
            "Without a department, it may be difficult to identify which business unit is responsible for the rule.",
            "Add the responsible department or business unit."
        )


def check_missing_business_justification(rule, findings):
    if is_empty(rule["Business_Justification"]):
        add_finding(
            rule,
            findings,
            "Missing business justification",
            "Medium",
            "Without a business justification, there is no documented reason explaining why the firewall rule is required.",
            "Add a clear business justification or remove the rule if it is not required."
        )


def check_missing_ticket_number(rule, findings):
    if is_empty(rule["Ticket_Number"]):
        add_finding(
            rule,
            findings,
            "Missing change ticket number",
            "Medium",
            "Without a change ticket number, the firewall rule may not be traceable to an approved change request.",
            "Add the related change request, service request, or approval ticket number."
        )


def check_logging_disabled(rule, findings):
    action = normalize(rule["Action"])
    logging = normalize(rule["Logging"])

    if action == "ALLOW" and logging in ["DISABLED", "NO", "FALSE", "OFF", ""]:
        add_finding(
            rule,
            findings,
            "Logging is disabled for allow rule",
            "Medium",
            "Without logging, allowed traffic may not be visible during monitoring, troubleshooting, or security investigations.",
            "Enable logging for allow rules, especially for high-risk or external-facing access."
        )


def check_rule_type_without_expiry(rule, findings):
    rule_type = normalize(rule["Rule_Type"])
    expiry_date = rule["Expiry_Date"]

    temporary_types = ["TEMP", "TEMPORARY", "VENDOR", "EMERGENCY", "TEST", "UAT"]

    if rule_type in temporary_types and is_empty(expiry_date):
        add_finding(
            rule,
            findings,
            f"{rule_type.title()} rule has no expiry date",
            "High",
            "Temporary, vendor, emergency, or test rules may remain active longer than intended if no expiry date is defined.",
            "Add an expiry date so the rule can be reviewed, disabled, or removed after it is no longer required."
        )


def check_missing_last_reviewed_date(rule, findings):
    if is_empty(rule["Last_Reviewed_Date"]):
        add_finding(
            rule,
            findings,
            "Missing last reviewed date",
            "Medium",
            "Rules without a review date may become outdated, unused, or overly permissive over time.",
            "Add the last reviewed date and include the rule in periodic firewall review activities."
        )


def check_expired_rule(rule, findings):
    expiry_date = rule["Expiry_Date"]

    if is_empty(expiry_date):
        return

    parsed_date = pd.to_datetime(expiry_date, dayfirst=True, errors="coerce")

    if pd.isna(parsed_date):
        add_finding(
            rule,
            findings,
            "Invalid expiry date format",
            "Low",
            "An invalid expiry date prevents the system from determining whether the rule is still valid.",
            "Use a valid date format such as DD/MM/YYYY."
        )
        return

    today = datetime.today()

    if parsed_date < today:
        add_finding(
            rule,
            findings,
            "Rule has expired",
            "High",
            "The rule expiry date has passed, which means the access may no longer be approved or required.",
            "Review the rule and disable or remove it if the access is no longer needed."
        )


def check_risky_services(rule, findings):
    service = normalize(rule["Service"])
    port = normalize(rule["Port"])
    action = normalize(rule["Action"])

    if action != "ALLOW":
        return

    risky_services = {
        "RDP": {
            "ports": ["3389"],
            "severity": "High",
            "risk": "RDP provides remote desktop access. If exposed broadly, attackers may attempt brute-force attacks or exploit remote access vulnerabilities.",
            "recommendation": "Restrict RDP to VPN or admin networks only and enable strong authentication."
        },
        "SSH": {
            "ports": ["22"],
            "severity": "Medium",
            "risk": "SSH provides remote administrative access. If exposed unnecessarily, it may be targeted for brute-force login attempts.",
            "recommendation": "Restrict SSH access to trusted administrator IP ranges only."
        },
        "TELNET": {
            "ports": ["23"],
            "severity": "High",
            "risk": "Telnet transmits data in clear text, including usernames and passwords. This can expose credentials to interception.",
            "recommendation": "Replace Telnet with SSH and block Telnet access."
        },
        "FTP": {
            "ports": ["21"],
            "severity": "High",
            "risk": "FTP can transmit credentials and data without encryption, making it unsuitable for sensitive environments.",
            "recommendation": "Use SFTP or FTPS instead of FTP."
        },
        "SMB": {
            "ports": ["445"],
            "severity": "High",
            "risk": "SMB is commonly abused for lateral movement and file-sharing attacks. Broad SMB access can increase ransomware impact.",
            "recommendation": "Restrict SMB to required internal systems only and avoid exposing it across network zones."
        },
        "MSSQL": {
            "ports": ["1433"],
            "severity": "Medium",
            "risk": "Database services should not be broadly reachable. Unrestricted database access can expose sensitive data.",
            "recommendation": "Allow database access only from approved application servers."
        },
        "MYSQL": {
            "ports": ["3306"],
            "severity": "Medium",
            "risk": "MySQL database access should be limited to authorised systems. Broad access may expose application data.",
            "recommendation": "Restrict MySQL access to approved application servers only."
        },
        "HTTP": {
            "ports": ["80"],
            "severity": "Low",
            "risk": "HTTP traffic is not encrypted. Sensitive data transmitted over HTTP may be intercepted.",
            "recommendation": "Use HTTPS instead of HTTP where possible."
        }
    }

    for risky_service, details in risky_services.items():
        if risky_service in service or port in details["ports"]:
            add_finding(
                rule,
                findings,
                f"Risky service detected: {risky_service}",
                details["severity"],
                details["risk"],
                details["recommendation"]
            )


def check_disabled_rule(rule, findings):
    status = normalize(rule["Status"])

    if status == "DISABLED":
        add_finding(
            rule,
            findings,
            "Disabled rule detected",
            "Low",
            "Disabled rules may clutter the firewall policy and make rulebase reviews more difficult.",
            "Review disabled rules and remove them if they are no longer required."
        )


def check_external_to_internal(rule, findings):
    source_zone = normalize(rule["Source_Zone"])
    destination_zone = normalize(rule["Destination_Zone"])
    action = normalize(rule["Action"])

    external_zones = ["WAN", "INTERNET", "EXTERNAL", "OUTSIDE"]
    internal_zones = ["LAN", "INTERNAL", "INSIDE", "SERVER", "DB", "APP"]

    if action == "ALLOW" and source_zone in external_zones and destination_zone in internal_zones:
        add_finding(
            rule,
            findings,
            "External to internal allow rule",
            "High",
            "The rule allows traffic from an external zone into an internal zone. This may expose internal systems to external threats.",
            "Ensure the access is required, restrict the source, restrict the destination, limit the ports, and enable logging."
        )


def check_prod_any_rule(rule, findings):
    environment = normalize(rule["Environment"])
    source = normalize(rule["Source"])
    destination = normalize(rule["Destination"])
    service = normalize(rule["Service"])
    action = normalize(rule["Action"])

    if environment == "PRODUCTION" and action == "ALLOW":
        if source == "ANY" or destination == "ANY" or service == "ANY":
            add_finding(
                rule,
                findings,
                "Production rule contains Any value",
                "High",
                "Production firewall rules with Any values are risky because they may expose critical systems or business services more broadly than required.",
                "Review the rule and apply least-privilege access by defining specific source, destination, and service values."
            )


# ============================================================
# Duplicate Rule Detection
# ============================================================

def check_duplicate_rules(df, findings):
    """
    Checks for duplicate rules using key traffic fields.
    """
    duplicate_columns = [
        "Source_Zone",
        "Source",
        "Source_IP",
        "Destination_Zone",
        "Destination",
        "Destination_IP",
        "Service",
        "Protocol",
        "Port",
        "Action"
    ]

    duplicates = df[df.duplicated(subset=duplicate_columns, keep=False)]

    for _, rule in duplicates.iterrows():
        add_finding(
            rule,
            findings,
            "Possible duplicate rule detected",
            "Medium",
            "This rule appears to have the same source, destination, service, protocol, port, and action as another rule. Duplicate rules can make the rulebase harder to manage.",
            "Review duplicate rules and remove unnecessary repeated entries."
        )


# ============================================================
# Analyzer Engine
# ============================================================

def analyze_firewall_rules(df):
    """
    Runs all compliance checks.
    """
    findings = []

    validate_columns(df)

    for _, rule in df.iterrows():
        check_any_source(rule, findings)
        check_any_destination(rule, findings)
        check_any_service(rule, findings)
        check_any_any_any(rule, findings)

        check_missing_owner(rule, findings)
        check_missing_department(rule, findings)
        check_missing_business_justification(rule, findings)
        check_missing_ticket_number(rule, findings)
        check_missing_last_reviewed_date(rule, findings)

        check_logging_disabled(rule, findings)
        check_rule_type_without_expiry(rule, findings)
        check_expired_rule(rule, findings)
        check_risky_services(rule, findings)
        check_disabled_rule(rule, findings)
        check_external_to_internal(rule, findings)
        check_prod_any_rule(rule, findings)

    check_duplicate_rules(df, findings)

    findings_df = pd.DataFrame(findings)

    return findings_df


# ============================================================
# Report Generation
# ============================================================

def create_summary(findings_df):
    """
    Creates a summary table by severity.
    """
    severity_order = ["Critical", "High", "Medium", "Low"]

    if findings_df.empty:
        return pd.DataFrame({
            "Severity": severity_order,
            "Count": [0, 0, 0, 0]
        })

    summary = findings_df["Severity"].value_counts().reset_index()
    summary.columns = ["Severity", "Count"]

    summary["Severity"] = pd.Categorical(
        summary["Severity"],
        categories=severity_order,
        ordered=True
    )

    summary = summary.sort_values("Severity")

    return summary


def create_rule_status_summary(original_df, findings_df):
    """
    Creates a rule-level pass/fail summary.
    """
    if findings_df.empty:
        result_df = original_df[["Rule_ID", "Rule_Name"]].copy()
        result_df["Compliance_Status"] = "Pass"
        result_df["Finding_Count"] = 0
        result_df["Highest_Severity"] = "None"
        return result_df

    severity_rank = {
        "Critical": 4,
        "High": 3,
        "Medium": 2,
        "Low": 1
    }

    grouped = findings_df.groupby(["Rule_ID", "Rule_Name"]).agg(
        Finding_Count=("Issue", "count")
    ).reset_index()

    highest_severity_list = []

    for _, row in grouped.iterrows():
        rule_findings = findings_df[findings_df["Rule_ID"] == row["Rule_ID"]]

        highest = max(
            rule_findings["Severity"],
            key=lambda x: severity_rank.get(x, 0)
        )

        highest_severity_list.append(highest)

    grouped["Highest_Severity"] = highest_severity_list
    grouped["Compliance_Status"] = "Fail"

    result_df = original_df[["Rule_ID", "Rule_Name"]].copy()
    result_df = result_df.merge(
        grouped,
        on=["Rule_ID", "Rule_Name"],
        how="left"
    )

    result_df["Compliance_Status"] = result_df["Compliance_Status"].fillna("Pass")
    result_df["Finding_Count"] = result_df["Finding_Count"].fillna(0).astype(int)
    result_df["Highest_Severity"] = result_df["Highest_Severity"].fillna("None")

    return result_df


def export_report(original_df, findings_df, output_file):
    """
    Exports original rules, findings, summary, and rule status to Excel.
    """
    summary_df = create_summary(findings_df)
    rule_status_df = create_rule_status_summary(original_df, findings_df)

    with pd.ExcelWriter(output_file, engine="openpyxl") as writer:
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


# ============================================================
# Main Program
# ============================================================

def main():
    print("=" * 70)
    print("Firewall Compliance Analyzer")
    print("=" * 70)

    file_path = input("Enter firewall rule file path CSV/XLSX: ").strip()

    try:
        firewall_rules_df = load_firewall_rules(file_path)

        print("\nFile loaded successfully.")
        print(f"Total rules loaded: {len(firewall_rules_df)}")

        findings_df = analyze_firewall_rules(firewall_rules_df)

        print("\nAnalysis completed.")

        if findings_df.empty:
            print("No compliance issues found.")
        else:
            print(f"Total findings: {len(findings_df)}")
            print("\nFindings by severity:")
            print(create_summary(findings_df).to_string(index=False))

        output_file = "firewall_compliance_report.xlsx"
        export_report(firewall_rules_df, findings_df, output_file)

        print(f"\nReport exported successfully: {output_file}")

    except Exception as e:
        print("\nError occurred:")
        print(str(e))


if __name__ == "__main__":
    main()