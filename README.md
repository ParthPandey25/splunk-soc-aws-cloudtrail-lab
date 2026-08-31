# 🛡️ Home SOC Lab: Splunk SIEM & AWS CloudTrail Monitoring

> Production-grade Security Operations Center (SOC) lab environment ingesting AWS CloudTrail and VPC Flow Logs into Splunk Enterprise with custom SPL detection rules mapped to the MITRE ATT&CK framework.

[![Splunk](https://img.shields.io/badge/Splunk-Enterprise%209.x-000000?logo=splunk&logoColor=white)](https://splunk.com)
[![AWS CloudTrail](https://img.shields.io/badge/AWS-CloudTrail-FF9900?logo=amazonwebservices&logoColor=white)](https://aws.amazon.com/cloudtrail/)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK%20v14-red.svg)](https://attack.mitre.org)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

---

## 🎯 Lab Objectives

1. **Log Pipeline Ingestion**: Configure automated log forwarding from AWS CloudWatch / S3 to Splunk via AWS Add-on.
2. **Threat Detection Engineering**: Develop high-fidelity SPL search queries for cloud security incident detection.
3. **MITRE ATT&CK Alignment**: Correlate alert patterns to industry-standard adversary tactics and techniques.
4. **Analyst Dashboarding**: Provide visual real-time metrics for failed logins, privilege escalations, and network port scanning.

---

## 🏗️ Detection Coverage (MITRE ATT&CK Mappings)

| Technique ID | Technique Name | SPL Query File | Severity | Description |
|---|---|---|---|---|
| **`T1110`** | Brute Force | `queries/mitre_attack_rules.spl` | **HIGH** | Detects >=5 failed console login attempts in a 5-minute window. |
| **`T1078`** | Valid Accounts | `queries/mitre_attack_rules.spl` | **CRITICAL** | Flags successful Root/Admin logins without Multi-Factor Authentication (MFA). |
| **`T1098`** | Account Manipulation | `queries/mitre_attack_rules.spl` | **CRITICAL** | Detects attachment of `AdministratorAccess` policies to unprivileged IAM entities. |
| **`T1530`** | Cloud Storage Discovery | `queries/mitre_attack_rules.spl` | **HIGH** | Alerts on S3 bucket ACL changes disabling public access blocks. |
| **`T1046`** | Network Scanning | `queries/mitre_attack_rules.spl` | **MEDIUM** | Flags IP scanning >25 rejected destination ports in VPC Flow Logs. |

---

## 📂 Repository Structure

```
splunk-soc-aws-cloudtrail-lab/
├── queries/
│   └── mitre_attack_rules.spl    # Splunk SPL detection queries with severity & technique tags
├── sample_logs/
│   └── aws_cloudtrail_sample.json # Sanitized simulated attack logs for lab testing
├── dashboards/
│   └── soc_overview.xml          # Splunk XML dashboard source
└── README.md                     # Architecture, detection logic & playbooks
```

---

## 🚀 Lab Deployment Steps

### 1. Ingest Sample Logs into Splunk
- In Splunk Enterprise: **Settings** ➔ **Add Data** ➔ **Upload**.
- Select `sample_logs/aws_cloudtrail_sample.json`.
- Set source type to `aws:cloudtrail` and index to `aws_cloudtrail`.

### 2. Import XML Dashboard
- In Splunk Search & Reporting: **Dashboards** ➔ **Create New Dashboard**.
- Click **Edit Source** and paste the contents of `dashboards/soc_overview.xml`.

---

## 📬 Contact

- **Author**: Parth Pandey ([@ParthPandey25](https://github.com/ParthPandey25))
- **Email**: parthrspandey25@gmail.com
- **LinkedIn**: [linkedin.com/in/parth-pandey-045709258](https://www.linkedin.com/in/parth-pandey-045709258/)
