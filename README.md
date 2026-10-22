# 🛡️ Home SOC Lab: Splunk SIEM & AWS CloudTrail Monitoring

> **Enterprise-grade Cloud SOC Detection Engineering Lab**: Ingests AWS CloudTrail and VPC Flow Logs into Splunk Enterprise with 12 custom SPL detection rules mapped across 8 MITRE ATT&CK techniques, validated against simulated cloud attacks with incident response playbooks adhering to the NIST Cybersecurity Framework (CSF).

[![Splunk](https://img.shields.io/badge/Splunk-Enterprise%209.x-000000?logo=splunk&logoColor=white)](https://splunk.com)
[![AWS CloudTrail](https://img.shields.io/badge/AWS-CloudTrail-FF9900?logo=amazonwebservices&logoColor=white)](https://aws.amazon.com/cloudtrail/)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK%20v14-red.svg)](https://attack.mitre.org)
[![NIST CSF](https://img.shields.io/badge/NIST-SP%20800--61%20Rev2-blue.svg)](https://csrc.nist.gov/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

---

## 🏛️ Cloud SOC Lab Architecture

```
                          ┌──────────────────────────────────────┐
                          │         AWS Cloud Infrastructure     │
                          │                                      │
                          │  [IAM]      [S3 Buckets]   [VPC Flow]│
                          │     │             │             │    │
                          │     ▼             ▼             ▼    │
                          │  AWS CloudTrail Management Audit Logs │
                          └──────────────────┬───────────────────┘
                                             │ (S3 / CloudWatch Export)
                                             ▼
                          ┌──────────────────────────────────────┐
                          │    Splunk Universal Forwarder / Addon│
                          │      Index: index=aws_cloudtrail     │
                          └──────────────────┬───────────────────┘
                                             │
                                             ▼
                          ┌──────────────────────────────────────┐
                          │       Splunk Enterprise SIEM         │
                          │  - 12 Custom MITRE ATT&CK SPL Rules  │
                          │  - Real-Time Alert Engine            │
                          │  - Executive & Analyst Dashboards    │
                          └──────────────────┬───────────────────┘
                                             │
                        ┌────────────────────┴────────────────────┐
                        ▼                                         ▼
            ┌──────────────────────┐                  ┌──────────────────────┐
            │   Alert Triage &     │                  │  NIST CSF Incident   │
            │   Threshold Tuning   │                  │  Remediation Reports │
            │  (40% FP Reduction)  │                  │  (IR-01, 02, 03)     │
            └──────────────────────┘                  └──────────────────────┘
```

---

## 🎯 Detection Engineering Matrix (12 Rules Across 8 ATT&CK Techniques)

All queries are defined and ready to execute in [`queries/mitre_attack_rules.spl`](queries/mitre_attack_rules.spl).

| # | Technique ID | MITRE Technique Name | Detection Name | Severity | Primary Data Source |
|---|---|---|---|---|---|
| **1** | **`T1110`** | Brute Force | Excessive Console Login Failures (>=5 in 5m) | **HIGH** | `aws:cloudtrail` (`ConsoleLogin`) |
| **2** | **`T1078`** | Valid Accounts | Root Console Login Without MFA | **CRITICAL** | `aws:cloudtrail` (`ConsoleLogin`) |
| **3** | **`T1098`** | Account Manipulation | IAM Privilege Escalation (`AdministratorAccess`) | **CRITICAL** | `aws:cloudtrail` (`AttachUserPolicy`) |
| **4** | **`T1530`** | Cloud Storage Discovery | S3 Public Exposure (Public Access Block Removed) | **HIGH** | `aws:cloudtrail` (`PutBucketAcl`) |
| **5** | **`T1046`** | Network Service Scanning | Port Sweep Detection (>25 Rejected Ports) | **MEDIUM** | `aws:vpc:flow` (`action=REJECT`) |
| **6** | **`T1136.003`** | Create Cloud Account | Unauthorized IAM User & API Access Key Created | **HIGH** | `aws:cloudtrail` (`CreateUser`) |
| **7** | **`T1562.001`** | Impair Defenses | Defense Evasion via CloudTrail Logging Halt | **CRITICAL** | `aws:cloudtrail` (`StopLogging`) |
| **8** | **`T1021`** | Remote Services | Security Group Ingress Permitting 0.0.0.0/0 on 22/3389 | **HIGH** | `aws:cloudtrail` (`AuthorizeSecurityGroupIngress`) |
| **9** | **`T1070.004`** | Indicator Removal | Forensic Log Eradication (DeleteLogGroup/Stream) | **HIGH** | `aws:cloudtrail` (`DeleteLogGroup`) |
| **10** | **`T1087.004`** | Cloud Account Discovery | High-Frequency IAM Enumeration Burst | **MEDIUM** | `aws:cloudtrail` (`ListUsers`, `GetAccountSummary`) |
| **11** | **`T1528`** | Steal Application Token | Untrusted Cross-Account STS AssumeRole Request | **HIGH** | `aws:cloudtrail` (`AssumeRole`) |
| **12** | **`T1059.009`** | Cloud Command Execution | Remote SSM RunCommand / CloudShell Execution | **HIGH** | `aws:cloudtrail` (`SendCommand`, `StartSession`) |

---

## 🧪 Threat Simulation & Validation Metrics

To measure detection efficacy, simulated attack scenarios were executed against the lab using Atomic Red Team tests and AWS CLI payloads:

- **Total Attack Scenarios Simulated**: 20 attacks across CloudTrail & VPC Flow Logs.
- **Successful True Positives Detected**: 18 / 20 (90% initial catch rate).
- **False-Positive Tuning**:
  - Whitelisted benign automated Terraform deployment service roles and read-only monitoring pipelines in Splunk lookup tables.
  - Tuned time-window thresholds (`span=5m`, `distinct_ports >= 25`), reducing false-positive alert volume by **40%**.

---

## 📑 NIST CSF Incident Response Reports

Formal incident investigation reports following NIST SP 800-61 Rev. 2 guidelines:

1. [**IR-001: Unauthorized Root Console Login Without MFA**](incident_reports/IR-001_Root_Login_No_MFA.md) *(CRITICAL)*
2. [**IR-002: S3 Bucket Public Exposure & Potential Data Leak**](incident_reports/IR-002_S3_Bucket_Public_Exposure.md) *(HIGH)*
3. [**IR-003: IAM Privilege Escalation via AdministratorAccess Attachment**](incident_reports/IR-003_IAM_Privilege_Escalation_AdminAccess.md) *(CRITICAL)*

---

## 📂 Repository Layout

```
splunk-soc-aws-cloudtrail-lab/
├── queries/
│   └── mitre_attack_rules.spl       # 12 production SPL detection queries
├── sample_logs/
│   └── aws_cloudtrail_sample.json   # Multi-vector simulated attack events for ingest testing
├── dashboards/
│   └── soc_overview.xml             # Complete Splunk XML dashboard source
├── incident_reports/
│   ├── IR-001_Root_Login_No_MFA.md
│   ├── IR-002_S3_Bucket_Public_Exposure.md
│   └── IR-003_IAM_Privilege_Escalation_AdminAccess.md
└── README.md                        # Architecture, detection matrix & NIST playbooks
```

---

## 🚀 Deployment & Usage

### 1. Ingest Sample Logs into Splunk
1. In Splunk Web, navigate to **Settings** ➔ **Add Data** ➔ **Upload**.
2. Select `sample_logs/aws_cloudtrail_sample.json`.
3. Set Sourcetype to `aws:cloudtrail` and Index to `aws_cloudtrail`.

### 2. Load the Analyst Dashboard
1. Go to **Search & Reporting** ➔ **Dashboards** ➔ **Create New Dashboard**.
2. Switch to **Edit Source** mode, paste [`dashboards/soc_overview.xml`](dashboards/soc_overview.xml), and click **Save**.

---

## 📬 Contact

- **Author**: Parth Pandey ([@ParthPandey25](https://github.com/ParthPandey25))
- **Portfolio**: [portfolio-parthpandey.vercel.app](https://portfolio-parthpandey.vercel.app/)
- **LinkedIn**: [linkedin.com/in/parth-pandey-045709258](https://www.linkedin.com/in/parth-pandey-045709258/)
