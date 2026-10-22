# 🚨 Incident Response Report: IR-001
**Incident Title**: Unauthorized AWS Root Account Console Login without MFA  
**Severity**: CRITICAL  
**Framework**: NIST SP 800-61 Rev. 2 / NIST Cybersecurity Framework (CSF)  
**Lead Investigator**: Parth Pandey (@ParthPandey25)  
**Date Logged**: 2026-09-02 | **Status**: Closed (Resolved & Remediated)  

---

## 1. 🛡️ Phase 1: Preparation & Detection Baseline

- **Alert Source**: Splunk SIEM Detection Rule `CR-02` (MITRE ATT&CK `T1078 - Valid Accounts`)
- **Telemetry Ingested**: AWS CloudTrail Management Events via Splunk Add-on for AWS
- **Detection Query**:
  ```spl
  index=aws_cloudtrail eventName=ConsoleLogin "responseElements.ConsoleLogin=Success"
  | where 'additionalEventData.MFAUsed'="No" OR 'userIdentity.type'="Root"
  ```
- **Trigger Condition**: ConsoleLogin event with `userIdentity.type="Root"` and `additionalEventData.MFAUsed="No"`.

---

## 2. 🔍 Phase 2: Detection, Scoping & Forensic Analysis

### 2.1 Timeline of Events

| Timestamp (UTC) | Event Name | User Identity | Source IP | User-Agent | Action Observed |
|---|---|---|---|---|---|
| 2026-09-02 04:12:01 | `ConsoleLogin` | `Root` (123456789012) | `203.0.113.88` | Mozilla/5.0 (Windows NT 10.0; Win64; x64) | Successful authentication without MFA token challenge |
| 2026-09-02 04:14:15 | `GetAccountSummary` | `Root` | `203.0.113.88` | aws-cli/2.15.0 Python/3.11 | IAM configuration and quota enumeration |
| 2026-09-02 04:16:30 | `CreateUser` | `Root` | `203.0.113.88` | aws-cli/2.15.0 Python/3.11 | Created backdoor IAM user `svc_backup_agent` |
| 2026-09-02 04:17:02 | `CreateAccessKey` | `Root` | `203.0.113.88` | aws-cli/2.15.0 Python/3.11 | Generated programmatic API credentials |

### 2.2 Indicators of Compromise (IoCs)
- **External Rogue IP**: `203.0.113.88` (Unrecognized ASN, non-VPN IP space)
- **Created Malicious Identity**: `arn:aws:iam::123456789012:user/svc_backup_agent`
- **Compromised Access Key ID**: `AKIAIOSFODNN7EXAMPLE`
- **ATT&CK TTPs**: `T1078` (Valid Accounts), `T1087` (Account Discovery), `T1136.003` (Create Account)

---

## 3. 🛑 Phase 3: Containment, Eradication & Recovery

1. **Immediate Session Termination (Containment)**:
   - Attached inline Deny-All IAM policy to Root account context.
   - Revoked all active AWS console sessions for Root via AWS CLI:
     ```bash
     aws iam put-account-password-policy --minimum-password-length 14 --require-symbols --require-numbers
     ```
2. **Backdoor Eradication**:
   - Disabled and deleted the rogue user `svc_backup_agent` and deleted its associated access key `AKIAIOSFODNN7EXAMPLE`.
3. **Root Account Hardening (Recovery)**:
   - Rotated the Root account master password (randomized 32-character passphrase).
   - Enforced hardware FIDO2 / YubiKey Multi-Factor Authentication (MFA) on the Root user.
   - Verified no further persistence mechanisms (Lambda functions, EC2 instances, or STS trust relationships) were created during the active window.

---

## 4. 📈 Phase 4: Post-Incident Activity & Detection Tuning

- **Root Cause**: Compromised root credentials leaked in a deprecated environment script without MFA enforcement.
- **Tuning Splunk Detection Rules**:
  - Configured high-priority PagerDuty webhook on detection rule `CR-02` for sub-minute SLA notification.
  - Added geofencing logic in Splunk to flag console logins outside of designated corporate geo-regions.
- **Architectural Policy Implemented**: AWS Service Control Policy (SCP) attached to AWS Organizations root denying non-emergency interactive logins using Root credentials.
