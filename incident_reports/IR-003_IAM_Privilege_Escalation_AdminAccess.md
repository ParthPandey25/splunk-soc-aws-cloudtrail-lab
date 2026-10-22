# 🚨 Incident Response Report: IR-003
**Incident Title**: Unauthorized IAM Privilege Escalation via AdministratorAccess Policy Attachment  
**Severity**: CRITICAL  
**Framework**: NIST SP 800-61 Rev. 2 / NIST Cybersecurity Framework (CSF)  
**Lead Investigator**: Parth Pandey (@ParthPandey25)  
**Date Logged**: 2026-09-28 | **Status**: Closed (Eradicated & Enforced)  

---

## 1. 🛡️ Phase 1: Preparation & Detection Baseline

- **Alert Source**: Splunk SIEM Detection Rule `CR-03` (MITRE ATT&CK `T1098 - Account Manipulation`)
- **Telemetry Ingested**: AWS CloudTrail Management Events (`iam.amazonaws.com`)
- **Detection Query**:
  ```spl
  index=aws_cloudtrail eventName IN ("AttachUserPolicy", "AttachRolePolicy", "PutUserPolicy", "PutRolePolicy", "CreatePolicyVersion")
  | search requestParameters.policyArn="*AdministratorAccess*" OR requestParameters.policyDocument="*\"Action\": \"*\"*"
  ```
- **Trigger Condition**: Immediate attachment of `arn:aws:iam::aws:policy/AdministratorAccess` to standard developer identity `dev_intern`.

---

## 2. 🔍 Phase 2: Detection, Scoping & Forensic Analysis

### 2.1 Timeline of Events

| Timestamp (UTC) | Event Name | Invoking Principal | Target Identity | Source IP | Action Observed |
|---|---|---|---|---|---|
| 2026-09-28 14:02:18 | `AssumeRole` | `stolen-developer-key` | `Role-DeploymentHelper` | `198.51.100.45` | Adversary assumed overly permissive deployment role |
| 2026-09-28 14:03:05 | `AttachUserPolicy` | `Role-DeploymentHelper` | `dev_intern` | `198.51.100.45` | Attached AWS-managed `AdministratorAccess` policy |
| 2026-09-28 14:04:12 | `CreateAccessKey` | `dev_intern` | `dev_intern` | `198.51.100.45` | Generated permanent secondary API access keys |
| 2026-09-28 14:05:40 | `StopLogging` | `dev_intern` | `arn:aws:cloudtrail:...:trail/org-security-trail` | `198.51.100.45` | Attempted defense evasion (flagged by Rule `CR-07`) |

### 2.2 Attack Analysis & TTP Correlation
- **Initial Vector**: Developer programmatic access keys compromised via public GitHub code commit.
- **Privilege Escalation (`T1098`)**: Used helper deployment role containing `iam:AttachUserPolicy` wildcard permissions to self-elevate to administrative control.
- **Defense Evasion (`T1562.001`)**: Attempted execution of `StopLogging` to disable forensic trace logging.
- **IoCs**: Source IP `198.51.100.45` (DigitalOcean VPS used as adversarial proxy).

---

## 3. 🛑 Phase 3: Containment, Eradication & Recovery

1. **Immediate Revocation (Containment)**:
   - Detached `AdministratorAccess` policy from `dev_intern`:
     ```bash
     aws iam detach-user-policy \
         --user-name dev_intern \
         --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
     ```
   - Inactivated the compromised access key:
     ```bash
     aws iam update-access-key --access-key-id AKIAEXAMPLESTOLENKEY --status Inactive --user-name dev_intern
     ```
2. **Defensive Re-activation (Recovery)**:
   - Re-enabled and verified CloudTrail stream state using `aws cloudtrail start-logging`.
   - Replaced `Role-DeploymentHelper` policy with strict least-privilege scoping (limiting actions strictly to `s3:PutObject` on build artifact buckets).

---

## 4. 📈 Phase 4: Post-Incident Activity & Detection Tuning

- **Root Cause**: Overly permissive IAM role (`iam:AttachUserPolicy` with `Resource: "*"`) allowed horizontal privilege escalation.
- **Detection Engineering Improvement**:
  - Implemented Splunk correlation alert linking `AttachUserPolicy` directly to secondary persistence actions (`CreateAccessKey`, `CreateUser`) within a 15-minute window.
  - Deployed AWS IAM Access Analyzer to continuously alert on policy findings granting full administrative power.
