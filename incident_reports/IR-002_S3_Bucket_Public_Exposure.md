# 🚨 Incident Response Report: IR-002
**Incident Title**: Accidental S3 Bucket Public ACL Exposure & Sensitive Data Leak Risk  
**Severity**: HIGH  
**Framework**: NIST SP 800-61 Rev. 2 / NIST Cybersecurity Framework (CSF)  
**Lead Investigator**: Parth Pandey (@ParthPandey25)  
**Date Logged**: 2026-09-14 | **Status**: Closed (Remediated & Verified)  

---

## 1. 🛡️ Phase 1: Preparation & Detection Baseline

- **Alert Source**: Splunk SIEM Detection Rule `CR-04` (MITRE ATT&CK `T1530 - Cloud Storage Discovery`)
- **Telemetry Ingested**: AWS CloudTrail Object-Level and S3 Management Events
- **Detection Query**:
  ```spl
  index=aws_cloudtrail eventName IN ("PutBucketAcl", "PutBucketPolicy", "PutBucketPublicAccessBlock", "DeleteBucketPublicAccessBlock")
  | search requestParameters.PublicAccessBlockConfiguration.BlockPublicAcls=false 
        OR requestParameters.PublicAccessBlockConfiguration.BlockPublicPolicy=false
        OR eventName="DeleteBucketPublicAccessBlock"
  ```
- **Trigger Condition**: Disabling of `BlockPublicAcls` or `BlockPublicPolicy` on bucket `corp-financial-records-archive`.

---

## 2. 🔍 Phase 2: Detection, Scoping & Forensic Analysis

### 2.1 Timeline of Events

| Timestamp (UTC) | Event Name | User Identity | Source IP | Bucket Targeted | Action Observed |
|---|---|---|---|---|---|
| 2026-09-14 11:20:10 | `PutBucketAcl` | `arn:aws:iam::123456789012:user/dev_contractor` | `198.51.100.12` | `corp-financial-records-archive` | Modified ACL to `public-read` to test file hosting |
| 2026-09-14 11:20:12 | `DeleteBucketPublicAccessBlock` | `dev_contractor` | `198.51.100.12` | `corp-financial-records-archive` | Removed AWS account S3 public access block override |
| 2026-09-14 11:22:04 | `GetObject` | `Anonymous / Unauthenticated` | `185.220.101.5` | `.../q3_earnings_prelim.csv` | External automated cloud scanner downloaded document |

### 2.2 Scoping & Impact Analysis
- **Target Bucket**: `corp-financial-records-archive` containing 14 archive documents.
- **Exposure Window**: 8 minutes and 32 seconds between modification and automated SOC containment.
- **External Download Observed**: IP `185.220.101.5` (Known Tor exit node scanning for misconfigured S3 buckets).
- **ATT&CK TTPs**: `T1530` (Data from Cloud Storage Object), `T1562.001` (Disable Cloud Storage Protections)

---

## 3. 🛑 Phase 3: Containment, Eradication & Recovery

1. **Automated Containment Execution**:
   - Splunk triggered an AWS CLI automated remediation webhook enabling S3 Public Access Block immediately:
     ```bash
     aws s3api put-public-access-block \
         --bucket corp-financial-records-archive \
         --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
     ```
2. **Access Control Reset (Eradication)**:
   - Restored bucket ACL to `private`.
   - Revoked `s3:PutBucketAcl` and `s3:PutBucketPolicy` permissions from `dev_contractor` role.
3. **Audit & Verification (Recovery)**:
   - Executed AWS CLI audit across all regional S3 buckets to confirm 100% compliance with organizational Block Public Access policies.

---

## 4. 📈 Phase 4: Post-Incident Activity & Detection Tuning

- **Root Cause**: Developer attempting to serve static test assets without understanding enterprise zero-trust cloud posture.
- **SPL Detection Tuning**:
  - Enhanced rule `CR-04` with a real-time email dispatch to the cloud infrastructure lead.
  - Implemented an AWS IAM Permission Boundary preventing junior roles from altering `s3:PutBucketPublicAccessBlock`.
- **False Positive Reduction**: Whitelisted designated public documentation buckets (`corp-public-branding-*`) in the Splunk lookup table, cutting non-malicious false-positive alerts by 40%.
