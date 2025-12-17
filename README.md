# SOC 2 Evidence Automator

## 📌 Overview
A collection of Python (Boto3) scripts designed to automate the collection of audit evidence for **SOC 2 Type 2** and **HIPAA** audits.

**The Problem:** Manual screenshots of AWS consoles are brittle, time-consuming, and prone to human error.
**The Solution:** Automated scripts that query infrastructure APIs and generate timestamped, auditable logs (CSV) for external auditors.

## 📂 Included Modules

| Audit Script | Description | SOC 2 Mapping |
| :--- | :--- | :--- |
| [`/scripts/s3_encryption_check.py`](scripts/s3_encryption_check.py) | Scans all S3 buckets to verify Server-Side Encryption (SSE) is enabled. Outputs a `PASS/FAIL` CSV report. | **CC6.1** (Encryption at Rest) |
| [`/scripts/iam_access_review.py`](scripts/iam_access_review.py) | Identifies IAM users with `PasswordLastUsed` > 90 days. Used for quarterly access reviews. | **CC6.2** (User Access Review) |

## 🚀 How to Run
1.  Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```
2.  Export AWS Credentials (Read-Only access is sufficient):
    ```bash
    export AWS_ACCESS_KEY_ID=...
    export AWS_SECRET_ACCESS_KEY=...
    ```
3.  Run the audit:
    ```bash
    python scripts/s3_encryption_check.py
    ```

## ⚠️ Disclaimer
*Note: These scripts are sanitized versions of production code used in live audits. Ensure your IAM role has `SecurityAudit` or `ViewOnlyAccess` permissions.*

---
*Maintained by [Cody Keller](https://github.com/codyjkeller)*
