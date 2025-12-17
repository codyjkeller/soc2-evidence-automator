import boto3
import csv
from datetime import datetime

def audit_s3_encryption():
    """
    SOC 2 Control CC6.1: Verifies all S3 buckets have Server-Side Encryption (SSE) enabled.
    Generates a CSV report for audit evidence.
    """
    s3 = boto3.client('s3')
    response = s3.list_buckets()
    
    audit_date = datetime.now().strftime("%Y-%m-%d")
    report_file = f"evidence_s3_encryption_{audit_date}.csv"
    
    print(f"Starting S3 Encryption Audit - {audit_date}")
    
    with open(report_file, 'w', newline='') as csvfile:
        fieldnames = ['BucketName', 'EncryptionStatus', 'Algorithm', 'ComplianceCheck']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        
        for bucket in response['Buckets']:
            name = bucket['Name']
            try:
                enc = s3.get_bucket_encryption(Bucket=name)
                rules = enc['ServerSideEncryptionConfiguration']['Rules']
                algo = rules[0]['ApplyServerSideEncryptionByDefault']['SSEAlgorithm']
                status = "ENCRYPTED"
                check = "PASS"
            except Exception:
                status = "NOT_ENCRYPTED"
                algo = "NONE"
                check = "FAIL"
            
            writer.writerow({
                'BucketName': name,
                'EncryptionStatus': status,
                'Algorithm': algo,
                'ComplianceCheck': check
            })
            print(f"Checked {name}: {check}")

    print(f"Audit Complete. Evidence saved to {report_file}")

if __name__ == "__main__":
    # Note: Ensure AWS_ACCESS_KEY_ID is set in environment variables before running.
    audit_s3_encryption()
