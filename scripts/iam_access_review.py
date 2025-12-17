import boto3
from datetime import datetime, timezone

def audit_stale_users(days_threshold=90):
    """
    SOC 2 Control CC6.2: Identifies IAM users who haven't logged in 
    for >90 days to support quarterly access reviews.
    """
    iam = boto3.client('iam')
    users = iam.list_users()
    
    print(f"Starting Access Review (Threshold: {days_threshold} days)...")
    
    for user in users['Users']:
        username = user['UserName']
        last_login = user.get('PasswordLastUsed')
        
        if last_login:
            # Calculate days since last login
            days_inactive = (datetime.now(timezone.utc) - last_login).days
            status = "ACTIVE" if days_inactive < days_threshold else "STALE"
            
            if status == "STALE":
                print(f"[ALERT] User {username} is inactive for {days_inactive} days. Recommendation: REVOKE.")
        else:
            print(f"[WARN] User {username} has never logged in (likely API-only or abandoned).")

if __name__ == "__main__":
    audit_stale_users()
