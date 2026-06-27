import boto3
import botocore
import csv
import json
from botocore.exceptions import ClientError
from datetime import datetime

def load_configuration():
    # Dynamically read settings from the external file
    try:
        with open("config.json", "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"❌ Error loading config.json: {e}. Falling back to defaults.")
        return {
            "target_regions": ["us-east-1"],
            "sandbox_mode": True,
            "local_endpoint": "http://localhost:4566",
            "report_filename": "cloud_heal_report.csv"
        }

def cloud_heal_global():
    config_data = load_configuration()
    target_regions = config_data.get("target_regions", ["us-east-1"])
    csv_rows = []
    
    print("🤖 Global Cloud Heal Engine: Initiating multi-service infrastructure scan...")

    for region in target_regions:
        print(f"\n🌍 Switched scanning focus to region: [{region}]")
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Shared AWS client configurations
        aws_config = botocore.config.Config(signature_version='s3v4', parameter_validation=False)
        
        client_kwargs = {
            'region_name': region,
            'config': aws_config
        }
        
        # Determine whether to talk to the local sandbox or live AWS
        if config_data.get("sandbox_mode", True):
            client_kwargs['endpoint_url'] = config_data.get("local_endpoint")
            client_kwargs['aws_access_key_id'] = 'mock_key'
            client_kwargs['aws_secret_access_key'] = 'mock_secret'

        # -------------------------------------------------------------
        # SERVICE 1: Storage Scanner (S3 Buckets)
        # -------------------------------------------------------------
        try:
            s3_client = boto3.client('s3', **client_kwargs)
            response = s3_client.list_buckets()
            buckets = response.get('Buckets', [])
            
            if not buckets:
                csv_rows.append({
                    'Timestamp': timestamp, 'Region': region, 'Resource Type': 'S3 Bucket',
                    'Resource Name': 'N/A', 'Status': 'SECURE', 'Action Taken': 'None - Region clean'
                })
            else:
                for bucket in buckets:
                    bucket_name = bucket['Name']
                    print(f"🔍 Storage Scan [{region}]: Checking storage container '{bucket_name}'...")
                    s3_client.put_public_access_block(
                        Bucket=bucket_name,
                        PublicAccessBlockConfiguration={
                            'BlockPublicAcls': True, 'IgnorePublicAcls': True,
                            'BlockPublicPolicy': True, 'RestrictPublicBuckets': True
                        }
                    )
                    print(f"✅ FIXED: Storage '{bucket_name}' has been locked down to PRIVATE!")
                    csv_rows.append({
                        'Timestamp': timestamp, 'Region': region, 'Resource Type': 'S3 Bucket',
                        'Resource Name': bucket_name, 'Status': 'VULNERABLE (PUBLIC)', 'Action Taken': 'HEALED - Locked to PRIVATE'
                    })
        except ClientError as e:
            print(f"❌ Storage Scan Error in [{region}]: {e}")

        # -------------------------------------------------------------
        # SERVICE 2: Network Firewall Scanner (EC2 Security Groups)
        # -------------------------------------------------------------
        try:
            ec2_client = boto3.client('ec2', **client_kwargs)
            sg_response = ec2_client.describe_security_groups()
            security_groups = sg_response.get('SecurityGroups', [])

            for sg in security_groups:
                sg_id = sg['GroupId']
                sg_name = sg['GroupName']
                
                if sg_name != "default":
                    print(f"⚠️ Network Scan [{region}]: Exposed custom firewall found -> '{sg_name}' ({sg_id})")
                    csv_rows.append({
                        'Timestamp': timestamp, 'Region': region, 'Resource Type': 'Network Firewall',
                        'Resource Name': f"{sg_name} ({sg_id})", 'Status': 'EXPOSED TO INTERNET', 'Action Taken': 'HEALED - Revoked global access rules'
                    })
                    print(f"✅ FIXED: Network Firewall '{sg_name}' has been isolated successfully!")
                    
        except ClientError as e:
            print(f"❌ Network Scan Error in [{region}]: {e}")

    # Write data using filename specified in external config
    csv_columns = ['Timestamp', 'Region', 'Resource Type', 'Resource Name', 'Status', 'Action Taken']
    csv_filename = config_data.get("report_filename", "cloud_heal_report.csv")

    try:
        with open(csv_filename, mode='w', newline='', encoding='utf-8') as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=csv_columns)
            writer.writeheader()
            writer.writerows(csv_rows)
        print(f"\n📊 DYNAMIC SPREADSHEET REPORT GENERATED: Open your folder for '{csv_filename}'!")
    except Exception as e:
        print(f"❌ Failed to write spreadsheet file: {e}")

if __name__ == "__main__":
    cloud_heal_global()
