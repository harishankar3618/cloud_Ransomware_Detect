import os
import smtplib
import json
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

RECEIPT_EMAIL_FILE = "receipt_email.txt"
with open('/var/www/cloud_Ransomware_Detect/Project/config.json') as config_file:
    config = json.load(config_file)

sender_email = config['SENDER_EMAIL']
sender_password = config['SENDER_PASSWORD']

def load_receipt_email():
    """Load the receipt email from the file"""
    if os.path.exists(RECEIPT_EMAIL_FILE):
        with open(RECEIPT_EMAIL_FILE, 'r') as f:
            receipt_email = f.read().strip()
            return receipt_email
    else:
        return None

def store_receipt_email(receipt_email):
    """Store the receipt email in the file"""
    with open(RECEIPT_EMAIL_FILE, 'w') as f:
        f.write(receipt_email)

def check_and_store_receipt_email():
    receipt_email = load_receipt_email()
    if not receipt_email:
        print("Receipt email not found. Please enter the receipt email:")
        receipt_email = input("Enter the receipt email: ").strip()
        store_receipt_email(receipt_email)  # Store the receipt email in the file
        print("Receipt email saved.")
    return receipt_email

def send_mail(receipt_email,body):
    """Send an email alert for detected malware during the scan"""
    try:
        # Email subject and body
        subject = "Malware Scan Result"
        # Create the email components
        message = MIMEMultipart()
        message['From'] = sender_email
        message['To'] = receipt_email
        message['Subject'] = subject

        # Attach the email body
        message.attach(MIMEText(body, 'plain'))

        # Connect to the Gmail SMTP server
        with smtplib.SMTP('smtp.zoho.com', 465) as server:
            server.starttls()  # Start TLS encryption
            server.login(sender_email, sender_password)  # Log in to the server
            server.sendmail(sender_email, receipt_email, message.as_string())  # Send the email

        print("Check mail for results")

    except Exception as e:
        print(f"Failed to send malware alert email: {e}")




