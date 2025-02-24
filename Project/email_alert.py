import sys
import smtplib
import json
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

with open('/var/www/cloud_Ransomware_Detect/Project/config.json') as config_file:
    config = json.load(config_file)

sender_email = config['SENDER_EMAIL']
sender_password = config['SENDER_PASSWORD']

def send_mail(receipt_email,result):
    """Send an email alert for detected malware during the scan"""
    try:
        # Email subject and body
        subject = "Malware Scan Result"
        body = f"""Dear User,

The recent malware scan has been completed. check the results:

{result}
Best regards,
Team Ransomewatch"""
        # Create the email components
        message = MIMEMultipart()
        message['From'] = sender_email
        message['To'] = receipt_email
        message['Subject'] = subject

        # Attach the email body
        message.attach(MIMEText(body, 'plain'))

        # Connect to the Gmail SMTP server
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()  # Start TLS encryption
            server.login(sender_email, sender_password)  # Log in to the server
            server.sendmail(sender_email, receipt_email, message.as_string())  # Send the email

        print("Check mail for results")

    except Exception as e:
        print(f"Failed to send malware alert email: {e}")

if __name__ == "__main__":
    result = sys.argv[1]
    receipt_email = sys.argv[2]
    send_mail(receipt_email, result)


