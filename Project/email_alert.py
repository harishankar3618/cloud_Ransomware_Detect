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
        body = f'''
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Ransomewatch - Scan Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; background-color: #f4f4f4; margin: 0; padding: 0; }}
                .container {{ max-width: 600px; margin: 20px auto; background: #ffffff; padding: 20px; border-radius: 8px; box-shadow: 0 0 10px rgba(0, 0, 0, 0.1); }}
                h1 {{ color: #00ffcc; text-align: center; }}
                p {{ font-size: 14px; color: #333; }}
                .result-box {{ background: #f8f8f8; padding: 15px; border-left: 4px solid #00ffcc; margin-top: 10px; }}
                .footer {{ text-align: center; font-size: 12px; color: #666; margin-top: 20px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Ransomewatch</h1>
                <p>Dear User,</p>
                <p>The recent malware scan has been completed. Please review the results below:</p>
                <div class="result-box">
                    <pre>{result}</pre>
                </div>
                <p>Best regards,<br>Team Ransomewatch</p>
                <p class="footer">This is an automated email. Please do not reply.</p>
            </div>
        </body>
        </html>
        '''
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


