import sys
import smtplib
import json
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

with open('/var/www/cloud_Ransomware_Detect/Project/config.json') as config_file:
    config = json.load(config_file)

sender_email = config['SENDER_EMAIL']
sender_password = config['SENDER_PASSWORD']

def send_mail(receipt_email, result):
    """Send an email alert for detected malware during the scan"""
    try:
        # Email subject and body
        subject = "Ransomewatch - Malware Scan Alert"
        body = f'''
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Ransomewatch - Malware Scan Report</title>
            <link href="https://fonts.googleapis.com/css2?family=Russo+One&display=swap" rel="stylesheet">
            <style>
                body {{
                    font-family: 'Russo One', sans-serif;
                    background: #0e0e0e;
                    color: #fff;
                    margin: 0;
                    padding: 0;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                }}

                .email-container {{
                    max-width: 600px;
                    width: 100%;
                    margin: 20px auto;
                    background: rgba(255, 255, 255, 0.1);
                    backdrop-filter: blur(10px);
                    border-radius: 15px;
                    padding: 25px;
                    box-shadow: 0 8px 20px rgba(0, 0, 0, 0.5);
                    text-align: center;
                }}

                .email-header {{
                    font-size: 24px;
                    color: #00ffcc;
                    margin-bottom: 10px;
                }}

                .email-body {{
                    font-size: 16px;
                    line-height: 1.5;
                    color: #ddd;
                }}

                .scan-results {{
                    margin-top: 15px;
                    padding: 15px;
                    background: rgba(255, 255, 255, 0.1);
                    border-radius: 10px;
                    text-align: left;
                }}

                .scan-results h2 {{
                    color: #00ffcc;
                    font-size: 18px;
                    margin-bottom: 10px;
                }}

                .scan-results pre {{
                    background: rgba(0, 255, 204, 0.2);
                    padding: 10px;
                    border-radius: 5px;
                    color: #fff;
                    white-space: pre-wrap;
                    word-wrap: break-word;
                    max-height: 300px;
                    overflow-y: auto;
                }}

                .footer {{
                    margin-top: 20px;
                    font-size: 14px;
                    color: #888;
                    border-top: 1px solid rgba(0, 255, 204, 0.2);
                    padding-top: 10px;
                }}

                .button {{
                    display: inline-block;
                    margin-top: 15px;
                    padding: 12px 20px;
                    background: linear-gradient(135deg, #00ffcc, #019c82);
                    border-radius: 8px;
                    color: white;
                    text-decoration: none;
                    font-size: 16px;
                    transition: 0.3s ease-in-out;
                }}

                .button:hover {{
                    background: linear-gradient(135deg, #138673, #0d5a4d);
                    transform: scale(1.05);
                }}
            </style>
        </head>
        <body>
            <div class="email-container">
                <h1 class="email-header">Ransomewatch - Malware Scan Report</h1>
                <p class="email-body">
                    Hello,<br><br>
                    We've completed a scan of your files and detected potential security risks.
                </p>
                <div class="scan-results">
                    <h2>Detailed Scan Results</h2>
                    <pre>{result}</pre>
                </div>
                <div class="footer">
                    <p>© Ransomewatch | Automated Security Scan</p>
                    <p>This is an automated email. Please do not reply.</p>
                </div>
            </div>
        </body>
        </html>'''

        # Create the email components
        message = MIMEMultipart()
        message['From'] = sender_email
        message['To'] = receipt_email
        message['Subject'] = subject

        # Attach the email body
        message.attach(MIMEText(body, 'html'))

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
