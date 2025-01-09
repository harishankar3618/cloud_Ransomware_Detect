import sys
import os
import logging
from scanner import YaraScanner
from email_alert import send_mail

# Configure logging
logging.basicConfig(
    level=logging.INFO,  # Set the log level to INFO to capture normal events and errors
    format="%(asctime)s - %(levelname)s - %(message)s",  # Format the log entries
    handlers=[
        logging.FileHandler("yara_scanner.log"),  # Log to file
        logging.StreamHandler()  # Also log to console
    ]
)

def detect_malware(file_path, receipt_email, file_name):

    # Declare the hardcoded rules directory
    rules_directory = os.path.abspath("rules")  # Specify your rules folder here
    try:
        scanner = YaraScanner(rules_directory)
        all_files_detected = []
        try:
            matches = scanner.scan_file(file_path)
            if matches:
                print(f"\nFile '{file_name}' matched the following rules:")
                for match in matches:
                    print(f"  - {match}")
                    all_files_detected.append(f"{file_name}: {match}")
                logging.info(f"Matches found in file: {file_name}")
                ody = f"""Dear User,

The recent malware scan has been completed. Unfortunately, malware has been detected on your system. Here are the details of the detected malware:

{all_files_detected}

Please take immediate action to address this issue and ensure your system is secure.

Best regards,
Team Ransomewatch"""
                send_mail(receipt_email,body)
                logging.info(f"Malware alert email sent for file: {file_name}")
            else:
                print(f"no matches found in file:{file_name}")
                logging.info(f"No matches found in file: {file_name}")
                body = """Dear User,

The recent malware scan has been completed, and we are happy to inform you that no malware was found. Your system is safe and secure.

Best regards,
Your Security Team"""
                send_mail(receipt_email,body)
        except FileNotFoundError as e:
            logging.error(f"File not found: {file_name}")
            print("File not found")
        except Exception as e:
            logging.error(f"Error scanning file {file_name}: {e}")
            print(f"Error: {e}")

    except Exception as e:
        logging.error(f"Error initializing YARA Scanner: {e}")
        print(f"Error: {e}")


if __name__ == "__main__":
    file_path = sys.argv[1]
    receipt_email = sys.argv[2]
    file_name = sys.argv[3]
    detect_malware(file_path, receipt_email,file_name)
