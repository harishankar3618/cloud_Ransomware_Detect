import sys
import os
import logging
from scanner import YaraScanner
from email_alert import send_mail_notfound, send_mail_found

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
                logging.info(f"File '{file_name}' matched the following rules:")
                print(f"File '{file_name}' matched the following rules:")
                for match in matches:
                    logging.info(f"  - {match}")
                    all_files_detected.append(f"{file_name}: {match}")
                send_mail_found(receipt_email, all_files_detected)
                logging.info(f"Malware alert email sent for file: {file_name}")
            else:
                logging.info(f"No matches found in file: {file_name}")
                print(f"No matches found in file: {file_name}")
                send_mail_notfound(receipt_email)
        except FileNotFoundError as e:
            logging.error(f"File not found: {file_name}")
        except Exception as e:
            logging.error(f"Error scanning file {file_name}: {e}")

    except Exception as e:
        logging.error(f"Error initializing YARA Scanner: {e}")
'''
def scan_directory(directory_path, receipt_email):
    if os.path.isdir(directory_path):
        logging.info(f"Scanning directory: {directory_path}")
        for root, dirs, files in os.walk(directory_path):
            for file in files:
                file_path = os.path.join(root, file)
                logging.info(f"Scanning file: {file_path}")
                detect_malware(file_path, receipt_email, file)
    else:
        logging.error(f"Directory not found: {directory_path}")
        print(f"Directory not found: {directory_path}")
'''

if __name__ == "__main__":
    filename = sys.argv[1]
    directory_path = sys.argv[2]
    receipt_email = sys.argv[3]
    detect_malware(directory_path, receipt_email, filename)
