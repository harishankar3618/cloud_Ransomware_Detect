import sys
import os
import logging
from scanner import YaraScanner
from email_alert import send_mail_notfound, send_mail_found

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("yara_scanner.log"),
        logging.StreamHandler()
    ]
)

def detect_malware(file_path, receipt_email, file_name):
    rules_directory = os.path.abspath("rules")
    try:
        scanner = YaraScanner(rules_directory)
        matches = scanner.scan_file(file_path)
        all_files_detected = []

        if matches:
            print(f"\nFile '{file_name}' matched the following rules:")
            for match in matches:
                print(f"  - {match}")
                all_files_detected.append(f"{file_name}: {match}")
            logging.info(f"Matches found in file: {file_name}")
            send_mail_found(receipt_email, all_files_detected)
            logging.info(f"Malware alert email sent for file: {file_name}")
        else:
            print(f"No matches found in file: {file_name}")
            logging.info(f"No matches found in file: {file_name}")
            send_mail_notfound(receipt_email)
    except Exception as e:
        logging.error(f"Error scanning file {file_name}: {e}")
        print(f"Error: {e}")

if __name__ == "__main__":
    receipt_email = sys.argv[1]
    files = sys.argv[2:]

    for file_entry in files:
        file_path, file_name = file_entry.split(":")  # Pass file path and name as "path:name"
        detect_malware(file_path, receipt_email, file_name)
