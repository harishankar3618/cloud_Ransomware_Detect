import sys
import os
import logging
from scanner import YaraScanner
from email_alert import send_mail_notfound,send_mail_found

# Configure logging
logging.basicConfig(
    level=logging.INFO,  # Set the log level to INFO to capture normal events and errors
    format="%(asctime)s - %(levelname)s - %(message)s",  # Format the log entries
    handlers=[
        logging.FileHandler("yara_scanner.log"),  # Log to file
        logging.StreamHandler()  # Also log to console
    ]
)

def detect_malware(folder_to_scan, receipt_email):

    # Declare the hardcoded rules directory
    rules_directory = os.path.abspath("rules")  # Specify your rules folder here
    try:
        scanner = YaraScanner(rules_directory)
        results = scanner.scan_folder(folder_to_scan)
        if results:
            print("\nMatches found in the following files:")
            all_files_detected = []
            for file_path, matches in results.items():
                print(f"{file_path}:")
                for match in matches:
                    print(f"  - {match}")
                    all_files_detected.append(f"{file_path}: {match}")
            logging.info(f"Matches found in folder: {folder_to_scan}")
            send_mail_found(receipt_email,all_files_detected)
            logging.info(f"Malware alert email sent for folder scan.")
        else:
            logging.info(f"No matches found in folder: {folder_to_scan}")
    except Exception as e:
            logging.error(f"Error scanning folder {folder_to_scan}: {e}")
            send_mail_notfound(receipt_email)
    except Exception as e:
        logging.error(f"Error initializing YARA Scanner: {e}")
        print(f"Error: {e}")


if __name__ == "__main__":
    folder_to_scan = sys.argv[1]
    receipt_email = sys.argv[2]
    detect_malware(folder_to_scan, receipt_email)
