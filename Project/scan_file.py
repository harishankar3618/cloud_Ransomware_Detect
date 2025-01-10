import sys
import os
import logging
from scanner import YaraScanner

# Configure logging
logging.basicConfig(
    level=logging.INFO,  # Set the log level to INFO to capture normal events and errors
    format="%(asctime)s - %(levelname)s - %(message)s",  # Format the log entries
    handlers=[
        logging.FileHandler("yara_scanner.log"),  # Log to file
        logging.StreamHandler()  # Also log to console
    ]
)

def detect_malware(file_path, file_name):
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
                    print(f"  - {match}")
                    all_files_detected.append(f"{file_name}: {match}")
                logging.info(f"Malware alert email sent for file: {file_name}")
            else:
                logging.info(f"No matches found in file: {file_name}")
                print(f"No matches found in file: {file_name}")

        except FileNotFoundError as e:
            logging.error(f"File not found: {file_name}")
        except Exception as e:
            logging.error(f"Error scanning file {file_name}: {e}")

    except Exception as e:
        logging.error(f"Error initializing YARA Scanner: {e}")

if __name__ == "__main__":
    filename = sys.argv[1]
    directory_path = sys.argv[2]
    detect_malware(directory_path, filename)
