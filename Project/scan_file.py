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

def get_all_rule_files(rules_directory):
    """Recursively get all YARA rule files from the directory and its subdirectories."""
    rule_files = []
    for root, dirs, files in os.walk(rules_directory):
        for file in files:
            if file.endswith(".yar") or file.endswith(".yara"):  # YARA files should have .yar or .yara extension
                rule_files.append(os.path.join(root, file))
    return rule_files

def detect_malware(file_path, file_name, rules_directory):
    try:
        # Collect all YARA rule files from the directory and its subdirectories
        rule_files = get_all_rule_files(rules_directory)

        if not rule_files:
            logging.warning(f"No YARA rules found in directory: {rules_directory}")
            print(f"No YARA rules found in directory: {rules_directory}")
            return

        # Initialize the YaraScanner with the list of rule files
        scanner = YaraScanner(rule_files)
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
    # Ensure the user provides both filename and directory path as command-line arguments
    if len(sys.argv) < 3:
        sys.exit(1)

    filename = sys.argv[1]
    directory_path = sys.argv[2]

    # Path to your rules directory
    rules_directory = os.path.abspath("rules")  # Specify the root directory for rules

    detect_malware(directory_path, filename)
