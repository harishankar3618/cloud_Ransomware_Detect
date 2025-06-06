import sys
import os
import logging
from scanner import YaraScanner

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("yara_scanner.log"),
        logging.StreamHandler()
    ]
)

def detect_malware(folder_to_scan):
    rules_directory = os.path.abspath("rules")
    try:
        scanner = YaraScanner(rules_directory)
    except Exception as e:
        logging.error(f"Error initializing YARA Scanner: {e}")
        print(f"Error: {e}")
        return

    try:
        results = scanner.scan_folder(folder_to_scan)
        if results:
            print("\nMatches found in the following files:")
            for file_path, matches in results.items():
                print(f"{file_path}:")
                for match in matches:
                    print(f"  - {match}")
            logging.info(f"Matches found in folder: {folder_to_scan}")
        else:
            logging.info(f"No matches found in folder: {folder_to_scan}")
    except Exception as e:
        logging.error(f"Error scanning folder {folder_to_scan}: {e}")

if __name__ == "__main__":
    folder_to_scan = sys.argv[1]
    detect_malware(folder_to_scan)
