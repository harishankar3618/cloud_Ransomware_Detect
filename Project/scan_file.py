#!/usr/bin/env python3
import sys
import os
import logging
import hashlib
import requests
import json
from datetime import datetime

# API settings for MalwareBazaar
HEADERS = {'API-KEY': 'fd23d8c7e5f2848a473d070ae6c0429f1eccb89f7848a1a3'}  
API_URL = 'https://mb-api.abuse.ch/api/v1/'

# Configure logging
logging.basicConfig(
    level=logging.INFO,  # Set the log level to INFO to capture normal events and errors
    format="%(asctime)s - %(levelname)s - %(message)s",  # Format the log entries
    handlers=[
        logging.FileHandler("malware_scanner.log"),  # Log to file
        logging.StreamHandler()  # Also log to console
    ]
)

# Function to calculate SHA256 hash
def calculate_sha256(file_path):
    sha256 = hashlib.sha256()
    try:
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception as e:
        logging.error(f"Error calculating hash for {file_path}: {e}")
        return None

# Function to query MalwareBazaar API
def query_malwarebazaar(file_hash, query_type='get_info'):
    data = {'query': query_type, 'hash': file_hash}
    try:
        response = requests.post(API_URL, data=data, timeout=15, headers=HEADERS)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"Error querying MalwareBazaar for {file_hash}: {e}")
        return None

# Function to save result to a file
def save_report(file_path, file_hash, result):
    # Saving to JSON file for later analysis or storage
    report_filename = f"malware_report_{file_hash}.json"
    try:
        with open(report_filename, 'w') as report_file:
            json.dump({
                'file_path': file_path,
                'sha256': file_hash,
                'result': result
            }, report_file, indent=4)
        logging.info(f"Report saved to {report_filename}")
    except Exception as e:
        logging.error(f"Error saving report for {file_path}: {e}")

# Function to process a single file
def process_file(file_path):
    logging.info(f"\nProcessing file: {file_path}")
    file_hash = calculate_sha256(file_path)
    if not file_hash:
        return
    logging.info(f"SHA256: {file_hash}")

    # Query MalwareBazaar for information
    result = query_malwarebazaar(file_hash, 'get_info')
    
    # Save the result to a file
    save_report(file_path, file_hash, result)

# Function to scan a directory
def scan_directory(directory):
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            process_file(file_path)

if __name__ == "__main__":
    filename = sys.argv[1]
    directory_path = sys.argv[2]
    scan_directory(directory_path, filename)
