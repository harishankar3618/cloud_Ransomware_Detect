#!/usr/bin/env python3
import sys
import os
import logging
import hashlib
import requests

# API settings for MalwareBazaar
HEADERS = {'API-KEY': 'fd23d8c7e5f2848a473d070ae6c0429f1eccb89f7848a1a3'}  
API_URL = 'https://mb-api.abuse.ch/api/v1/'

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("malware_scanner.log"), logging.StreamHandler()]
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

# Function to process a single file
def process_file(file_path):
    logging.info(f"\nProcessing file: {file_path}")
    file_hash = calculate_sha256(file_path)
    if not file_hash:
        return None
    logging.info(f"SHA256: {file_hash}")

    # Query MalwareBazaar for information
    result = query_malwarebazaar(file_hash, 'get_info')
    
    if result:
        # Display the result or pass it along
        return f"File: {file_path}\nSHA256: {file_hash}\nResult: {result}\n"
    else:
        return f"File: {file_path}\nSHA256: {file_hash}\nNo data found."

# Function to scan a directory
def scan_directory(directory):
    results = []
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            result = process_file(file_path)
            if result:
                results.append(result)
    return results

# Main function to run script
if __name__ == "__main__":
    upload_type = sys.argv[1]  # Either 'file' or 'folder'
    path = sys.argv[2]

    results = []

    if upload_type == 'file':
        # Process a single file
        result = process_file(path)
        if result:
            results.append(result)
    elif upload_type == 'folder':
        # Process all files in a folder
        results = scan_directory(path)

    # Print all results
    for res in results:
        print(res)
