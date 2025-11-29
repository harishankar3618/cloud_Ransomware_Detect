#!/usr/bin/env python3
import sys
import os
import logging
import hashlib
import requests

# API settings for MalwareBazaar
HEADERS = {'Auth-Key': '56000943ca1ef0682a4db841e9523add9f5014cf0115c669'}
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

# Function to print a detailed malware report
def print_malware_report(file_path, file_hash, result):
    file_name=os.path.basename(file_path)
    if result and result.get('query_status') == 'ok':
        data = result.get('data', [])
        if data:
            malware_info = data[0]
            # General Malware Information
            print(f"Malware Found in {file_name} and its information")
            print("\n")
            print(f"File Name: {file_name}")
            print(f"First Seen: {malware_info.get('first_seen', 'N/A')}")
            print(f"File Name: {malware_info.get('file_name', 'N/A')}")
            print(f"File Size: {malware_info.get('file_size', 'N/A')} bytes")
            print(f"File Type: {malware_info.get('file_type', 'N/A')}")
            print(f"MIME Type: {malware_info.get('file_type_mime', 'N/A')}")
            print(f"Tags: {', '.join(malware_info.get('tags', []))}")
            print(f"Signature: {malware_info.get('signature', 'N/A')}")
            print(f"Country of Origin: {malware_info.get('origin_country', 'N/A')}")
            print(f"Delivery Method: {malware_info.get('delivery_method', 'N/A')}")

            # Intelligence Section
            print("\nIntelligence:")
            intelligence = malware_info.get('intelligence', {})
            for key, value in intelligence.items():
                if isinstance(value, list):
                    print(f"  {key}: {', '.join(value)}")
                else:
                    print(f"  {key}: {value}")

            # Analysis Links Section
            print("\nAnalysis Links:")
            file_info = malware_info.get('file_information', [])
            for info in file_info:
                print(f"  {info.get('context', 'N/A')}: {info.get('value', 'N/A')}")

            # YARA Rules Section
            yara_rules = malware_info.get('yara_rules', [])
            if yara_rules:
                print("\nYARA Rules:")
                for rule in yara_rules:
                    print(f"  Rule Name: {rule.get('rule_name', 'N/A')}")
                    print(f"    Author: {rule.get('author', 'N/A')}")
                    print(f"    Description: {rule.get('description', 'N/A')}")
            print("\n")

    else:
        print(f"No malware information found for {file_name}")
        print("\n")
# Function to process a single file
def process_file(file_path):
    logging.info(f"Processing file: {file_path}")
    file_hash = calculate_sha256(file_path)
    if not file_hash:
        return None
    logging.info(f"SHA256: {file_hash}")

    result = query_malwarebazaar(file_hash, 'get_info')
    print_malware_report(file_path, file_hash, result)

# Function to scan a directory
def scan_directory(directory):
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            process_file(file_path)

# Main function to run the script
if __name__ == "__main__":
    upload_type = sys.argv[1]  # Either 'file' or 'folder'
    path = sys.argv[2]

    if upload_type == 'file':
        process_file(path)
    elif upload_type == 'folder':
        scan_directory(path)
    else:
        print("Invalid upload type. Use 'file' or 'folder'.")
