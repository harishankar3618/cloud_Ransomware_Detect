import sys
import requests
import json

# Defining the API endpoint for AbuseIPDB
url = 'https://api.abuseipdb.com/api/v2/check'

# Function to check the IP using the AbuseIPDB API
def check_ip(ip_address):
    querystring = {
        'ipAddress': ip_address,
        'maxAgeInDays': '90'  # You can change this if needed
    }

    # Your AbuseIPDB API Key
    headers = {
        'Accept': 'application/json',
        'Key': '12486cee49d6de871b8621142cd803e1bdfbb84e373dd5564ab85f024c18ddf32f863bf662e7dbdb'  # Replace this with your actual API key
    }

    # Sending GET request to AbuseIPDB
    response = requests.get(url, headers=headers, params=querystring)

    # Check if request was successful
    if response.status_code == 200:
        return response.json()  # Return the JSON response if successful
    else:
        print(f"Error: Unable to fetch data for IP {ip_address}")
        return None

# Function to process the IP address and print the result
def process_ip(ip_address):
    print(f"Checking IP address: {ip_address}")
    result = check_ip(ip_address)

    if result:
        # Pretty print the response from AbuseIPDB
        print(json.dumps(result, sort_keys=True, indent=4))
    else:
        print(f"No information found for IP {ip_address}")

# Main function
if __name__ == "__main__":
    # Get IP address as an argument from the command line
    if len(sys.argv) < 2:
        print("Usage: python ip_scan.py <IP_ADDRESS>")
        sys.exit(1)

    ip_address = sys.argv[1]  # IP address passed as argument
    process_ip(ip_address)
