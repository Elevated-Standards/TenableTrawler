import csv
import os
from tenable.io import TenableIO
from datetime import datetime, timezone

# Retrieve credentials from environment variables
ACCESS_KEY = os.getenv("TENABLE_ACCESS_KEY")
SECRET_KEY = os.getenv("TENABLE_SECRET_KEY")
OUTPUT_FILE = "most_recent_vulnerabilities.csv"

# Initialize Tenable.io instance
def initialize_tenable(access_key, secret_key):
    """Initialize Tenable.io instance."""
    return TenableIO(access_key, secret_key)

def get_most_recent_scan(tio):
    """Retrieve the most recent scan."""
    scans = list(tio.scans.list())
    if not scans:
        raise Exception("No scans found.")
    
    # Sort scans by the 'last_modification_date' field
    most_recent_scan = max(scans, key=lambda scan: scan['last_modification_date'])
    return most_recent_scan

def fetch_vulnerabilities_from_scan(tio, scan_id):
    """Fetch vulnerabilities from the given scan."""
    scan_details = tio.scans.results(scan_id)
    vulnerabilities = scan_details.get('vulnerabilities', [])
    return vulnerabilities

def write_to_csv(vulnerabilities, output_file):
    """Write vulnerabilities to a CSV file."""
    if not vulnerabilities:
        print("No vulnerabilities to export.")
        return

    with open(output_file, mode='w', newline='', encoding='utf-8') as file:
        writer = csv.DictWriter(file, fieldnames=vulnerabilities[0].keys())
        writer.writeheader()
        writer.writerows(vulnerabilities)

    print(f"Vulnerabilities exported to {output_file}")

def main():
    """Main function to execute the script."""


    if not ACCESS_KEY or not SECRET_KEY:
        print("Error: ACCESS_KEY or SECRET_KEY environment variable is not set.")
        return

    # Initialize Tenable.io client
    tio = initialize_tenable(ACCESS_KEY, SECRET_KEY)

    try:
        # Get the most recent scan
        most_recent_scan = get_most_recent_scan(tio)
        scan_id = most_recent_scan['id']
        scan_name = most_recent_scan['name']
        last_modified = datetime.fromtimestamp(
            most_recent_scan['last_modification_date'], tz=timezone.utc
        ).strftime('%Y-%m-%d %H:%M:%S')

        print(f"Most Recent Scan: {scan_name} (ID: {scan_id}) Last Modified: {last_modified}")

        # Fetch vulnerabilities from the most recent scan
        vulnerabilities = fetch_vulnerabilities_from_scan(tio, scan_id)

        if vulnerabilities:
            # Write vulnerabilities to CSV
            write_to_csv(vulnerabilities, OUTPUT_FILE)
        else:
            print("No vulnerabilities found in the most recent scan.")

    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
