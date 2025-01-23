import os
import csv
import argparse
from tenable.io import TenableIO

# Tenable.io Configuration
ACCESS_KEY = os.getenv("TIO_ACCESS_KEY")
SECRET_KEY = os.getenv("TIO_SECRET_KEY")
BASE_URL = os.getenv("TIO_BASE_URL", "fedcloud.tenable.com")  # Default to fedcloud.tenable.com

if not ACCESS_KEY or not SECRET_KEY:
    raise ValueError("API keys are missing. Ensure TIO_ACCESS_KEY and TIO_SECRET_KEY are set.")

# Connect to Tenable.io
tio = TenableIO(ACCESS_KEY, SECRET_KEY, url=f"https://{BASE_URL}")

def list_findings():
    """
    Retrieve all findings from the most recent scan.
    """
    try:
        print(f"Fetching findings from {BASE_URL} using pytenable...")
        findings_iterator = tio.was.export(
            sort=[("plugin_publication_date", "desc")]  # Sort findings by publication date
        )

        # Collect all findings
        findings = [finding for finding in findings_iterator]
        if not findings:
            print("No findings found.")
            return None

        # Debugging: Print the first finding object for reference
        print(f"Debug: Retrieved first finding object: {findings[0]}")
        return findings
    except Exception as e:
        print(f"Error fetching findings: {e}")
        raise

def export_findings_to_csv(findings, output_dir, file_name="findings.csv"):
    """
    Export findings to a CSV file in the specified directory with the given file name.
    """
    try:
        # Ensure the directory exists
        os.makedirs(output_dir, exist_ok=True)
        file_path = os.path.join(output_dir, file_name)
        print(f"Exporting findings to CSV: {file_path}...")
        
        with open(file_path, mode="w", newline="", encoding="utf-8") as csvfile:
            csvwriter = csv.writer(csvfile)
            
            # Write CSV headers
            headers = [
                "Name", 
                "Severity", 
                "Description", 
                "Family", 
                "URI", 
                "Attachments"
            ]
            csvwriter.writerow(headers)

            # Write findings
            for finding in findings:
                finding_data = finding.get('finding', {})
                name = finding_data.get('name', 'Unknown Name')
                severity = finding_data.get('risk_factor', 'Unknown Severity')
                description = finding_data.get('description', 'No description available.')
                family = finding_data.get('family', 'Unknown Family')
                uri = finding_data.get('uri', 'Unknown URI')
                attachments = ", ".join(finding_data.get('attachments', []))

                csvwriter.writerow([name, severity, description, family, uri, attachments])

        print(f"Findings successfully exported to {file_path}.")
    except Exception as e:
        print(f"Error exporting findings to CSV: {e}")
        raise

if __name__ == "__main__":
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Tenable Findings Exporter")
    parser.add_argument("--output-dir", required=True, help="Directory to save the CSV file")
    parser.add_argument("--file-name", required=True, help="Name of the CSV file to save")
    args = parser.parse_args()

    # Fetch findings
    findings = list_findings()
    if not findings:
        print("No findings to process.")
    else:
        # Export findings to the specified directory with the given file name
        export_findings_to_csv(findings, args.output_dir, args.file_name)
