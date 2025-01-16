#!/usr/bin/env python3

import os
import json
import xml.etree.ElementTree as ET
from datetime import datetime


def main():
    # Get all .nessus files in the current directory
    nessus_files = [f for f in os.listdir('.') if f.endswith('.nessus')]

    if not nessus_files:
        print("No .nessus files found in the current directory.")
        return

    summary_lines = []

    # Process each .nessus file
    for nessus_file in nessus_files:
        try:
            # Parse the file for timestamp and vulnerabilities
            print(f"Processing {nessus_file}...")
            parsed_data, severity_counts, timestamp_prefix = parse_nessus_file(nessus_file)

            # Rename the file if needed
            if timestamp_prefix:
                nessus_file = rename_file_if_needed(nessus_file, timestamp_prefix)

            # Generate JSON output
            output_file = f"{os.path.splitext(nessus_file)[0]}.json"
            with open(output_file, 'w', encoding='utf-8') as json_file:
                json.dump(parsed_data, json_file, indent=4)

            print(f"Successfully converted {nessus_file} to {output_file}")

            # Record severity counts for the summary
            summary_lines.append(f"{nessus_file}:")
            summary_lines.append(f"  Low: {severity_counts['low']}")
            summary_lines.append(f"  Medium: {severity_counts['medium']}")
            summary_lines.append(f"  High: {severity_counts['high']}")
            summary_lines.append(f"  Critical: {severity_counts['critical']}\n")
        except Exception as e:
            print(f"Error processing {nessus_file}: {e}")

    # Write the summary file
    summary_file = "severity_summary.txt"
    with open(summary_file, 'w', encoding='utf-8') as sf:
        sf.writelines('\n'.join(summary_lines))
    print(f"Severity summary written to {summary_file}")


def parse_nessus_file(nessus_file):
    """Parse a .nessus file and extract all vulnerability data and the HOST_END timestamp."""
    try:
        tree = ET.parse(nessus_file)
        root = tree.getroot()

        all_data = []
        severity_counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        timestamp_prefix = None

        # Process each ReportHost
        for report_host in root.iter('ReportHost'):
            host_data = {
                "ip_address": report_host.get('name'),
                "host_properties": parse_host_properties(report_host),
                "vulnerabilities": []
            }

            # Get the HOST_END timestamp and format it
            host_end = host_data["host_properties"].get("HOST_END")
            if host_end and not timestamp_prefix:
                timestamp_prefix = format_timestamp(host_end)

            # Extract all data from each ReportItem
            for report_item in report_host.iter('ReportItem'):
                severity = int(report_item.get('severity', '0'))  # Default to 0 if missing

                # Update severity counts
                if severity == 0:  # Skip informational items
                    continue
                elif severity == 1:
                    severity_counts["low"] += 1
                elif severity == 2:
                    severity_counts["medium"] += 1
                elif severity == 3:
                    severity_counts["high"] += 1
                elif severity == 4:
                    severity_counts["critical"] += 1

                vuln_data = {
                    **report_item.attrib,  # Include all attributes as top-level fields
                    **extract_nested_fields(report_item)  # Include all nested elements
                }
                host_data["vulnerabilities"].append(vuln_data)

            # Add host data only if it has vulnerabilities
            if host_data["vulnerabilities"]:
                all_data.append(host_data)

        return all_data, severity_counts, timestamp_prefix

    except ET.ParseError as e:
        raise ValueError(f"Error parsing .nessus file: {e}")


def rename_file_if_needed(file_name, timestamp_prefix):
    """Rename the file if it is not correctly timestamped or has redundant timestamps."""
    if is_timestamped(file_name):
        print(f"{file_name} already follows the timestamped naming convention.")
        return file_name

    # Strip redundant timestamps before renaming
    clean_name = file_name
    while True:
        parts = clean_name.split('_', 3)
        try:
            datetime.strptime("_".join(parts[:3]), "%Y_%B_%d_%H%M%S")
            clean_name = "_".join(parts[3:])  # Remove the first valid timestamp
        except (ValueError, IndexError):
            break

    new_name = f"{timestamp_prefix}_{clean_name}"
    os.rename(file_name, new_name)
    print(f"Renamed {file_name} to {new_name}")
    return new_name


def is_timestamped(file_name):
    """Check if the file name starts with a valid timestamp and avoids duplicates."""
    try:
        parts = file_name.split('_', 3)
        if len(parts) < 4:
            return False

        datetime.strptime("_".join(parts[:3]), "%Y_%B_%d_%H%M%S")
        remaining_name = "_".join(parts[3:])
        redundant_timestamp = "_".join(parts[:3]) in remaining_name
        return not redundant_timestamp
    except (ValueError, IndexError):
        return False


def parse_host_properties(report_host):
    """Extract host properties from ReportHost."""
    host_properties = {}
    properties_element = report_host.find('HostProperties')
    if properties_element is not None:
        for tag in properties_element:
            host_properties[tag.attrib.get('name', tag.tag)] = tag.text.strip() if tag.text else None
    return host_properties


def extract_nested_fields(report_item):
    """Extract all nested fields from a ReportItem."""
    nested_fields = {}
    for child in report_item:
        # Handle nested text fields
        if child.tag not in nested_fields:
            nested_fields[child.tag] = child.text.strip() if child.text else None
        else:
            # Handle duplicate tags as lists
            if not isinstance(nested_fields[child.tag], list):
                nested_fields[child.tag] = [nested_fields[child.tag]]
            nested_fields[child.tag].append(child.text.strip() if child.text else None)

    return nested_fields


def format_timestamp(timestamp):
    """Format the HOST_END timestamp as 'YYYY_MONTH_DD_TIME'."""
    try:
        dt = datetime.strptime(timestamp, "%a %b %d %H:%M:%S %Y")
        return dt.strftime("%Y_%B_%d_%H%M%S")
    except ValueError:
        return None


if __name__ == "__main__":
    main()