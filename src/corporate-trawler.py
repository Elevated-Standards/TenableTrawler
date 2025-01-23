#!/usr/bin/env python
from tenable.io import TenableIO
import os
import click
from datetime import datetime

# Set up TenableIO client
ACCESS_KEY = os.getenv('TIO_ACCESS_KEY')
SECRET_KEY = os.getenv('TIO_SECRET_KEY')

if not ACCESS_KEY or not SECRET_KEY:
    raise ValueError("API keys are missing. Ensure TIO_ACCESS_KEY and TIO_SECRET_KEY are set.")

# Initialize TenableIO client
tio = TenableIO(ACCESS_KEY, SECRET_KEY)

@click.command()
@click.option('--download-path', '-p', 'path', envvar='DOWNLOAD_PATH', type=click.Path(exists=False), default='.', help='The base path to where the downloaded report files will reside.')
@click.option('--search', '-s', 'search', default='', help='The search filter to use on the scan names.')
@click.option('--report-format', '-r', 'format', type=click.Choice(['csv', 'nessus']), default='csv', help='The report format. Acceptable values are "csv" and "nessus".')
def download_scans(search, path, format):
    """
    Downloads the latest completed scans from Tenable.io using pytenable.
    """
    # Create a dynamic download directory based on the current year and month
    current_year = datetime.now().year
    current_month = datetime.now().strftime('%B')
    dynamic_download_path = os.path.join(path, str(current_year), current_month)

    os.makedirs(dynamic_download_path, exist_ok=True)

    # Fetch and process scans via pytenable
    click.echo("Fetching scans using pytenable...")
    try:
        scans = [scan for scan in tio.scans.list() if search.lower() in scan['name'].lower()]
        for scan in scans:
            process_scan(scan, dynamic_download_path, format)
    except Exception as e:
        click.echo(f"Error fetching scans via pytenable: {e}")

def process_scan(scan, path, report_format):
    """
    Processes a single scan fetched via pytenable.
    """
    try:
        details = tio.scans.results(scan['id'])
        completed = [h for h in details.get('history', []) if h.get('status') == 'completed']
        if completed:
            history = completed[0]
            filename = f"{scan['name'].replace(' ', '_')}-{history['uuid']}.{report_format}"
            file_path = os.path.join(path, filename)
            with open(file_path, 'wb') as report_file:
                tio.scans.export(scan['id'], history_id=history['history_id'], fobj=report_file, format=report_format)
            click.echo(f"Downloaded scan: {filename}")
        else:
            click.echo(f"No completed scans found for: {scan['name']}")
    except Exception as e:
        click.echo(f"Error processing scan '{scan['name']}': {e}")

if __name__ == '__main__':
    download_scans()
