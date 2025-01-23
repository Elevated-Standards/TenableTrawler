# Python Code

### Tenable Vulnerability Management Code



# Tenable.io Scan Downloader

This script uses the `pytenable` library to interact with Tenable.io, a vulnerability management platform. The primary functionality is to download the latest completed scans that match a given search filter. The script organizes downloaded scans into a dynamically created directory structure based on the current year and month.

## Script Breakdown

### 1. Environment Setup
The script retrieves the Tenable.io API keys (`TIO_ACCESS_KEY` and `TIO_SECRET_KEY`) from environment variables to initialize the `TenableIO` client. If these keys are not set, the script raises an error and exits.

```python
ACCESS_KEY = os.getenv('TIO_ACCESS_KEY')
SECRET_KEY = os.getenv('TIO_SECRET_KEY')

if not ACCESS_KEY or not SECRET_KEY:
    raise ValueError("API keys are missing. Ensure TIO_ACCESS_KEY and TIO_SECRET_KEY are set.")
```

### 2. TenableIO Client Initialization
The `TenableIO` client is instantiated using the provided API keys.

```python
tio = TenableIO(ACCESS_KEY, SECRET_KEY)
```

### 3. Command-Line Interface
The script uses the `click` library to provide a CLI interface with the following options:
- `--download-path` or `-p`: Specifies the base path for saving downloaded reports. Defaults to the current directory (`.`).
- `--search` or `-s`: A filter for scan names. Only scans containing this string (case-insensitive) will be downloaded.
- `--report-format` or `-r`: Specifies the report format. Options are `csv` or `nessus`.

```python
@click.command()
@click.option('--download-path', '-p', 'path', envvar='DOWNLOAD_PATH', type=click.Path(exists=False), default='.', help='The base path to where the downloaded report files will reside.')
@click.option('--search', '-s', 'search', default='', help='The search filter to use on the scan names.')
@click.option('--report-format', '-r', 'format', type=click.Choice(['csv', 'nessus']), default='csv', help='The report format. Acceptable values are "csv" and "nessus".')
```

### 4. Main Function: `download_scans`
This function fetches and processes scans from Tenable.io:
1. Creates a dynamic directory structure (`year/month`) for downloaded reports.
2. Lists all available scans and filters them based on the `search` term.
3. Calls the `process_scan` function for each filtered scan.

```python
def download_scans(search, path, format):
    current_year = datetime.now().year
    current_month = datetime.now().strftime('%B')
    dynamic_download_path = os.path.join(path, str(current_year), current_month)

    os.makedirs(dynamic_download_path, exist_ok=True)

    click.echo("Fetching scans using pytenable...")
    try:
        scans = [scan for scan in tio.scans.list() if search.lower() in scan['name'].lower()]
        for scan in scans:
            process_scan(scan, dynamic_download_path, format)
    except Exception as e:
        click.echo(f"Error fetching scans via pytenable: {e}")
```

### 5. Helper Function: `process_scan`
Processes individual scans:
1. Retrieves scan details and checks for completed scan history.
2. Exports the completed scan to the specified directory in the chosen format (`csv` or `nessus`).
3. Handles errors during processing.

```python
def process_scan(scan, path, report_format):
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
```

### 6. Script Entry Point
Defines the script's entry point to execute the `download_scans` function when the script is run.

```python
if __name__ == '__main__':
    download_scans()
```

## How It Works
1. The user runs the script, optionally specifying `--download-path`, `--search`, and `--report-format`.
2. The script fetches all scans from Tenable.io using the `tio.scans.list()` method.
3. It filters scans based on the `search` term and processes each scan to download completed scan reports.
4. Reports are saved in a dynamically created directory structure (`path/year/month`) with a name derived from the scan name and its history UUID.

## Example Usage
```bash
python script.py --download-path ./reports --search "critical" --report-format nessus
```
This command downloads all completed scans containing "critical" in their name, saves them in the `./reports/<year>/<month>` directory, and exports them in `nessus` format.

## Dependencies
- Python 3.x
- `pytenable` library for Tenable.io integration
- `click` library for CLI functionality
- Environment variables `TIO_ACCESS_KEY` and `TIO_SECRET_KEY` for API authentication.






### Tenable Web App Scanning Code











