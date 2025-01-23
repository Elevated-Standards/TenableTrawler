# TenableTrawler

TenableTrawler (Cloud OR FedCloud) is a Python-based project designed to pull scan results using the Tenable API and different Tenable scan results into an organized output that is POAM-ready. The project includes several scripts to handle various types of scans and export the results in different formats such as CSV, JSON, and YAML.


## Features

- Fetches scan results from Tenable.io using the Tenable API.
- Supports exporting scan results to CSV, JSON, and YAML formats.
- Organizes scan results into a structured format suitable for POAM (Plan of Action and Milestones).
- Includes GitHub Actions workflows to automate the fetching and exporting of scan results on a scheduled basis.

## Requirements

- Python 3.x
- Tenable API Access Key and Secret Key
- Required Python packages listed in `requirements.txt`:
  - `pytenable`
  - `click`
  - `arrow`
  - `requests`

## Installation

1. Fork and Clone the repository:

Fork First

```bash
   git clone https://github.com/YOURUSERNAME/TenableTrawler.git
   cd TenableTrawler
```

2. Install the required Python Packages

```python
pip install -r requirements.txt
```

3. Set Up a Python Virtual Environment (Optional But Recommended)

```python
python3 -m venv tenable
source tenable/bin/activate
```

## Usage

### Running the Scripts

1. Set the Tenable API Access Key and Secret Key as environment variables:

```bash
export TIO_ACCESS_KEY='your_access_key'
export TIO_SECRET_KEY='your_secret_key'
```

2. Variable for timestamping file name later

```bash
YEAR=$(date +"%Y")
MONTH=$(date +"%B")
END_DATE=$(date -u +"%Y-%m-%dT%H-%M-%SZ")
```

3. Run the desired script. For example, to run the tenable.py script:

```python
# was = Web App Scanning

# cloud.tenable.com

python3 src/cloud_trawler.py --download-path scans/cloud/vulmgt/${YEAR}/${MONTH}/

python3 src/cloud_trawler-webapp-tio.py \
            --output-dir scans/cloud/was/${YEAR}/${MONTH}/ \
            --file-name "${END_DATE}_findings.csv"

## fedcloud.tenable.com

python3 src/fedcloud_tenabletrawler.py --download-path scans/fedcloud/vulmgt/${YEAR}/${MONTH}/

python3 src/fedcloud_trawler-webapp-tio.py \
            --output-dir scans/fedcloud/was/${YEAR}/${MONTH}/ \
            --file-name "${END_DATE}_findings.csv"

```

### GitHub Actions Workflows


The project includes several GitHub Actions workflows to automate the fetching and exporting of scan results:

- Cloud Tenable VM Scan Results: `cloud-scan-results.yml`
- Cloud WebAppScanning Scan Results: `cloud-was-results-tio.yml`
- FedCloud Tenable VM Scan Results: `fedcloud-scan-results.yml`
- FedCloud WebAppScanning Scan Results: `fedcloud-was-results-tio.yml`


These workflows are triggered on a schedule and can also be manually triggered via the GitHub Actions interface.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request with your changes


## License

This project is licensed under the Apache2 License.



