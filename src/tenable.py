#!/usr/bin/env python
from tenable.io import TenableIO
import os
import click
import arrow
from datetime import datetime

tio = TenableIO('os.getenv("TIO_ACCESS_KEY")', 'os.getenv("TIO_SECRET_KEY")')


@click.command()
@click.option('--tio-access-key', 'access_key', envvar='TIO_ACCESS_KEY',
    help='Tenable.io API Access Key')
@click.option('--tio-secret-key', 'secret_key', envvar='TIO_SECRET_KEY',
    help='Tenable.io API Secret Key')
@click.option('--download-path', '-p', 'path', envvar='DOWNLOAD_PATH',
    type=click.Path(exists=False), default='.',
    help='The base path to where the downloaded report files will reside.')
@click.option('--search', '-s', 'search', default='',
    help='The search filter to use on the scan names.')
@click.option('--filter', '-f', 'filters', nargs=3, multiple=True,
    type=click.Tuple([str, str, str]),
    help=' '.join([
        'Filter the output using the specified name, operator, and value',
        'such as: -f plugin.id eq 19506'
    ]))
@click.option('--report-format', '-r', 'format',
    type=click.Choice(['csv', 'nessus']), default='csv',  # Set csv as the default
    help='The report format. Acceptable values are "csv" and "nessus".')
@click.option('--filter-type', 'filter_type',
    type=click.Choice(['and', 'or']), default='and',
    help='Should the filters all match ("and") or any of them match ("or").')
def download_scans(access_key, secret_key, search, path, filters, **kwargs):
    '''
    Attempts to download the latest completed scan from tenable.io and stores
    the file in the path specified. The exported scan will be filtered based
    on the filters specified.
    '''
    tio = TenableIO(access_key, secret_key)

    # Get the current year and month for dynamic folder structure
    current_year = datetime.now().year
    current_month = datetime.now().strftime('%B')

    # Create the dynamic download path based on year and month
    dynamic_download_path = os.path.join(path, str(current_year), current_month)
    
    # Ensure the download path exists
    if not os.path.exists(dynamic_download_path):
        os.makedirs(dynamic_download_path)

    # Get the list of scans that match the name filter defined.
    scans = [s for s in tio.scans.list() if search.lower() in s['name'].lower()]

    for scan in scans:
        details = tio.scans.results(scan['id'])

        # Get the list of scan histories that are in a completed state.
        completed = [h for h in details.get('history', list())
                        if h.get('status') == 'completed']

        # Download the latest completed scan.
        if len(completed) > 0:
            history = completed[0]
            filename = '{}-{}.{}'.format(
                scan['name'].replace(' ', '_'),
                history['uuid'],
                kwargs['format']
            )
            file_path = os.path.join(dynamic_download_path, filename)
            with open(file_path, 'wb') as report_file:
                kw = kwargs
                kw['history_id'] = history['history_id']
                kw['fobj'] = report_file
                click.echo('Scan "{}" completed at {} downloading to {}'.format(
                    scan['name'],
                    arrow.get(history['last_modification_date']).isoformat(),
                    report_file.name))
                tio.scans.export(scan['id'], *filters, **kw)
        else:
            click.echo('No completed scans found for "{}"'.format(scan['name']))

if __name__ == '__main__':
    download_scans()
