import typer
import boto3
import os
import datetime
import re
import json
import gzip
import shutil
from typing import Annotated
from rich.console import Console
from rich.table import Table

s3_client = boto3.client('s3')
console = Console()
paginator = s3_client.get_paginator('list_objects_v2')
now = datetime.datetime.now().strftime("%Y%m%d-%")

def s3_log_parser(
        bucket_name: Annotated[str, typer.Argument(help="The name of the S3 bucket containing WAF logs")],
        s3_prefix: Annotated[str, typer.Argument(help="The S3 prefix where WAF logs are stored")],
        regex_filter: Annotated[str, typer.Option(help="Regex filter to apply on log entries")],
        local_dir: Annotated[str, typer.Option(help="Local directory to store downloaded logs")] = f'tmp/{now}'
):
    """
    Pull S3 Logs from AWS Bucket Path recursively and parse the contents of the logs based on a simple filter.
    """

    pages = paginator.paginate(Bucket=bucket_name, Prefix=s3_prefix)

    for page in pages:
        for obj in page['Contents']:
            s3_key = obj['Key']

            if s3_key.endswith('/'):
                continue

            relative_path = os.path.relpath(s3_key, s3_prefix)
            local_file_path = os.path.join(local_dir, relative_path)

            local_file_dir = os.path.dirname(local_file_path)
            if not os.path.exists(local_file_dir):
                os.makedirs(local_file_dir, exist_ok=True)

            try:
                s3_client.download_file(bucket_name, s3_key, local_file_path)
                console.print(f"[green]Downloaded:[/green] {s3_key} to {local_file_path}")
                if local_file_path.endswith('.gz'):
                    with gzip.open(local_file_path, 'rb') as f_in:
                        with open(local_file_path[:-3], 'wb') as f_out:
                            shutil.copyfileobj(f_in, f_out)
                    os.remove(local_file_path)
                    local_file_path = local_file_path[:-3]
                    console.print(f"[green]Decompressed:[/green] {local_file_path}")

                print(f'Processing {local_file_path} for regex matches...')
                match_count = 0
                with open(local_file_path, 'r') as log_file:
                    for line in log_file:
                        if re.search(regex_filter, line):
                            match_count += 1
                            log_data = json.loads(line)
                            http = log_data.get('httpRequest', {})

                            data_string = ','.join(
                                [
                                    local_file_path,
                                    str(log_data.get('timestamp', 'N/A')),
                                    log_data.get('action', 'N/A'),
                                    http.get('clientIp', 'N/A'),
                                    http.get('httpMethod', 'N/A'),
                                    http.get('country', 'N/A'),
                                    http.get('uri', 'N/A')
                                ]
                            )

                            print(f'MATCH {match_count}: {data_string}')

                            with open (f'{local_dir}/matched_logs.log', 'a') as match_file:
                                match_file.write(data_string + '\n')
                
                print(f'Found {match_count} matches in {local_file_path}.')

            except Exception as e:
                console.print(f"[red]Error processing file {local_file_path}: {e}[/red]")
    
    table = Table("File Name", "Timestamp", "Action", "Client IP", "HTTP Method", "URI")

    f = open(f'{local_dir}/matched_logs.txt', 'r')

    while True:
        line = f.readline()
        if not line:
            break
        waf_fields = line.strip().split(',')
        table.add_row(waf_fields[0], waf_fields[1], waf_fields[2], waf_fields[3], waf_fields[4], waf_fields[6])

    f.close()

    console.print(table)

if __name__ == "__main__":
    typer.run(s3_log_parser)
