# aws-s3-waf-parser
This is a tool to help with pulling down waf logs that are stored in S3 for analysis

When running this tool run as follows

`python s3-waf-log-parser.py <s3bucket> <s3prefix> <filter>`

Parameter Examples
- s3bucket: `s3:// <bucketname> /*`  ## Bucket
- s3prefix: `s3://bucket/ <prefix>`  ## Path to content
- filter: 1.1.1.1 ## An abstract value that can be used for filtering the logs

The following headers are used to assist with readability
- File Name
- Timestamp
- Action
- ClientIp
- HttpMethod
- Country
- URI

## Usage
When running this tool, in your CLI environment export your AWS_PROFILE and perform an `aws sso login` 

This tool will produce the following:
- `matched_logs.log` that enters all the entries in a comma separated pattern against the following headers
- `tmp/<date>/<s3prefix>` to recursively download all child files within the parent prefix provided. All parent folders are created recursively as well.
- `typer CLI output` for a tabulated visual to assist with analysis and further investigation of waf logs in particular