# GDPR Obfuscator Project

## Context

The purpose of this project is to create a general-purpose tool to process data being ingested to AWS and intercept personally identifiable information (PII). All information stored by Northcoders data projects should be for bulk data analysis only. Consequently, there is a requirement under GDPR to ensure that all data containing information that can be used to identify an individual should be anonymised.

## Completion notes

I have created two versions implemented by creating clases, the first is S3CSVObfuscator which will conceal required files in a CSV file type. The second is an expanded version called MultiFormatObfuscator which expands out to two further file types, JSON and parquet. This tool will replace requested fields with \*\*\*\*. This was intentional because I did considering implementing a system that would put one star per character of input, however, this would in a small way compromise the data security of the students.

## Assumptions and Prerequisites

The input data is stored in CSV-, JSON-, or parquet-formatted files in an AWS S3 bucket.
Fields containing GDPR-sensitive data are known and will be supplied in advance.
Data records will be supplied with a primary key.

## Usage instructions

You would begin by instantiating a new class of the required variant, in this case the multiple file version with the relevant login information already formatted as an AWS secret for the code to to utilise.

obfuscator = MultiFormatObfuscator(secret_name="your-secret-name")

event = {
"file_to_obfuscate": "s3://bucket/path/northcoders_data.csv",
"pii_fields": ["email"]
}
result = obfuscator.process_request(event)

The obfuscated information is returned by the process request method, should you wish to save this to a new S3 file location the following code can extract this data.

event = {
"file_to_obfuscate": "s3://bucket/path/northcoders_data.csv",
"pii_fields": ["email"]
}
result = obfuscator.process_request(event)

if result["statusCode"] == 200:
obfuscated_content = result["body"]

    if result["isBase64Encoded"]:
        import base64
        obfuscated_content = base64.b64decode(obfuscated_content)

    s3_client.put_object(
        Bucket="new-destination-bucket",
        Key="path/to/obfuscated_file",
        Body=obfuscated_content,
        ContentType=result["headers"]["Content-Type"]
    )
