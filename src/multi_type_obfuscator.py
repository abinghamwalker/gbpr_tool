import json
import csv
import io
import os
import boto3
import logging
import pyarrow.parquet as pq
import pyarrow as pa
from typing import Dict, List, Tuple, Union
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)


class SecretsManager:
    """This is a class constructed to handle AWS information"""

    def __init__(self, secret_name: str, region_name: str = "eu-west-2"):
        """
        Initialise SecretsManager with secret name and region

        Parameters:
            secret_name: Name of the secret in AWS Secrets Manager
            region_name: AWS region where the secret is stored
        """
        self.secret_name = secret_name
        self.region_name = region_name
        self.session = boto3.session.Session()
        self.client = self.session.client(
            service_name="secretsmanager", region_name=region_name
        )

    def get_secret(self) -> Dict:
        """
        Retrieve secret value from AWS Secrets Manager
        """
        try:
            response = self.client.get_secret_value(SecretId=self.secret_name)
            if "SecretString" in response:
                return json.loads(response["SecretString"])
        except ClientError as er_info:
            logger.error(f"Error retrieving secret: {str(er_info)}")
            raise


class MultiFormatObfuscator:
    """Class to  implement methods to obfuscate CSV, JSON, Parquet"""

    def __init__(self, secret_name: str = None, region: str = "eu-west-2"):
        """
        Initialise the MultiFormatObfuscator with an S3 client

        Parameters:
            secret_name: Name of the secret in AWS Secrets Manager
            region_name: AWS region where the secret is stored

        Raises:
            ValueError: if missing login credentials for AWS
        """

        self.s3_client = None
        self.session = None
        if not secret_name:
            raise ValueError("Log in credentials are required")
        self._initialise_with_secrets(secret_name, region)

    def _initialise_with_secrets(self, secret_name: str, region: str):
        """
        Initialise AWS client with credentials from Secrets Manager

        Parameters:
            secret_name: Name of the secret in AWS Secrets Manager
            region_name: AWS region where the secret is stored

        Raises:
            Exception: If initialization fails
        """
        try:
            secrets_manager = SecretsManager(secret_name, region)
            credentials = secrets_manager.get_secret()

            self.session = boto3.Session(
                aws_access_key_id=credentials.get("aws_access_key_id"),
                aws_secret_access_key=credentials.get("aws_secret_access_key"),
                region_name=credentials.get("aws_region", region),
            )

            self.s3_client = self.session.client("s3")
            logger.info("Successfully initialised S3 client")
        except Exception as er_info:
            logger.error(f"Error initializing with secrets: {str(er_info)}")
            raise

    def _parse_s3_uri(self, s3_uri: str) -> Dict[str, str]:
        """
        Parse S3 URI into bucket and key components

        Parameters:
            s3_uri: S3 URI (e.g., 's3://bucket/path/file.csv')
            
        Raises:
            ValueError: S3 URI is not correct format
            
        Returns:
            Dictionary containing bucket and key
        """
        if not s3_uri.startswith("s3://"):
            raise ValueError(f"Invalid S3 URI format: {s3_uri}")

        parts = s3_uri[5:].split("/", 1)
        return {"bucket": parts[0], "key": parts[1] if len(parts) > 1 else ""}

    def _get_file_format(self, file_path: str) -> str:
        """
        Retrieve the file type of S3 bucket content

        Parameters:
            file_path: S3 object file path
            
        Raises:
            ValueError: File type is not CSV, JSON or Parquet
            
        Returns:
            File type as string
        """
        extension = file_path.lower().split(".")[-1]
        if extension not in ["csv", "parquet", "json"]:
            raise ValueError(f"Unsupported file format: {extension}")
        return extension

    def _get_file_from_s3(self, bucket: str, key: str) -> bytes:
        """
        Retrieve the file type from S3
        
        Parameters:
            file_path: S3 object file path
            
        Raises:
            ValueError: File type is not CSV, JSON or Parquet
            
        Returns:
            File type as string
        """
        try:
            response = self.s3_client.get_object(Bucket=bucket, Key=key)
            return response["Body"].read()
        except Exception as er_info:
            logger.error(f"Error retrieving file from S3: {str(er_info)}")
            raise

    def obfuscate_data(self, data: Union[str, bytes],
        file_format: str, pii_fields: List[str]) -> str:
        """
        Obfuscate PII fields in different file formats

        Parameters:
            data: Raw data content
            file_format: Format of the file ('csv', 'json', or 'parquet')
            pii_fields: List of field names to obfuscate

        Raises:
            ValueError: If given the wrong file format to obfuscate

        Returns:
            Obfuscated data in the original format
        """
        if file_format == 'csv':
            return self._obfuscate_csv(data, pii_fields)
        if file_format == 'json':
            return self._obfuscate_json(data, pii_fields)
        if file_format == 'parquet':
            return self._obfuscate_parquet(data, pii_fields)
        else:
            raise ValueError(f"Unsupported file format: {file_format}")

    def _obfuscate_csv(self, csv_content: bytes, pii_fields: List[str]) -> Tuple[str, str]:
        """Handle CSV format
        Obfuscate specified fields in CSV content

        Parameters:
            content: Raw bytes
            pii_fields: List of fields to obfuscate
            
        Raises:
            ValueError: if pii_fields are not in headers
            ValueError: if CSV is empty
            Exception: process fails
            
        Returns:
            Obfuscated CSV content
        """
        try:
            csv_str = csv_content.decode('utf-8') if isinstance(csv_content, bytes) else csv_content

            input_file = io.StringIO(csv_str)
            output_file = io.StringIO()

            reader = csv.DictReader(input_file)
            if not reader.fieldnames:
                raise ValueError("CSV file appears to be empty")

            missing_fields = [field for field in pii_fields if field not in reader.fieldnames]
            if missing_fields:
                raise ValueError(f"Fields not found in CSV: {', '.join(missing_fields)}")

            writer = csv.DictWriter(output_file, fieldnames=reader.fieldnames)
            writer.writeheader()

            for row in reader:
                for field in pii_fields:
                    row[field] = "****"
                writer.writerow(row)

            return output_file.getvalue(), 'text/csv'

        except Exception as er_info:
            logger.error(f"Error processing CSV: {str(er_info)}")
            raise


    def _obfuscate_json(self, json_content: bytes, pii_fields: List[str]) -> Tuple[str, str]:
        """Handle JSON format
        Obfuscate specified fields in JSON content

        Parameters:
            json_content: Raw bytes
            pii_fields: List of fields to obfuscate

        Raises:
            ValueError: if JSON is empty
            ValueError: if JSON is invalid
            Exception: process fails

        Returns:
            Obfuscated JSON content
        """
        try:
            json_str = (json_content.decode('utf-8')
            if isinstance(json_content, bytes)
            else json_content)

            if not json_str.strip():
                raise ValueError("Invalid JSON format")

            try:
                data = json.loads(json_str)
            except json.JSONDecodeError:
                raise ValueError("Invalid JSON format")

            if isinstance(data, dict):
                data = [data]

            first_obj = data[0]
            missing_fields = [field for field in pii_fields if field not in first_obj]
            if missing_fields:
                raise ValueError(f"Fields not found in JSON: {missing_fields}")

            for item in data:
                for field in pii_fields:
                    if field in item:
                        item[field] = "****"

            return json.dumps(data), 'application/json'

        except Exception as er_info:
            if isinstance(er_info, ValueError):
                raise er_info
            raise Exception(f"Failed to process JSON: {str(er_info)}")

    def _obfuscate_parquet(self, parquet_content: bytes,
        pii_fields: List[str]) -> Tuple[bytes, str]:
        """Handle Parquet format
        Obfuscate specified fields in Parquet content

        Parameters:
            parquet_content: Raw bytes
            pii_fields: List of fields to obfuscate

        Raises:
            ValueError: if content is not Parquet format
            ValueError: if pii_fields are not in content
            ValueError: if Parquet is empty
            Exception: process fails

        Returns:
            Obfuscated Parquet content as bytes
        """
        try:
            input_buffer = io.BytesIO(parquet_content)

            try:
                df = pq.read_table(input_buffer).to_pandas()
            except pa.lib.ArrowInvalid:
                raise Exception("Parquet processing failed please check inputs")

            if df.empty:
                raise ValueError("Parquet file appears to be empty")

            missing_fields = [field for field in pii_fields if field not in df.columns]
            if missing_fields:
                raise ValueError(f"Fields not found in Parquet: {missing_fields}")

            for field in pii_fields:
                if field in df.columns:
                    df[field] = "****"

            table = pa.Table.from_pandas(df)
            output_buffer = io.BytesIO()
            pq.write_table(table, output_buffer)

            output_buffer.seek(0)
            return output_buffer.getvalue(), 'application/parquet'

        except ValueError as er_info:
            raise er_info
        except Exception as er_info:
            raise Exception(f"Error processing Parquet: {str(er_info)}")


    def process_request(self, event: Dict) -> Dict:
        """
        Process the obfuscation request

        Parameters:
            Dictionary containing file_to_obfuscate and pii_fields
            
        Raises:
            ValueError: missing file or fields data
            Exception: processing error
            
        Returns
            Dictionary with status code and response body
        """
        try:
            file_to_obfuscate = event.get("file_to_obfuscate")
            pii_fields = event.get("pii_fields", [])

            if not file_to_obfuscate:
                raise ValueError("Missing required parameter: file_to_obfuscate")
            if not pii_fields:
                raise ValueError("Missing required parameter: pii_fields")

            s3_location = self._parse_s3_uri(file_to_obfuscate)
            file_format = self._get_file_format(s3_location["key"])
            content=self._get_file_from_s3(s3_location["bucket"],s3_location["key"])

            if file_format == "csv":
                output_content, content_type = self._obfuscate_csv(content, pii_fields)
                is_base64 = False
            elif file_format == "json":
                output_content, content_type = self._obfuscate_json(content, pii_fields)
                is_base64 = False
            elif file_format == "parquet":
                output_content, content_type = self._obfuscate_parquet(
                    content, pii_fields
                )
                is_base64 = True
                import base64
                output_content = base64.b64encode(output_content).decode('utf-8')
            else:
                raise ValueError(f"Unsupported file format: {file_format}")

            return {
                "statusCode": 200,
                "body": output_content,
                "headers": {"Content-Type": content_type},
                "isBase64Encoded": is_base64,
            }

        except Exception as er_info:
            logger.error(f"Error processing request: {str(er_info)}")
            return {"statusCode": 500, "body": json.dumps({"error": str(er_info)})}


def lambda_handler(event, context):
    """
    AWS Lambda handler for Multi file type obfuscation
    Expected event format:
    {
        "file_to_obfuscate": "s3://bucket/path/file.csv",
        "pii_fields": ["field1", "field2"]
    }
    
    Raises:
        ValueError: is missing login credentials
        Exeption: error handling from the process
    """
    try:
        if isinstance(event, str):
            event = json.loads(event)

        logger.info(f"Processing request: {json.dumps(event)}")

        secret_name = os.environ.get("AWS_SECRET_NAME")
        if not secret_name:
            raise ValueError("AWS_SECRET_NAME is required")

        region = os.environ.get("AWS_REGION", "eu-west-2")

        obfuscator = MultiFormatObfuscator(secret_name=secret_name, region=region)
        return obfuscator.process_request(event)

    except json.JSONDecodeError as er_info:
        logger.error(f"Error parsing JSON input: {str(er_info)}")
        return {"statusCode": 400, "body": json.dumps({"error": "Invalid input"})}

    except Exception as er_info:
        logger.error(f"Unexpected error: {str(er_info)}")
        return {"statusCode": 500, "body": json.dumps({"error": str(er_info)})}
