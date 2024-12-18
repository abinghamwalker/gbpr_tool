import json
import csv
import io
import os
import boto3
import logging
from typing import Dict, List
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)


class SecretsManager:
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
            raise ValueError("Secret value is not a string")

        except ClientError as e:
            logger.error(f"Error retrieving secret: {str(e)}")
            raise


class S3CSVObfuscator:
    def __init__(self, secret_name: str = None, region: str = "eu-west-2"):
        """
        Initialise the S3CSVObfuscator with an S3 client
        """
        self.s3_client = None
        if not secret_name:
            raise ValueError("Log in credentials are required")

        self._initialise_with_secrets(secret_name, region)

    def _initialise_with_secrets(self, secret_name: str, region: str):
        """
        Initialise AWS client with credentials from Secrets Manager
        
        Raises:
         Exception: If initialization fails
        """
        try:
            secrets_manager = SecretsManager(secret_name, region)
            credentials = secrets_manager.get_secret()

            required_keys = ["aws_access_key_id", "aws_secret_access_key"]
            missing_keys = [key for key in required_keys if key not in credentials]
            if missing_keys:
                raise ValueError(f"Missing required credentials: {missing_keys}")

            session = boto3.Session(
                aws_access_key_id=credentials["aws_access_key_id"],
                aws_secret_access_key=credentials["aws_secret_access_key"],
                region_name=credentials.get("aws_region", region),
            )

            self.s3_client = session.client("s3")
            logger.info("Successfully initialised S3 client")
        except Exception as e:
            logger.error(f"Error initializing with secrets: {str(e)}")
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
            
        return {"bucket": parts[0], "key": parts[1]}

    def _get_csv_from_s3(self, bucket: str, key: str) -> str:
        """
        Retrieve CSV content from S3

        Parameters:
            bucket: S3 bucket name
            key: S3 object key
            
        Raises:
            Exception: Error handling in file retrieval
            
        Returns:
            CSV content as string
        """
        try:
            response = self.s3_client.get_object(Bucket=bucket, Key=key)
            return response["Body"].read().decode("utf-8")
        except Exception as e:
            logger.error(f"Error retrieving file from S3: {str(e)}")
            raise

    def _obfuscate_csv(self, content: str, pii_fields: List[str]) -> str:
        """
        Obfuscate specified fields in CSV content

        Parameters:
            content: Raw CSV content
            pii_fields: List of fields to obfuscate
            
        Raises:
            ValueError: if pii_fields are not in headers or CSV is empty
            Exception: if processing fails
            
        Returns:
            Obfuscated CSV content as string
        """
        try:
            csv_str = content.decode('utf-8') if isinstance(content, bytes) else content
            input_file = io.StringIO(csv_str)
            output_file = io.StringIO()

            reader = csv.DictReader(input_file)
            if not reader.fieldnames:
                raise ValueError("CSV file appears to be empty")

            missing_fields = [field for field in pii_fields if field not in reader.fieldnames]
            if missing_fields:
                raise ValueError(f"Fields not found in CSV: {missing_fields}")

            writer = csv.DictWriter(output_file, fieldnames=reader.fieldnames)
            writer.writeheader()

            # Process rows
            for row in reader:
                for field in pii_fields:
                    row[field] = "****"
                writer.writerow(row)

            return output_file.getvalue()

        except Exception as e:
            logger.error(f"Error processing CSV: {str(e)}")
            raise

    def process_request(self, event: Dict) -> Dict:
        """
        Process the obfuscation request

        Parameters:
            Dictionary containing file_to_obfuscate and pii_fields
            
        Raises:
            ValueError: missing file or fields data
            Exception: processing error
            
        Returns:
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
            csv_content = self._get_csv_from_s3(s3_location["bucket"], s3_location["key"])
            obfuscated_content = self._obfuscate_csv(csv_content, pii_fields)

            return {
                "statusCode": 200,
                "body": obfuscated_content,
                "headers": {"Content-Type": "text/csv"},
            }

        except ValueError as e:
            logger.error(f"Validation error: {str(e)}")
            return {"statusCode": 400, "body": json.dumps({"error": str(e)})}


def lambda_handler(event, context):
    """
    AWS Lambda handler for CSV obfuscation
    Expected event format:
    {
        "file_to_obfuscate": "s3://bucket/path/file.csv",
        "pii_fields": ["field1", "field2"]
    }
    """
    try:
        if isinstance(event, str):
            event = json.loads(event)

        logger.info(f"Processing request: {json.dumps(event)}")

        secret_name = os.environ.get("AWS_SECRET_NAME")
        if not secret_name:
            raise ValueError("AWS_SECRET_NAME is required")

        region = os.environ.get("AWS_REGION", "eu-west-2")

        obfuscator = S3CSVObfuscator(secret_name=secret_name, region=region)
        return obfuscator.process_request(event)

    except json.JSONDecodeError as e:
        logger.error(f"Error parsing JSON input: {str(e)}")
        return {"statusCode": 400, "body": json.dumps({"error": "Invalid JSON input"})}

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        return {"statusCode": 500, "body": json.dumps({"error": str(e)})}
