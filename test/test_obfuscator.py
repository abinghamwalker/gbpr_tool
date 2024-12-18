import pytest
import boto3
import json
from moto import mock_aws
from botocore.exceptions import ClientError
from src.obfuscator import (
    S3CSVObfuscator,
    SecretsManager,
    lambda_handler,
)

import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

@pytest.fixture
def aws_credentials():
    """Mocked AWS Credentials"""
    return {
        "aws_access_key_id": "testing",
        "aws_secret_access_key": "testing",
        "aws_region": "eu-west-2",
    }


@pytest.fixture
def secret_name():
    """Test secret name"""
    return "test-secret"


@pytest.fixture
def aws_secrets(aws_credentials):
    """Test AWS secrets content"""
    return json.dumps(aws_credentials)


@pytest.fixture
def mock_aws_env(monkeypatch):
    """Mock AWS environment variables"""
    monkeypatch.setenv("AWS_SECRET_NAME", "test-secret")
    monkeypatch.setenv("AWS_REGION", "eu-west-2")


@pytest.fixture
def setup_aws_credentials(aws_credentials):
    """Setup mock AWS credentials"""
    import os

    os.environ["AWS_ACCESS_KEY_ID"] = aws_credentials["aws_access_key_id"]
    os.environ["AWS_SECRET_ACCESS_KEY"] = aws_credentials["aws_secret_access_key"]
    os.environ["AWS_DEFAULT_REGION"] = aws_credentials["aws_region"]


@pytest.fixture
def sample_csv_content():
    """Sample CSV content for testing"""
    return (
        "student_id,name,email_address,course\n"
        "1,John Smith,j.smith@email.com,Software\n"
        "2,Jane Doe,j.doe@email.com,Data\n"
    )


@pytest.fixture
def setup_secrets(aws_secrets):
    """Setup mock Secrets Manager"""
    with mock_aws():
        secrets_client = boto3.client("secretsmanager", region_name="eu-west-2")
        secrets_client.create_secret(Name="test-secret", SecretString=aws_secrets)
        yield secrets_client


@pytest.fixture
def setup_s3(sample_csv_content):
    """Setup mock S3"""
    with mock_aws():
        s3_client = boto3.client("s3", region_name="eu-west-2")
        bucket_name = "test-bucket"
        file_key = "test-data/file1.csv"

        # Create bucket and upload file
        s3_client.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={"LocationConstraint": "eu-west-2"},
        )
        s3_client.put_object(
            Bucket=bucket_name, Key=file_key, Body=sample_csv_content.encode("utf-8")
        )

        yield {"client": s3_client, "bucket": bucket_name, "key": file_key}


class TestSecretsManager:
    """Test suite for SecretsManager class"""

    @mock_aws
    def test_get_secret_success(self, setup_secrets, secret_name):
        """Test successful secret retrieval"""
        secrets_manager = SecretsManager(secret_name)
        secret = secrets_manager.get_secret()
        assert isinstance(secret, dict)
        assert "aws_access_key_id" in secret
        assert "aws_secret_access_key" in secret
        assert "aws_region" in secret

        secrets_manager = SecretsManager(secret_name)
        result = secrets_manager.get_secret()
        assert isinstance(result, dict)

    @mock_aws
    def test_get_secret_value_error(self):
        """Test when SecretString is missing from response"""
        secrets_client = boto3.client("secretsmanager", region_name="eu-west-2")
        
        secret_name = "test-secret"
        secrets_client.create_secret(
            Name=secret_name,
            SecretBinary=b'some binary data'
        )
        
        secrets_manager = SecretsManager(secret_name)

        with pytest.raises(ValueError, match="Secret value is not a string"):
            secrets_manager.get_secret()

    @mock_aws
    def test_get_secret_nonexistent(self):
        """Test retrieval of non-existent secret"""
        secrets_manager = SecretsManager("nonexistent-secret")
        with pytest.raises(ClientError):
            secrets_manager.get_secret()


class TestS3CSVObfuscator:
    """Test suite for S3CSVObfuscator class"""

    def test_parse_s3_uri_valid(
        self, setup_aws_credentials, setup_secrets, secret_name
    ):
        """Test parsing valid S3 URI"""
        obfuscator = S3CSVObfuscator(secret_name=secret_name)
        uri = "s3://test-bucket/path/to/file.csv"
        result = obfuscator._parse_s3_uri(uri)
        assert result["bucket"] == "test-bucket"
        assert result["key"] == "path/to/file.csv"

    def test_parse_s3_uri_invalid(
        self, setup_aws_credentials, setup_secrets, secret_name
    ):
        """Test parsing invalid S3 URI"""
        obfuscator = S3CSVObfuscator(secret_name=secret_name)
        uri = "invalid://test-bucket/file.csv"
        with pytest.raises(ValueError):
            obfuscator._parse_s3_uri(uri)

    def test_secret_name_missing(self):
        """Test constructor raises error when secret_name is None"""
        with pytest.raises(ValueError, match="Log in credentials are required"):
            S3CSVObfuscator(secret_name=None)

    def test_initialise_with_secrets_failure(self):
        with mock_aws():
            secret_name = "test-secret"
            client = boto3.client("secretsmanager")

            client.create_secret(
                Name=secret_name, SecretString=json.dumps({"aws_region": "eu-west-2"})
            )

        with pytest.raises(Exception):
            S3CSVObfuscator(secret_name=secret_name)

    def test_initialise_with_secrets_value_error(self):
        """Test ValueError is raised when aws_access_key_id is missing"""
        with mock_aws():
            secret_name = "test-secret"
            client = boto3.client("secretsmanager")
            
            client.create_secret(
                Name=secret_name,
                SecretString=json.dumps({
                    "aws_secret_access_key": "dummy_secret"
                })
            )
            
            with pytest.raises(ValueError) as e:
                S3CSVObfuscator(secret_name=secret_name)  
            
            assert "Missing required credentials" in str(e.value)
            assert "aws_access_key_id" in str(e.value)

    @mock_aws
    def test_get_csv_from_s3_success(
        self, setup_s3, setup_secrets, secret_name, sample_csv_content
    ):
        """Test successful CSV retrieval from S3"""
        obfuscator = S3CSVObfuscator(secret_name=secret_name)
        content = obfuscator._get_csv_from_s3(setup_s3["bucket"], setup_s3["key"])
        assert content == sample_csv_content

    @mock_aws
    def test_get_csv_from_s3_nonexistent(self, setup_s3, setup_secrets, secret_name):
        """Test retrieval of non-existent CSV"""
        obfuscator = S3CSVObfuscator(secret_name=secret_name)
        with pytest.raises(ClientError):
            obfuscator._get_csv_from_s3("test-bucket", "nonexistent.csv")

    @mock_aws
    def test_obfuscate_csv(self, setup_secrets, secret_name):
        """Test CSV content obfuscation"""
        obfuscator = S3CSVObfuscator(secret_name=secret_name)
        csv_content = (
            "id,name,email,phone\n" "1,John Smith,j.smith@email.com,01234254124\n"
        )
        pii_fields = ["name", "email"]
        result = obfuscator._obfuscate_csv(csv_content, pii_fields)

        assert "John Smith" not in result
        assert "j.smith@email.com" not in result
        assert "01234254124" in result

    @mock_aws
    def test_obfuscate_csv_error(self, setup_secrets, secret_name):
        """Test ValueError when field is not found in CSV headers"""
        obfuscator = S3CSVObfuscator(secret_name=secret_name)
        csv_content = (
            "student_id,name,email_address,course\n"
            "1,John Smith,john@email.com,Software\n"
            "2,Jane Doe,j.doe@email.com,Data\n"
        )
        pii_fields = ["grades"]
        with pytest.raises(ValueError):
            obfuscator._obfuscate_csv(csv_content, pii_fields)

    def test_empty_csv_raises_error(self):
        """Test that empty CSV content raises ValueError"""
        with mock_aws():
            region = "eu-west-2"
            secret_name = "test-secret"
            secrets_client = boto3.client("secretsmanager", region_name=region)

            secrets_client.create_secret(
                Name=secret_name,
                SecretString=json.dumps({
                    "aws_access_key_id": "dummy_key",
                    "aws_secret_access_key": "dummy_secret",
                    "aws_region": region  
                })
            )

            # Pass both secret_name and region
            obfuscator = S3CSVObfuscator(secret_name=secret_name, region=region)
            empty_content = ""
            pii_fields = ["name", "email"]
            
            with pytest.raises(ValueError) as e:
                obfuscator._obfuscate_csv(empty_content, pii_fields)
            
            assert "CSV file appears to be empty" in str(e.value)

    @mock_aws
    def test_process_request_success(self, setup_s3, setup_secrets, secret_name):
        """Test successful request processing"""
        obfuscator = S3CSVObfuscator(secret_name=secret_name)
        event = {
            "file_to_obfuscate": f"s3://{setup_s3['bucket']}/{setup_s3['key']}",
            "pii_fields": ["name", "email_address"],
        }
        result = obfuscator.process_request(event)

        assert result["statusCode"] == 200
        assert "John Smith" not in result["body"]
        assert "Software" in result["body"]

    @mock_aws
    def test_process_request_missing_file_parameter(self, setup_secrets, secret_name):
        """Test request processing with missing file_to_obfuscate parameter"""
        obfuscator = S3CSVObfuscator(secret_name=secret_name)
        event = {"pii_fields": ["name"]}
        result = obfuscator.process_request(event)
        assert result["statusCode"] == 400
        assert "Missing required parameter: file_to_obfuscate" in result["body"]

    @mock_aws
    def test_process_request_missing_pii_fields(self, setup_secrets, secret_name):
        """Test request processing with missing pii_fields parameter"""
        obfuscator = S3CSVObfuscator(secret_name=secret_name)
        event = {"file_to_obfuscate": "s3://bucket/file.csv"}
        result = obfuscator.process_request(event)
        assert result["statusCode"] == 400
        assert "Missing required parameter: pii_fields" in result["body"]


class TestLambdaHandler:
    """Test suite for Lambda handler"""

    @mock_aws
    def test_lambda_handler_success(self, setup_s3, setup_secrets, mock_aws_env):
        """Test successful Lambda execution"""
        event = {
            "file_to_obfuscate": f"s3://{setup_s3['bucket']}/{setup_s3['key']}",
            "pii_fields": ["name", "email_address"],
        }
        result = lambda_handler(event, None)
        assert result["statusCode"] == 200
        assert "John Smith" not in result["body"]

    @mock_aws
    def test_lambda_handler_json_string(self, setup_s3, setup_secrets, mock_aws_env):
        """Test Lambda with JSON string input"""
        event = json.dumps(
            {
                "file_to_obfuscate": f"s3://{setup_s3['bucket']}/{setup_s3['key']}",
                "pii_fields": ["name", "email_address"],
            }
        )
        result = lambda_handler(event, None)
        assert result["statusCode"] == 200

    @mock_aws
    def test_lambda_handler_missing_secret(self, setup_s3):
        """Test lambda handler with missing AWS_SECRET_NAME environment variable"""
        event = json.dumps(
            {
                "file_to_obfuscate": f"s3://{setup_s3['bucket']}/{setup_s3['key']}",
                "pii_fields": ["name", "email_address"],
            }
        )
        result = lambda_handler(event, None)
        assert result["statusCode"] == 500
        assert "AWS_SECRET_NAME is required" in result["body"]

    def test_lambda_handler_invalid_json(self, mock_aws_env):
        """Test Lambda with invalid JSON input"""
        event = "invalid json"
        result = lambda_handler(event, None)
        assert result["statusCode"] == 400
