import pytest
import boto3
import json
import io
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq
from moto import mock_aws
from unittest.mock import Mock, patch
from botocore.exceptions import ClientError
from src.multi_type_obfuscator import (
    MultiFormatObfuscator,
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
def sample_csv():
    """Sample CSV content for testing"""
    return (
        "student_id,name,email_address,course\n"
        "1,John Smith,j.smith@email.com,Software\n"
        "2,Jane Doe,jane@email.com,Data\n"
    )


@pytest.fixture
def sample_json():
    """Sample JSON content for testing"""
    return """[
        {"student_id": "1", "name": "John Smith", "email": "j.smith@email.com", "course": "Data"},
        {"student_id": "2", "name": "Jane Doe", "email": "j.doe@email.com", "course": "Software"}
    ]"""

@pytest.fixture
def sample_parquet():
    """Sample Parquet content for testing"""
    df = pd.DataFrame({
        'student_id': ['1', '2'],
        'name': ['John Smith', 'Jane Doe'],
        'email': ['j.smith@email.com', 'j.doe@email.com'],
        'course': ['Data', 'Software']
    })
    table = pa.Table.from_pandas(df)
    buf = io.BytesIO()
    pq.write_table(table, buf)
    return buf.getvalue()


@pytest.fixture
def setup_secrets(aws_secrets):
    """Setup mock Secrets Manager"""
    with mock_aws():
        secrets_client = boto3.client("secretsmanager", region_name="eu-west-2")
        secrets_client.create_secret(Name="test-secret", SecretString=aws_secrets)
        secrets_client.create_secret(Name="dummy_secret", SecretString=aws_secrets)
        yield secrets_client


@pytest.fixture
def setup_s3(sample_csv):
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
            Bucket=bucket_name, Key=file_key, Body=sample_csv.encode("utf-8")
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
    def test_get_secret_nonexistent(self):
        """Test retrieval of non-existent secret"""
        secrets_manager = SecretsManager("nonexistent-secret")
        with pytest.raises(ClientError):
            secrets_manager.get_secret()


class TestMultiFormatObfuscator:
    """Test suite MultiFormatObfuscator class"""

    def test_parse_s3_uri_valid(
        self, setup_aws_credentials, setup_secrets, secret_name
    ):
        """Test parsing valid S3 URI"""
        multi_obfuscator = MultiFormatObfuscator(secret_name=secret_name)
        uri = "s3://test-bucket/path/to/file.csv"
        result = multi_obfuscator._parse_s3_uri(uri)
        assert result["bucket"] == "test-bucket"
        assert result["key"] == "path/to/file.csv"

    def test_parse_s3_uri_invalid(
        self, setup_aws_credentials, setup_secrets, secret_name
    ):
        """Test parsing invalid S3 URI"""
        multi_obfuscator = MultiFormatObfuscator(secret_name=secret_name)
        uri = "invalid://test-bucket/file.csv"
        with pytest.raises(ValueError):
            multi_obfuscator._parse_s3_uri(uri)

    def test_secret_name_missing(self):
        """Test constructor raises error when secret_name is None"""
        with pytest.raises(ValueError, match="Log in credentials are required"):
            MultiFormatObfuscator(secret_name=None)

    def test_initialise_with_secrets_failure(self):
        """Test the secrets manager failure"""
        with mock_aws():
            secret_name = "test-secret"
            client = boto3.client("secretsmanager")

            client.create_secret(
                Name=secret_name, SecretString=json.dumps({"aws_region": "eu-west-2"})
            )

        with pytest.raises(Exception):
            MultiFormatObfuscator(secret_name=secret_name)

    @mock_aws
    def test_get_file_from_s3_success(
        self, setup_s3, setup_secrets, secret_name, sample_csv
    ):
        """Test successful file retrieval from S3"""
        multi_obfuscator = MultiFormatObfuscator(secret_name=secret_name)
        content = multi_obfuscator._get_file_from_s3(
            setup_s3["bucket"], setup_s3["key"]
        )
        result = content.decode()
        assert result == sample_csv

    @mock_aws
    def test_get_file_from_s3_nonexistent(self, setup_s3, setup_secrets, secret_name):
        """Test retrieval of non-existent file"""
        multi_obfuscator = MultiFormatObfuscator(secret_name=secret_name)
        with pytest.raises(ClientError):
            multi_obfuscator._get_file_from_s3("test-bucket", "nonexistent.csv")

    @mock_aws
    @pytest.mark.parametrize(
        "file_path,expected_format",
        [
            ("data/test.csv", "csv"),
            ("data/test_data.json", "json"),
            ("my_data.parquet", "parquet"),
            ("TEST.CSV", "csv"),
            ("/data.JSON", "json"),
        ]
    )
    def test_get_file_format_success(self, setup_secrets, file_path, expected_format):
        """Test successful file format detection for supported types"""
        multi_obfuscator = MultiFormatObfuscator(secret_name="dummy_secret")
        result = multi_obfuscator._get_file_format(file_path)
        assert result == expected_format

    @mock_aws
    @pytest.mark.parametrize(
        "file_path",
        [
            "data/data.txt",
            "data/file.xlsx",
            "data"
        ]
    )
    def test_get_file_format_invalid(self, setup_secrets, file_path):
        """Test ValueError is raised for unsupported file formats"""
        multi_obfuscator = MultiFormatObfuscator(secret_name="dummy_secret")
        with pytest.raises(ValueError) as e:
            multi_obfuscator._get_file_format(file_path)
        assert "Unsupported file format:" in str(e.value)


    @mock_aws
    def test_csv_obfuscation(self, setup_secrets, sample_csv):
        """Test CSV obfuscation"""
        multi_obfuscator = MultiFormatObfuscator(secret_name="dummy_secret")
        pii_fields = ['name', 'course']
        result, content_type = multi_obfuscator.obfuscate_data(sample_csv, 'csv', pii_fields)
        
        assert content_type == 'text/csv'
        df = pd.read_csv(io.StringIO(result))
        
        assert df['student_id'][0] == 1
        assert df['name'][0] == '****'
        assert df['course'][0] == '****'
        assert len(df) == 2


    @mock_aws
    def test_non_supported_file_obfuscation(self, setup_secrets, sample_csv):
        """Test Wrong file type fails obfuscation"""
        multi_obfuscator = MultiFormatObfuscator(secret_name="dummy_secret")
        pii_fields = ['name', 'email']
        
        with pytest.raises(ValueError) as e:
            multi_obfuscator.obfuscate_data(sample_csv, 'haha', pii_fields)
        assert "Unsupported file format:" in str(e.value)
        


    @mock_aws
    def test_json_obfuscation(self, setup_secrets, sample_json):
        """Test JSON obfuscation"""

        multi_obfuscator = MultiFormatObfuscator(secret_name="dummy_secret")
        pii_fields = ['name', 'email']
        
        result, content_type = multi_obfuscator.obfuscate_data(sample_json, 'json', pii_fields)
        
        assert content_type == 'application/json'
        json_data = json.loads(result)
        
        assert isinstance(json_data, list)
        
        assert json_data[0]['student_id'] == '1'
        assert json_data[0]['name'] == '****'
        assert json_data[0]['email'] == '****'
        assert json_data[0]['course'] == 'Data'
        
        assert json_data[1]['student_id'] == '2'
        assert json_data[1]['name'] == '****'
        assert json_data[1]['email'] == '****'
        assert json_data[1]['course'] == 'Software'

    @mock_aws
    def test_parquet_obfuscation(self, setup_secrets, sample_parquet):
        """Test Parquet obfuscation"""
        multi_obfuscator = MultiFormatObfuscator(secret_name="dummy_secret")
        pii_fields = ['name', 'email']
        
        result, content_type = multi_obfuscator.obfuscate_data(sample_parquet, 'parquet', pii_fields)
        table = pq.read_table(io.BytesIO(result))
        df = table.to_pandas()
        
        assert not df.empty
        assert len(df) == 2
        
        assert df['student_id'].iloc[0] == '1'
        assert df['name'].iloc[0] == '****'
        assert df['email'].iloc[0] == '****'
        assert df['course'].iloc[0] == 'Data'
        assert content_type == 'application/parquet'

    @mock_aws
    def test_parquet_obfuscation_invalid_format(self, setup_secrets):
        """Test Parquet obfuscation with invalid format"""
        multi_obfuscator = MultiFormatObfuscator(secret_name="dummy_secret")
        invalid_parquet = b'not a parquet file'
        pii_fields = ['name']
        
        with pytest.raises(Exception) as e:
            multi_obfuscator.obfuscate_data(invalid_parquet, 'parquet', pii_fields)
        assert "Parquet processing failed please check inputs" in str(e.value)


    @mock_aws     
    def test_parquet_obfuscation_missing_fields(self, setup_secrets, sample_parquet):
        """Test Parquet obfuscation with missing fields"""
        multi_obfuscator = MultiFormatObfuscator(secret_name="dummy_secret")
        pii_fields = ['nonexistent_field']
        
        with pytest.raises(ValueError) as e:
            multi_obfuscator.obfuscate_data(sample_parquet, 'parquet', pii_fields)
        
        assert "Fields not found in Parquet: ['nonexistent_field']" in str(e.value)


    @mock_aws
    def test_parquet_obfuscation_empty_file(self, setup_secrets):
        """Test Parquet obfuscation with empty file"""
        multi_obfuscator = MultiFormatObfuscator(secret_name="dummy_secret")

        empty_df = pd.DataFrame()
        table = pa.Table.from_pandas(empty_df)
        buffer = io.BytesIO()
        pq.write_table(table, buffer)
        empty_parquet = buffer.getvalue()

        pii_fields = ['name']

        with pytest.raises(ValueError, match="Parquet file appears to be empty"):
            multi_obfuscator.obfuscate_data(empty_parquet, 'parquet', pii_fields)

    @mock_aws
    def test_csv_is_empty(self, setup_secrets):
        """Test if we use an empty csv specifically in _obfuscate_csv"""
        multi_obfuscator = MultiFormatObfuscator(secret_name="dummy_secret")
        empty_csv = b""
        pii_fields = 'name'

        with pytest.raises(ValueError) as e:
            multi_obfuscator._obfuscate_csv(empty_csv, pii_fields)
        assert str(e.value) == "CSV file appears to be empty"

    @mock_aws
    def test_empty_json(self, setup_secrets):
        """Test for empty JSON processing"""
        multi_obfuscator = MultiFormatObfuscator(secret_name="dummy_secret")
        
        empty_json = b""
        pii_fields = ["name"]
        
        with pytest.raises(ValueError) as e:
            multi_obfuscator._obfuscate_json(empty_json, pii_fields)
        assert str(e.value) == "Invalid JSON format"

    @mock_aws
    def test_parquet_is_empty(self,setup_secrets):
        """ Test if the parquet is empty in _obfuscate parquet method"""
        multi_obfuscator = MultiFormatObfuscator(secret_name="dummy_secret")

        empty_df = pd.DataFrame()
        table = pa.Table.from_pandas(empty_df)
        buffer = io.BytesIO()
        pq.write_table(table, buffer)
        empty_parquet = buffer.getvalue()
        pii_fields = ['name']

        with pytest.raises(ValueError, match="Parquet file appears to be empty"):
            multi_obfuscator._obfuscate_parquet(empty_parquet, pii_fields)

    @mock_aws
    def test_corrupted_parquet(self, setup_secrets):
        """Test handling of corrupted Parquet file"""
        multi_obfuscator = MultiFormatObfuscator(secret_name="dummy_secret")
        
        df = pd.DataFrame({"field1": ["data1"], "field2": ["data2"]})
        buffer = io.BytesIO()
        df.to_parquet(buffer)
        
        corrupted_content = buffer.getvalue()[:-10]
        
        with pytest.raises (Exception) as e:
            multi_obfuscator._obfuscate_parquet(corrupted_content, ["field1"])
            assert "Parquet processing failed please check inputs" in str(e.value)


    @mock_aws
    def test_csv_fields_not_found(self, sample_csv,setup_secrets):
        """Test if we are missingfield in csv specifically in _obfuscate_csv"""
        multi_obfuscator = MultiFormatObfuscator(secret_name="dummy_secret")
        pii_fields = ['FALSE_FIELDS']

        with pytest.raises(ValueError) as e:
            multi_obfuscator._obfuscate_csv(sample_csv, pii_fields)
        assert str(e.value) == "Fields not found in CSV: FALSE_FIELDS"

    @mock_aws
    def test_json_fields_not_found(self, sample_csv,setup_secrets):
        """Test if we are missingfield in json specifically in _obfuscate_json"""
        multi_obfuscator = MultiFormatObfuscator(secret_name="dummy_secret")
        pii_fields = ['FALSE_FIELDS']

        with pytest.raises(ValueError) as e:
            multi_obfuscator._obfuscate_json(sample_csv, pii_fields)
        assert str(e.value) == "Invalid JSON format"

    @mock_aws
    def test_process_request_success(self, setup_s3, setup_secrets, secret_name):
        """Test successful request processing"""
        multi_obfuscator = MultiFormatObfuscator(secret_name=secret_name)
        event = {
            "file_to_obfuscate": f"s3://{setup_s3['bucket']}/{setup_s3['key']}",
            "pii_fields": ["name", "email_address"],
        }
        result = multi_obfuscator.process_request(event)

        assert result["statusCode"] == 200
        assert "John Smith" not in result["body"]
        assert "Software" in result["body"]

    @mock_aws
    def test_process_request_missing_file_parameter(self, setup_secrets, secret_name):
        """Test request processing with missing file_to_obfuscate parameter"""
        multi_obfuscator = MultiFormatObfuscator(secret_name=secret_name)
        event = {"pii_fields": ["name"]}
        result = multi_obfuscator.process_request(event)
        assert result["statusCode"] == 500
        assert "Missing required parameter: file_to_obfuscate" in result["body"]

    @mock_aws
    def test_process_request_missing_pii_fields(self, setup_secrets, secret_name):
        """Test request processing with missing pii_fields parameter"""
        multi_obfuscator = MultiFormatObfuscator(secret_name=secret_name)
        event = {"file_to_obfuscate": "s3://bucket/file.csv"}
        result = multi_obfuscator.process_request(event)
        assert result["statusCode"] == 500
        assert "Missing required parameter: pii_fields" in result["body"]

    @mock_aws
    def test_process_request_incorrect_file_type(self, setup_secrets, secret_name, setup_s3):
        """Test request processing with incorrect file type"""
        multi_obfuscator = MultiFormatObfuscator(secret_name=secret_name)
        
        s3_client = setup_s3["client"]
        bucket_name = setup_s3["bucket"]
        
        jpeg_key = "test-data/file.jpeg"
        s3_client.put_object(Bucket=bucket_name, Key=jpeg_key, Body=b"test content")
        
        multi_obfuscator._get_file_format = Mock(return_value="jpeg")
        
        event = {
            "file_to_obfuscate": f"s3://{bucket_name}/{jpeg_key}",
            "pii_fields": ["field"]
        }
        
        result = multi_obfuscator.process_request(event)
        assert "Unsupported file format: jpeg" in str(result)

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