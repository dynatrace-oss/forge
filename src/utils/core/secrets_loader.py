import boto3
import json
import logging
import os
        
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)


def load_secrets_into_environment():
    """
    Load secrets into os.environ from AWS Secrets Manager or .env file.

    - If USE_AWS_SECRETS=true: Load from AWS Secrets Manager
    - Otherwise: Rely on .env file (already loaded by dotenv)
    """
    use_aws = os.getenv("USE_AWS_SECRETS", "false").lower() == "true"

    if not use_aws:
        logger.info("Using local .env file for configuration")
        return

    aws_region = os.getenv("AWS_REGION", "us-east-1")
    secret_name = os.getenv("AWS_SECRETS_NAME", "forge/api-keys")

    try:
        logger.info(f"Loading secrets from AWS Secrets Manager ({secret_name} in {aws_region})")

        client = boto3.client('secretsmanager', region_name=aws_region)
        response = client.get_secret_value(SecretId=secret_name)

        if 'SecretString' in response:
            secrets = json.loads(response['SecretString'])

            for key, value in secrets.items():
                os.environ[key] = value

            logger.info(f"Successfully loaded {len(secrets)} secrets from AWS Secrets Manager")
        else:
            logger.error("AWS secret does not contain SecretString")

    except ImportError:
        logger.error("boto3 not installed - install with: poetry add boto3")
    except ClientError as e:
        logger.error(f"Failed to load secrets from AWS Secrets Manager: {e}")
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse AWS secret as JSON: {e}")
    except Exception as e:
        logger.error(f"Unexpected error loading AWS secrets: {e}")
