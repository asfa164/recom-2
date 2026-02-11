# src/core/config.py
import os
from dotenv import load_dotenv

from .aws_utils import AwsUtils


class Config:
    @staticmethod
    def _load_secrets(chamber_of_secrets: dict, region: str) -> dict:
        # ENV: prefer process env (Vercel) over secret; normalize lowercase
        env_value = (os.getenv("ENV") or chamber_of_secrets.get("ENV") or "dev").strip().lower()

        return {
            "env": env_value,
            "region": chamber_of_secrets.get("REGION", region),
            "aws_endpoint": chamber_of_secrets.get("AWS_ENDPOINT"),
            "bedrock_model_id": chamber_of_secrets.get("BEDROCK_MODEL_ID"),
            "bedrock_mock": chamber_of_secrets.get("BEDROCK_MOCK"),
            "api_key": chamber_of_secrets.get("API_KEY"),

            # Cognito -> Bedrock (always used except ENV=local)
            "user_pool_id": chamber_of_secrets.get("USER_POOL_ID"),
            "client_id": chamber_of_secrets.get("CLIENT_ID"),
            "client_secret": chamber_of_secrets.get("CLIENT_SECRET"),
            "identity_pool_id": chamber_of_secrets.get("IDENTITY_POOL_ID"),
            "cognito_username": chamber_of_secrets.get("COGNITO_USERNAME"),
            "cognito_password": chamber_of_secrets.get("COGNITO_PASSWORD"),
        }

    @staticmethod
    def _load_env_vars() -> dict:
        env_value = (os.getenv("ENV") or "dev").strip().lower()
        return {
            "env": env_value,
            "region": os.getenv("REGION", None),
            "aws_endpoint": os.getenv("AWS_ENDPOINT", None),
            "bedrock_model_id": os.getenv("BEDROCK_MODEL_ID", None),
            "bedrock_mock": os.getenv("BEDROCK_MOCK", None),
            "api_key": os.getenv("API_KEY", None),

            "user_pool_id": os.getenv("USER_POOL_ID", None),
            "client_id": os.getenv("CLIENT_ID", None),
            "client_secret": os.getenv("CLIENT_SECRET", None),
            "identity_pool_id": os.getenv("IDENTITY_POOL_ID", None),
            "cognito_username": os.getenv("COGNITO_USERNAME", None),
            "cognito_password": os.getenv("COGNITO_PASSWORD", None),
        }

    @staticmethod
    def load_config() -> dict:
        # Only load local .env outside Vercel; never override real env vars
        if not os.getenv("VERCEL"):
            load_dotenv(dotenv_path=".env", override=False)

        secret_name = os.environ.get("SECRET_NAME", None)
        region = os.environ.get("REGION", None)
        aws_endpoint = os.environ.get("AWS_ENDPOINT", None)

        # Cognito bootstrap inputs (Option B)
        identity_pool_id = os.environ.get("IDENTITY_POOL_ID", None)
        user_pool_id = os.environ.get("USER_POOL_ID", None)
        client_id = os.environ.get("CLIENT_ID", None)
        client_secret = os.environ.get("CLIENT_SECRET", None)
        cognito_username = os.environ.get("COGNITO_USERNAME", None)
        cognito_password = os.environ.get("COGNITO_PASSWORD", None)

        if secret_name and region:
            aws_utils = AwsUtils(
                region_name=region,
                aws_endpoint_url=aws_endpoint,
                identity_pool_id=identity_pool_id,
                user_pool_id=user_pool_id,
                client_id=client_id,
                client_secret=client_secret,
                cognito_username=cognito_username,
                cognito_password=cognito_password,
            )
            try:
                chamber_of_secrets = aws_utils.get_secrets(secret_name)
                return Config._load_secrets(chamber_of_secrets, region)
            except Exception:
                # Fall back to env vars
                return Config._load_env_vars()

        return Config._load_env_vars()
