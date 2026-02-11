import os
from dotenv import load_dotenv

from .aws_utils import AwsUtils


class Config:
    @staticmethod
    def _normalize_env(value: str | None) -> str:
        if not value:
            return "dev"
        return str(value).strip().lower()

    @staticmethod
    def _load_secrets(chamber_of_secrets, region):
        # Prefer process env vars over secrets for ENV/REGION so deployments can override safely.
        env_value = Config._normalize_env(os.getenv("ENV") or chamber_of_secrets.get("ENV"))
        region_value = os.getenv("REGION") or chamber_of_secrets.get("REGION") or region

        # NOTE: keys are read from AWS Secrets Manager SecretString JSON
        return {
            "env": env_value,
            "region": region_value,
            "aws_endpoint": os.getenv("AWS_ENDPOINT") or chamber_of_secrets.get("AWS_ENDPOINT"),
            "bedrock_model_id": os.getenv("BEDROCK_MODEL_ID") or chamber_of_secrets.get("BEDROCK_MODEL_ID"),
            "bedrock_mock": os.getenv("BEDROCK_MOCK") or chamber_of_secrets.get("BEDROCK_MOCK"),

            # Cognito -> Bedrock (non-dev)
            "user_pool_id": os.getenv("USER_POOL_ID") or chamber_of_secrets.get("USER_POOL_ID"),
            "client_id": os.getenv("CLIENT_ID") or chamber_of_secrets.get("CLIENT_ID"),
            "client_secret": os.getenv("CLIENT_SECRET") or chamber_of_secrets.get("CLIENT_SECRET"),
            "identity_pool_id": os.getenv("IDENTITY_POOL_ID") or chamber_of_secrets.get("IDENTITY_POOL_ID"),
            "cognito_username": os.getenv("COGNITO_USERNAME") or chamber_of_secrets.get("COGNITO_USERNAME"),
            "cognito_password": os.getenv("COGNITO_PASSWORD") or chamber_of_secrets.get("COGNITO_PASSWORD"),

            # Endpoint protection
            "api_key": os.getenv("API_KEY") or chamber_of_secrets.get("API_KEY"),
        }

    @staticmethod
    def _load_env_vars():
        return {
            "env": Config._normalize_env(os.getenv("ENV", None)),
            "region": os.getenv("REGION", None),
            "aws_endpoint": os.getenv("AWS_ENDPOINT", None),
            "bedrock_model_id": os.getenv("BEDROCK_MODEL_ID", None),
            "bedrock_mock": os.getenv("BEDROCK_MOCK", None),

            # Cognito -> Bedrock (non-dev)
            "user_pool_id": os.getenv("USER_POOL_ID", None),
            "client_id": os.getenv("CLIENT_ID", None),
            "client_secret": os.getenv("CLIENT_SECRET", None),
            "identity_pool_id": os.getenv("IDENTITY_POOL_ID", None),
            "cognito_username": os.getenv("COGNITO_USERNAME", None),
            "cognito_password": os.getenv("COGNITO_PASSWORD", None),

            # Endpoint protection
            "api_key": os.getenv("API_KEY", None),
        }

    @staticmethod
    def load_config():
        # IMPORTANT:
        # - On Vercel, environment variables set in the dashboard should win.
        # - Do not load/override from a committed .env file on Vercel.
        if not os.getenv("VERCEL"):
            load_dotenv(dotenv_path=".env", override=False)

        SECRET_NAME = os.environ.get("SECRET_NAME", None)
        REGION = os.environ.get("REGION", None)
        AWS_ENDPOINT = os.environ.get("AWS_ENDPOINT", None)

        # Optional: allow fetching secrets using unauth Cognito Identity Pool creds
        IDENTITY_POOL_ID = os.environ.get("IDENTITY_POOL_ID", None)

        aws_utils = AwsUtils(region_name=REGION, aws_endpoint_url=AWS_ENDPOINT, identity_pool_id=IDENTITY_POOL_ID)
        print(
            f"Attempting to load secrets: {SECRET_NAME} from Secrets Manager in region {REGION}, using aws endpoint: {AWS_ENDPOINT}"
        )
        try:
            chamber_of_secrets = aws_utils.get_secrets(SECRET_NAME)
            print(f"Loaded secrets: {SECRET_NAME} from Secrets Manager, using aws endpoint: {AWS_ENDPOINT}")
            return Config._load_secrets(chamber_of_secrets, REGION)
        except Exception as e:
            print(f"Error accessing secrets. Falling back to env vars. {repr(e)}")
            return Config._load_env_vars()
