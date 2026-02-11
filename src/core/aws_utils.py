import boto3
import json
from botocore.exceptions import ClientError


class AwsUtils:
    def __init__(self, region_name, aws_endpoint_url=None, identity_pool_id=None):
        self.region_name = region_name
        self.aws_endpoint_url = aws_endpoint_url
        self.identity_pool_id = identity_pool_id

    def _client_with_identity_pool_creds(self):
        # 1) Get unauth identity
        ident = boto3.client("cognito-identity", region_name=self.region_name)
        identity_id = ident.get_id(IdentityPoolId=self.identity_pool_id)["IdentityId"]

        # 2) Get temp creds
        creds = ident.get_credentials_for_identity(IdentityId=identity_id)["Credentials"]

        # 3) Use temp creds for Secrets Manager
        return boto3.client(
            "secretsmanager",
            region_name=self.region_name,
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretKey"],
            aws_session_token=creds["SessionToken"],
            endpoint_url=self.aws_endpoint_url if self.aws_endpoint_url else None,
        )

    def get_secrets(self, secret_name):
        try:
            # Try default client first (works if AWS_ACCESS_KEY_ID is set)
            session = boto3.session.Session()
            client = session.client("secretsmanager", region_name=self.region_name, endpoint_url=self.aws_endpoint_url)
            resp = client.get_secret_value(SecretId=secret_name)
            return json.loads(resp["SecretString"])

        except Exception as e:
            # Fallback: use Cognito Identity Pool (unauth) credentials
            if not self.identity_pool_id:
                raise e

            try:
                client = self._client_with_identity_pool_creds()
                resp = client.get_secret_value(SecretId=secret_name)
                return json.loads(resp["SecretString"])
            except ClientError as ce:
                raise ce
