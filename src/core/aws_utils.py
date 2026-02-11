# src/core/aws_utils.py
import base64
import hashlib
import hmac
import json
from typing import Optional

import boto3
from botocore.exceptions import ClientError


class AwsUtils:
    """
    Secrets Manager loader with Cognito bootstrap.

    Order:
      1) Try Secrets Manager with default boto3 credentials (AWS_* env vars / instance role).
      2) If that fails and IDENTITY_POOL_ID is provided:
         - If USER_POOL_ID/CLIENT_ID/COGNITO_USERNAME/COGNITO_PASSWORD provided -> authenticated Identity Pool creds
         - else -> unauthenticated Identity Pool creds
         - Use temp creds to call Secrets Manager.
    """

    def __init__(
        self,
        region_name: str,
        aws_endpoint_url: Optional[str] = None,
        identity_pool_id: Optional[str] = None,
        user_pool_id: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        cognito_username: Optional[str] = None,
        cognito_password: Optional[str] = None,
    ):
        self.region_name = region_name
        self.aws_endpoint_url = aws_endpoint_url

        self.identity_pool_id = identity_pool_id
        self.user_pool_id = user_pool_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.cognito_username = cognito_username
        self.cognito_password = cognito_password

    def _compute_secret_hash(self, username: str) -> Optional[str]:
        if not self.client_secret or not self.client_id:
            return None
        msg = (username + self.client_id).encode("utf-8")
        key = self.client_secret.encode("utf-8")
        dig = hmac.new(key, msg, hashlib.sha256).digest()
        return base64.b64encode(dig).decode("utf-8")

    def _get_id_token(self) -> str:
        if not (self.client_id and self.cognito_username and self.cognito_password):
            raise ValueError("Missing Cognito User Pool login config to obtain IdToken")

        idp = boto3.client("cognito-idp", region_name=self.region_name)
        auth_params = {"USERNAME": self.cognito_username, "PASSWORD": self.cognito_password}
        secret_hash = self._compute_secret_hash(self.cognito_username)
        if secret_hash:
            auth_params["SECRET_HASH"] = secret_hash

        auth = idp.initiate_auth(
            AuthFlow="USER_PASSWORD_AUTH",
            ClientId=self.client_id,
            AuthParameters=auth_params,
        )
        return auth["AuthenticationResult"]["IdToken"]

    def _get_identity_creds(self) -> dict:
        if not self.identity_pool_id:
            raise ValueError("IDENTITY_POOL_ID is required for Cognito bootstrap credentials")

        ident = boto3.client("cognito-identity", region_name=self.region_name)

        # Use authenticated identity if we have enough info; otherwise unauth identity.
        use_auth = all(
            [
                self.user_pool_id,
                self.client_id,
                self.cognito_username,
                self.cognito_password,
            ]
        )

        if use_auth:
            if not self.user_pool_id:
                raise ValueError("USER_POOL_ID is required for authenticated Cognito Identity bootstrap")
            id_token = self._get_id_token()
            provider = f"cognito-idp.{self.region_name}.amazonaws.com/{self.user_pool_id}"

            identity_id = ident.get_id(
                IdentityPoolId=self.identity_pool_id,
                Logins={provider: id_token},
            )["IdentityId"]

            creds = ident.get_credentials_for_identity(
                IdentityId=identity_id,
                Logins={provider: id_token},
            )["Credentials"]
            return creds

        # Unauthenticated identity pool credentials
        identity_id = ident.get_id(IdentityPoolId=self.identity_pool_id)["IdentityId"]
        creds = ident.get_credentials_for_identity(IdentityId=identity_id)["Credentials"]
        return creds

    def _secretsmanager_client_with_identity_pool(self):
        creds = self._get_identity_creds()

        kwargs = dict(
            service_name="secretsmanager",
            region_name=self.region_name,
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretKey"],
            aws_session_token=creds["SessionToken"],
        )
        if self.aws_endpoint_url:
            kwargs["endpoint_url"] = self.aws_endpoint_url
        return boto3.client(**kwargs)

    def _secretsmanager_client_default(self):
        session = boto3.session.Session()
        kwargs = dict(service_name="secretsmanager", region_name=self.region_name)
        if self.aws_endpoint_url:
            kwargs["endpoint_url"] = self.aws_endpoint_url
        return session.client(**kwargs)

    def get_secrets(self, secret_name: str) -> dict:
        # 1) Default credentials attempt
        try:
            client = self._secretsmanager_client_default()
            resp = client.get_secret_value(SecretId=secret_name)
            return json.loads(resp["SecretString"])
        except Exception as first_err:
            # 2) Cognito bootstrap fallback (Identity Pool)
            if not self.identity_pool_id:
                raise first_err

            try:
                client = self._secretsmanager_client_with_identity_pool()
                resp = client.get_secret_value(SecretId=secret_name)
                return json.loads(resp["SecretString"])
            except ClientError as e:
                raise e
            except Exception as e:
                raise e
