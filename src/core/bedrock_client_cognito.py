"""Cognito-authenticated Bedrock Runtime client.

Use this in non-dev environments when you want to reach Bedrock using temporary AWS
credentials minted via Cognito (User Pool -> Identity Pool).

This keeps dev simple (use the local mock), and avoids long-lived AWS access keys.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from typing import Any

import boto3


@dataclass
class _CachedBedrock:
    client: Any
    exp_epoch: float


class BedrockClient:
    """Invoke Bedrock models using temporary creds obtained through Cognito."""

    def __init__(
        self,
        region_name: str,
        config: dict,
        endpoint_url: str | None = None,
        refresh_skew_seconds: int = 60,
    ):
        self.region_name = region_name
        self.endpoint_url = endpoint_url
        self.config = config
        self.refresh_skew_seconds = refresh_skew_seconds
        self._cached: _CachedBedrock | None = None

    # -------- Cognito helpers --------
    def _compute_secret_hash(self, username: str) -> str | None:
        """Compute Cognito SECRET_HASH only when a client secret is configured."""
        client_secret = self.config.get("client_secret")
        client_id = self.config.get("client_id")
        if not client_secret or not client_id:
            return None
        msg = (username + client_id).encode("utf-8")
        key = client_secret.encode("utf-8")
        dig = hmac.new(key, msg, hashlib.sha256).digest()
        return base64.b64encode(dig).decode("utf-8")

    def _get_temp_credentials(self) -> tuple[str, str, str, float]:
        """Return (access_key, secret_key, session_token, exp_epoch)."""
        username = self.config.get("cognito_username")
        password = self.config.get("cognito_password")
        user_pool_id = self.config.get("user_pool_id")
        client_id = self.config.get("client_id")
        identity_pool_id = self.config.get("identity_pool_id")

        missing = [
            k
            for k, v in {
                "cognito_username": username,
                "cognito_password": password,
                "user_pool_id": user_pool_id,
                "client_id": client_id,
                "identity_pool_id": identity_pool_id,
            }.items()
            if not v
        ]
        if missing:
            raise ValueError(
                "Missing required Cognito config keys: " + ", ".join(missing)
            )

        idp = boto3.client("cognito-idp", region_name=self.region_name)
        auth_params: dict[str, str] = {"USERNAME": username, "PASSWORD": password}
        secret_hash = self._compute_secret_hash(username)
        if secret_hash:
            auth_params["SECRET_HASH"] = secret_hash

        auth = idp.initiate_auth(
            AuthFlow="USER_PASSWORD_AUTH",
            ClientId=client_id,
            AuthParameters=auth_params,
        )
        id_token = auth["AuthenticationResult"]["IdToken"]

        provider = f"cognito-idp.{self.region_name}.amazonaws.com/{user_pool_id}"
        ident = boto3.client("cognito-identity", region_name=self.region_name)
        identity_id = ident.get_id(
            IdentityPoolId=identity_pool_id,
            Logins={provider: id_token},
        )["IdentityId"]

        creds = ident.get_credentials_for_identity(
            IdentityId=identity_id,
            Logins={provider: id_token},
        )["Credentials"]

        access_key = creds["AccessKeyId"]
        secret_key = creds["SecretKey"]
        session_token = creds["SessionToken"]

        # boto3 returns Expiration as datetime; handle robustly
        exp = creds.get("Expiration")
        exp_epoch = exp.timestamp() if hasattr(exp, "timestamp") else (time.time() + 900)
        return access_key, secret_key, session_token, float(exp_epoch)

    # -------- Bedrock runtime --------
    def _get_bedrock_client(self):
        now = time.time()
        if self._cached and now < (self._cached.exp_epoch - self.refresh_skew_seconds):
            return self._cached.client

        access_key, secret_key, session_token, exp_epoch = self._get_temp_credentials()
        kwargs: dict[str, Any] = {
            "service_name": "bedrock-runtime",
            "region_name": self.region_name,
            "aws_access_key_id": access_key,
            "aws_secret_access_key": secret_key,
            "aws_session_token": session_token,
        }
        if self.endpoint_url:
            kwargs["endpoint_url"] = self.endpoint_url

        client = boto3.client(**kwargs)
        self._cached = _CachedBedrock(client=client, exp_epoch=exp_epoch)
        return client

    def invoke_model(
        self,
        model_id: str,
        body: dict | bytes,
        content_type: str = "application/json",
        accept: str = "application/json",
    ) -> dict:
        """Invoke the model. body can be a dict (JSON-serialized) or bytes."""
        if isinstance(body, dict):
            body = json.dumps(body).encode("utf-8")

        response = self._get_bedrock_client().invoke_model(
            modelId=model_id,
            body=body,
            contentType=content_type,
            accept=accept,
        )
        response_body = response["body"].read()
        if accept == "application/json":
            return json.loads(response_body.decode("utf-8"))
        return {"raw": response_body.decode("utf-8")}
