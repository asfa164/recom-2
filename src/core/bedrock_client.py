"""
Bedrock Runtime client.
Mock implementation when BEDROCK_MOCK or MOCK_MODE is set.
"""

import json
import boto3
from botocore.exceptions import ClientError

class BedrockClient:
    """Invoke Bedrock models; supports LocalStack via endpoint_url."""

    def __init__(self, region_name: str, endpoint_url: str | None = None):
        self.region_name = region_name
        self.endpoint_url = endpoint_url
        self._client = None

    @property
    def client(self):
        if self._client is None:
            kwargs = {
                "service_name": "bedrock-runtime",
                "region_name": self.region_name,
            }
            if self.endpoint_url:
                kwargs["endpoint_url"] = self.endpoint_url
            self._client = boto3.client(**kwargs)
        return self._client

    def invoke_model(
        self,
        model_id: str,
        body: dict | bytes,
        content_type: str = "application/json",
        accept: str = "application/json",
    ) -> dict:
        """
        Invoke the model. body can be a dict (JSON-serialized) or bytes.
        Returns the parsed response body as a dict when accept is application/json.
        """
        if isinstance(body, dict):
            body = json.dumps(body).encode("utf-8")
        response = self.client.invoke_model(
            modelId=model_id,
            body=body,
            contentType=content_type,
            accept=accept,
        )
        response_body = response["body"].read()
        if accept == "application/json":
            return json.loads(response_body.decode("utf-8"))
        return {"raw": response_body.decode("utf-8")}
