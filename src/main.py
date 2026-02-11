from fastapi import FastAPI, HTTPException, Depends
from fastapi.security.api_key import APIKeyHeader

from core.config import Config
from core.bedrock_client_cognito import BedrockClient as CognitoBedrockClient
from local.bedrock_client import BedrockClient as LocalBedrockClient

from inference.recommendation import (
    recommend_objective,
    SimpleObjectiveRequest,
    SimpleRecommendResponse,
)

config = Config.load_config()
env = (config.get("env") or "dev").lower()

# ✅ Always use Cognito unless local
if env == "local":
    print("Using LOCAL mock Bedrock client (ENV=local)")
    bedrock_client = LocalBedrockClient(region_name=config["region"], endpoint_url=config.get("aws_endpoint"))
else:
    print(f"Using COGNITO Bedrock client (ENV={env})")
    bedrock_client = CognitoBedrockClient(
        region_name=config["region"],
        config=config,
        endpoint_url=config.get("aws_endpoint"),
    )

app = FastAPI(title="Cyara Recommendation Engine", version="1.0.0")

# ✅ API key required always
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=True)

def verify_api_key(api_key: str = Depends(api_key_header)):
    expected = config.get("api_key")
    if not expected:
        raise HTTPException(status_code=500, detail="API_KEY is not configured")
    if api_key != expected:
        raise HTTPException(status_code=401, detail="Invalid API key")

@app.post(
    "/recommendation",
    response_model=SimpleRecommendResponse,
    summary="Recommend clearer defining objective",
)
async def handle_recommendation(
    req: SimpleObjectiveRequest,
    _: None = Depends(verify_api_key),
):
    model_id = config.get("bedrock_model_id")
    if not model_id:
        raise HTTPException(status_code=500, detail="BEDROCK_MODEL_ID is not configured")

    try:
        result = recommend_objective(req, bedrock_client=bedrock_client, model_id=model_id)
        return result
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e))
