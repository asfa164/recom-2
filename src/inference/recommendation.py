from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel, Field


SYSTEM_PROMPT_SIMPLE = """You are a helpful assistant that improves an objective into a clearer, testable defining objective.

Input: You will receive a JSON payload containing:
  - objective: string
  - context: optional object with fields like persona, domain, instructions, satisfactionCriteria, extraNotes

Output: You MUST return ONLY valid JSON with EXACTLY these keys:
{
  \"reason\": string,
  \"suggestedDefiningObjective\": string,
  \"alternativeDefiningObjective\": string
}

Do not wrap your JSON in markdown. Do not include any other keys.
"""


class SimpleContext(BaseModel):
    persona: str | None = None
    domain: str | None = None
    instructions: str | None = None
    satisfactionCriteria: list[str] | None = None
    extraNotes: str | None = None


class SimpleObjectiveRequest(BaseModel):
    objective: str = Field(..., min_length=1)
    context: SimpleContext | None = None


class SimpleRecommendResponse(BaseModel):
    reason: str
    suggestedDefiningObjective: str
    alternativeDefiningObjective: str


def _extract_text_from_anthropic_bedrock(resp: dict) -> str:
    """Extract concatenated text from a Bedrock Anthropic-style response."""
    content = resp.get("content")
    if isinstance(content, list):
        chunks = []
        for c in content:
            if isinstance(c, dict) and c.get("type") == "text" and isinstance(c.get("text"), str):
                chunks.append(c["text"])
        if chunks:
            return "".join(chunks).strip()

    # Some wrappers put the model text in different keys
    for key in ("outputText", "completion", "generation", "text"):
        val = resp.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()

    return ""


def _safe_json_loads(text: str) -> dict:
    """Parse JSON, with a small recovery attempt if the model included extra text."""
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # Recovery: extract the first {...} block
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end != -1 and end > start:
            return json.loads(text[start : end + 1])
        raise


def recommend_objective(
    payload: dict | SimpleObjectiveRequest,
    bedrock_client: Any,
    model_id: str,
) -> SimpleRecommendResponse:
    """Main inference function used by the API route."""
    req = payload if isinstance(payload, SimpleObjectiveRequest) else SimpleObjectiveRequest.model_validate(payload)
    model_input = req.model_dump()

    body = {
        "anthropic_version": "bedrock-2023-05-31",
        "system": SYSTEM_PROMPT_SIMPLE,
        "messages": [
            {
                "role": "user",
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(model_input, ensure_ascii=False, indent=2),
                    }
                ],
            }
        ],
        "max_tokens": 512,
        "temperature": 0.0,
    }

    resp = bedrock_client.invoke_model(model_id=model_id, body=body)
    raw_text = _extract_text_from_anthropic_bedrock(resp)
    if not raw_text:
        raise ValueError("Bedrock response did not contain model text")

    parsed = _safe_json_loads(raw_text)
    return SimpleRecommendResponse.model_validate(parsed)
