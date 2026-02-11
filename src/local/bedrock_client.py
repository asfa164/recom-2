import json
from typing import Any


class BedrockClient:
    """
    DEV mock Bedrock client that mimics Anthropic Bedrock JSON responses.
    It returns: {"content": [{"type": "text", "text": "<json>"}]}
    """

    def __init__(self, region_name: str, endpoint_url: str | None = None):
        self.region_name = region_name
        self.endpoint_url = endpoint_url

    def invoke_model(
        self,
        model_id: str,
        body: dict | bytes,
        content_type: str = "application/json",
        accept: str = "application/json",
    ) -> dict:
        if isinstance(body, (bytes, bytearray)):
            body = json.loads(body.decode("utf-8"))

        # Detect the Anthropic-style request payload your recommend_objective() sends
        is_anthropic = isinstance(body, dict) and "anthropic_version" in body and "messages" in body

        if is_anthropic:
            # Try to extract objective/context from the user message JSON
            objective = ""
            context = {}
            try:
                msg0 = (body.get("messages") or [])[0]
                content0 = (msg0.get("content") or [])[0]
                user_text = content0.get("text") or ""
                user_payload = json.loads(user_text)
                objective = str(user_payload.get("objective", "")).strip()
                context = user_payload.get("context") or {}
            except Exception:
                objective = objective or ""

            # Deterministic “good enough” recommendation for dev
            persona = context.get("persona") if isinstance(context, dict) else None
            domain = context.get("domain") if isinstance(context, dict) else None

            reason = "DEV MOCK: Objective is ambiguous; it lacks concrete scope, constraints, and measurable success criteria."
            if persona or domain:
                reason += f" (persona={persona or 'n/a'}, domain={domain or 'n/a'})"

            result = {
                "reason": reason,
                "suggestedDefiningObjective": (
                    f"Rewrite the objective into a testable statement with clear inputs/outputs, constraints, "
                    f"and acceptance criteria. Objective: '{objective or 'n/a'}'."
                ),
                "alternativeDefiningObjective": (
                    f"Alternative: Define success metrics and edge cases explicitly for: '{objective or 'n/a'}'. "
                    f"Include what data is needed and what a correct response must contain."
                ),
            }

            # IMPORTANT: This is the exact response shape recommend_objective() expects
            return {
                "content": [{"type": "text", "text": json.dumps(result, ensure_ascii=False)}],
                "model": model_id,
                "stop_reason": "end_turn",
            }

        # If other endpoints call invoke_model in dev, provide a generic response
        return {
            "content": [{"type": "text", "text": json.dumps({"message": "DEV MOCK: unsupported request"})}],
            "model": model_id,
            "stop_reason": "end_turn",
        }
