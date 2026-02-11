# recommendation-engine

FastAPI service for generating **objective recommendations** via **Amazon Bedrock**.

- **dev**: uses a local/mock Bedrock client (no AWS calls)
- **non-dev (qa/stage/prod, etc.)**: calls Bedrock using **Cognito User Pool → Cognito Identity Pool → temporary AWS credentials**

---

## API

### `POST /{ENV}/recommendation`

Body:

```json
{
  "objective": "What is this extra charge?",
  "context": {
    "persona": "telecom postpaid customer",
    "domain": "billing",
    "instructions": "keep it concise",
    "satisfactionCriteria": "clear, testable objective",
    "extraNotes": "Ireland market"
  }
}
```

Response:

```json
{
  "reason": "...",
  "suggestedDefiningObjective": "...",
  "alternativeDefiningObjective": "..."
}
```

#### Optional API-key protection

If your secrets/config include an `API_KEY`, then requests must include:

- Header: `X-API-Key: <API_KEY>`

If `API_KEY` is **not** set, the endpoint is open (backwards compatible for local/dev).

---

## How config works (Secrets Manager first, env fallback)

At startup, `src/core/config.py` loads:

1) **AWS Secrets Manager** using `SECRET_NAME` + `REGION`  
2) falls back to **environment variables** if Secrets Manager is unavailable

Secrets are expected as a **JSON object** (SecretString).

### Required keys (typical)

```json
{
  "ENV": "dev",
  "REGION": "eu-west-1",
  "BEDROCK_MODEL_ID": "anthropic.claude-3-5-sonnet-20240620-v1:0",

  "USER_POOL_ID": "eu-west-1_XXXXXXX",
  "CLIENT_ID": "xxxxxxxxxxxxxxxxxxxx",
  "CLIENT_SECRET": "xxxxxxxxxxxxxxxxxxxx",
  "IDENTITY_POOL_ID": "eu-west-1:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "COGNITO_USERNAME": "service-user@email.com",
  "COGNITO_PASSWORD": "super-secret",

  "API_KEY": "optional"
}
```

Notes:
- `CLIENT_SECRET` is optional **only if** your Cognito App Client has no secret.
- `AWS_ENDPOINT` is used for LocalStack (optional).

---

## Dev vs non-dev behaviour

### dev
- `ENV=dev`
- Uses `src/local/bedrock_client.py`
- Returns a deterministic Anthropic-style response so parsing matches production.

### non-dev (anything except dev)
- Uses `src/core/bedrock_client_cognito.py`
- Logs into Cognito (username/password) → exchanges IdToken for temporary AWS creds → calls Bedrock Runtime.
- Temporary creds are cached until close to expiration (to avoid logging in every request).

---

## Run locally (recommended)

### Option A: LocalStack + secrets bootstrap
This repo includes a LocalStack setup that creates the secret from `.env`.

1) Start LocalStack and create the secret:
```bash
make local-dev-env
```

2) Run the API:
```bash
make dev-server
```

3) Call the endpoint:
```bash
curl -X POST http://localhost:8000/dev/recommendation \
  -H "Content-Type: application/json" \
  -d '{"objective":"What is this extra charge?"}'
```

### Option B: No LocalStack (env-only)
Set variables in your shell (or `.env`) and run:

```bash
cd src && PYTHONPATH=. python -m uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

---

## Scripts

### Send a sample request
Update `scripts/request.json` and run:

```bash
make send-message BODY_JSON=scripts/request.json
```

This posts to `/{ENV}/recommendation` on `API_URL` (defaults to `http://localhost:8000`).

---

## Directory structure

```
recommendation-engine/src/
├── inference/                    # Bedrock + pre/post processing (no FastAPI types)
│   ├── recommendation.py
│   └── ...
├── core/                         # Shared infra & config
│   ├── config.py                 # Config loading (secrets/env)
│   ├── aws_utils.py              # Secrets Manager helper
│   ├── bedrock_client_cognito.py # Cognito → Bedrock Runtime client (non-dev)
│   └── ...
├── local/                        # Local/mock clients (dev)
│   └── bedrock_client.py
└── main.py                       # FastAPI entry point + routes
```

---

## Troubleshooting

- **401 Invalid or missing API key**: either remove `API_KEY` from your secret for local dev, or pass `X-API-Key`.
- **Cognito errors in non-dev**: verify:
  - Identity Pool is configured with the User Pool as an auth provider
  - the Cognito user exists and credentials are correct
  - App Client secret setting matches whether you provide `CLIENT_SECRET`
- **Model returns non-JSON**: the system prompt requires JSON-only output; confirm the model is an Anthropic Claude model.


## Endpoint

- `POST /recommendation` (requires header `X-API-Key`).

## Environment behaviour

`ENV` controls which Bedrock client is used:
- `local`: local mock Bedrock client (no AWS calls)
- `dev`: real AWS Bedrock using standard AWS credentials (`AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY` or an attached IAM role)
- anything else (e.g. `prod`, `qa`): Bedrock via Cognito (User Pool -> Identity Pool -> temporary AWS credentials)

### Important (Vercel)
On Vercel we do **not** load a committed `.env` file. Vercel environment variables take precedence.
