#!/usr/bin/env bash
# POST to the botium API route. Uses API_URL and ENV from env (defaults below).
set -e

API_URL="${API_URL:-http://localhost:8000}"
ENV="${ENV:-dev}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BODY_JSON="${1:-$SCRIPT_DIR/request.json}"

curl -s -X POST "${API_URL}/${ENV}/botium" \
  -H "Content-Type: application/json" \
  -d @"$BODY_JSON"
