#!/usr/bin/env bash
# Prints an access token from the client credentials grant.
# Usage: ./get-at.sh [client_id] [client_secret]
#   Defaults to the demo client documents-api / documents-api-secret.
set -euo pipefail

KC_URL=${KC_URL:-http://localhost:8082}
REALM=${REALM:-demo}
CLIENT_ID=${1:-documents-api}
CLIENT_SECRET=${2:-documents-api-secret}

response=$(curl -s -X POST "$KC_URL/realms/$REALM/protocol/openid-connect/token" \
  --data-urlencode grant_type=client_credentials \
  --data-urlencode "client_id=$CLIENT_ID" \
  --data-urlencode "client_secret=$CLIENT_SECRET") || {
  echo "get-at.sh: cannot reach Keycloak at $KC_URL" >&2
  exit 1
}

if ! jq -er '.access_token' <<<"$response" 2>/dev/null; then
  echo "get-at.sh: no access token for $CLIENT_ID: $response" >&2
  exit 1
fi
