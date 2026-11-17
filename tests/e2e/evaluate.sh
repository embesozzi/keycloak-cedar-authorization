#!/usr/bin/env bash
# AuthZEN checks of the use cases in tests/README.md. Needs a running demo (make up).
# Exits with 1 if any decision is not the expected one.
set -euo pipefail
cd "$(dirname "$0")"

KC_URL=${KC_URL:-http://localhost:8082}
REALM=${REALM:-demo}
EVALUATION_URL="$KC_URL/realms/$REALM/authzen/access/v1/evaluation"
PLANNER="spiffe://example.org/ns/agents/sa/planner-agent"

DOCS_TOKEN=$(./token.sh documents-api documents-api-secret)
MCP_TOKEN=$(./token.sh mcp-server mcp-server-secret)

# sub <access token>: the `sub` claim, as a PEP reads it from the verified token
sub() {
  jq -Rr 'split(".")[1] | gsub("-"; "+") | gsub("_"; "/") | @base64d | fromjson | .sub' <<<"$1"
}

# The agent authenticates with client credentials; the `sub` of its token is its service account user.
PLANNER_SUB=$(sub "$(./token.sh "$PLANNER" planner-agent-secret)")

passed=0
failed=0

# check <expected true|false> <description> <token> <request json>
check() {
  local expected=$1 description=$2 token=$3 request=$4 response decision
  response=$(curl -s -X POST "$EVALUATION_URL" \
    -H "Authorization: Bearer $token" \
    -H "Content-Type: application/json" \
    -d "$request")
  decision=$(jq -r '.decision' <<<"$response" 2>/dev/null || echo "invalid response")
  if [ "$decision" = "$expected" ]; then
    echo "PASS  $description"
    passed=$((passed + 1))
  else
    echo "FAIL  $description: expected decision $expected, got: $response"
    failed=$((failed + 1))
  fi
}

# request <subject type> <subject id> <action> [context json]
request() {
  local context='{}'
  if [ $# -ge 4 ]; then context=$4; fi
  jq -n --arg type "$1" --arg id "$2" --arg action "$3" --argjson context "$context" '{
    subject:  { type: $type, id: $id },
    resource: { type: "Document", id: "document-1" },
    action:   { name: $action },
    context:  $context
  }'
}

# tool_call <agent sub> <tool name> [context json]: the agent calling an MCP tool
tool_call() {
  local context='{}'
  if [ $# -ge 3 ]; then context=$3; fi
  request user "$1" call "$context" | jq --arg tool "$2" '.resource = { type: "Tool", id: $tool }'
}

echo "== documents-api (tests/policies/documents-api/documents.cedar)"
check true  "alice (document-reader) reads document-1"  "$DOCS_TOKEN" "$(request user alice read)"
check false "alice (document-reader) writes document-1" "$DOCS_TOKEN" "$(request user alice write)"
check true  "bob (document-writer) writes document-1"  "$DOCS_TOKEN" "$(request user bob write)"

check false "alice claiming document-writer in subject.properties writes document-1 (claim ignored)" "$DOCS_TOKEN" \
  "$(request user alice write | jq '.subject.properties = { roles: "document-writer" }')"

check true  "alice reads document-1 with scope and aud in the context" "$DOCS_TOKEN" \
  "$(request user alice read '{"scope": ["documents:read", "openid"], "aud": ["spiffe://example.org/ns/agents/sa/agent-orchestrator"]}')"
check true  "alice reads document-1 with acr and amr in the context" "$DOCS_TOKEN" \
  "$(request user alice read '{"acr": "inherence", "amr": ["passkeys", "mfa"]}')"

echo "== documents-api, authentication context (tests/policies/documents-api/document-write-passkey.cedar)"
check true  "carol (document-editor) writes document-1 after a passkey login" "$DOCS_TOKEN" \
  "$(request user carol write '{"acr": "inherence", "amr": ["passkeys", "mfa"]}')"
check false "carol (document-editor) writes document-1 after a password login" "$DOCS_TOKEN" \
  "$(request user carol write '{"acr": "inherence", "amr": ["pwd"]}')"

echo "== documents-api, AI agent (tests/policies/documents-api/planner-agent-read.cedar)"
check true  "planner-agent reads document-1"  "$DOCS_TOKEN" "$(request user "$PLANNER_SUB" read)"
check false "planner-agent writes document-1" "$DOCS_TOKEN" "$(request user "$PLANNER_SUB" write)"

echo "== mcp-server (tests/policies/mcp-server/tools.cedar)"
check true  "planner-agent (support-agent) calls get_customer with scope mcp:tools" "$MCP_TOKEN" \
  "$(tool_call "$PLANNER_SUB" get_customer '{"scope": ["mcp:tools"]}')"
check true  "planner-agent (support-agent) calls list_customers with scope mcp:tools" "$MCP_TOKEN" \
  "$(tool_call "$PLANNER_SUB" list_customers '{"scope": ["mcp:tools"]}')"
check false "planner-agent calls get_customer without scope mcp:tools" "$MCP_TOKEN" \
  "$(tool_call "$PLANNER_SUB" get_customer)"
check false "planner-agent calls delete_customer (forbidden for every agent)" "$MCP_TOKEN" \
  "$(tool_call "$PLANNER_SUB" delete_customer '{"scope": ["mcp:tools"]}')"

echo "== $passed passed, $failed failed"
[ "$failed" -eq 0 ]
