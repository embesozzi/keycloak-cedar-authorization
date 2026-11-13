#!/usr/bin/env bash
# Configures the demo realm: users, an AI agent, two resource servers, their Cedar schemas and policies
# (mounted from tests/policies/), and permissions.
# Runs in the keycloak-bootstrap container of tests/docker-compose.yml, with the image's kcadm.sh.
set -euo pipefail
log() { echo "[$(date '+%H:%M:%S')] $*"; }

KCADM=/opt/keycloak/bin/kcadm.sh
SERVER=${KEYCLOAK_URL:-http://keycloak:8082}
POLICIES=${POLICIES_DIR:-/opt/bootstrap/policies}
REALM=demo
PLANNER="spiffe://example.org/ns/agents/sa/planner-agent"

# create_client <clientId> <secret> → prints the client's internal id
create_client() {
  $KCADM create clients -r "$REALM" -i -s "clientId=$1" -s "secret=$2" -s enabled=true \
    -s serviceAccountsEnabled=true -s authorizationServicesEnabled=true
}

# set_schema <client id> <schema file>: stores the schema in the client attribute cedar.schema
set_schema() {
  $KCADM update "clients/$1" -r "$REALM" -s "attributes.\"cedar.schema\"=$(cat "$2")"
}

# create_policy <client id> <policy file>: the Keycloak policy is named after the file
create_policy() {
  $KCADM create "clients/$1/authz/resource-server/policy/cedar" -r "$REALM" \
    -s "name=$(basename "$2" .cedar)" -s "code=$(cat "$2")"
}

# create_document <client id>: the scopes read and write, and the resource document-1 of type Document
create_document() {
  $KCADM create "clients/$1/authz/resource-server/scope" -r "$REALM" -s name=read
  $KCADM create "clients/$1/authz/resource-server/scope" -r "$REALM" -s name=write
  $KCADM create "clients/$1/authz/resource-server/resource" -r "$REALM" \
    -s name=document-1 -s type=Document -s 'scopes=[{"name":"read"},{"name":"write"}]'
}

# create_tool <client id> <tool name>: an MCP tool as a resource of type Tool with the scope call
create_tool() {
  $KCADM create "clients/$1/authz/resource-server/resource" -r "$REALM" \
    -s "name=$2" -s type=Tool -s 'scopes=[{"name":"call"}]'
}

# create_permission <client id> <name> <resources json> <scope> <policies json>
create_permission() {
  $KCADM create "clients/$1/authz/resource-server/permission/scope" -r "$REALM" \
    -s "name=$2" -s decisionStrategy=AFFIRMATIVE \
    -s "resources=$3" -s "scopes=[\"$4\"]" -s "policies=$5"
}

log "Authenticating to $SERVER"
$KCADM config credentials --server "$SERVER" --realm master \
  --user "${KEYCLOAK_USER:-admin}" --password "${KEYCLOAK_PASSWORD:-admin}"

# Local demo over plain HTTP: requests from the host reach Keycloak through Docker's network,
# which Keycloak's default (sslRequired=external) treats as external and refuses without HTTPS.
$KCADM update realms/master -s sslRequired=NONE

log "Creating realm $REALM, roles document-reader and document-writer, users alice and bob"
$KCADM create realms -s "realm=$REALM" -s enabled=true -s sslRequired=NONE
$KCADM create roles -r "$REALM" -s name=document-reader
$KCADM create roles -r "$REALM" -s name=document-writer
for user in alice:document-reader bob:document-writer; do
  name=${user%%:*}; role=${user#*:}
  $KCADM create users -r "$REALM" -s "username=$name" -s "email=$name@example.com" -s emailVerified=true -s enabled=true
  $KCADM set-password -r "$REALM" --username "$name" --new-password "$name"
  $KCADM add-roles -r "$REALM" --uusername "$name" --rolename "$role"
done

log "Creating resource server documents-api"
DOCS=$(create_client documents-api documents-api-secret)
create_document "$DOCS"
set_schema "$DOCS" "$POLICIES/documents-api/schema.cedarschema"
create_policy "$DOCS" "$POLICIES/documents-api/documents.cedar"
create_policy "$DOCS" "$POLICIES/documents-api/planner-agent-read.cedar"
create_permission "$DOCS" read-document-permission '["document-1"]' read '["documents","planner-agent-read"]'
create_permission "$DOCS" write-document-permission '["document-1"]' write '["documents"]'

log "Creating the AI agent $PLANNER (a client with a service account), with the role support-agent"
AGENT=$($KCADM create clients -r "$REALM" -i -s "clientId=$PLANNER" -s secret=planner-agent-secret -s enabled=true -s serviceAccountsEnabled=true)
$KCADM create roles -r "$REALM" -s name=support-agent
AGENT_USER=$($KCADM get "clients/$AGENT/service-account-user" -r "$REALM" --fields id --format csv --noquotes)
$KCADM add-roles -r "$REALM" --uid "$AGENT_USER" --rolename support-agent

log "Creating resource server mcp-server, with the tools get_customer, list_customers and delete_customer"
MCP=$(create_client mcp-server mcp-server-secret)
$KCADM create "clients/$MCP/authz/resource-server/scope" -r "$REALM" -s name=call
create_tool "$MCP" get_customer
create_tool "$MCP" list_customers
create_tool "$MCP" delete_customer
set_schema "$MCP" "$POLICIES/mcp-server/schema.cedarschema"
create_policy "$MCP" "$POLICIES/mcp-server/tools.cedar"
create_permission "$MCP" call-tool-permission '["get_customer","list_customers","delete_customer"]' call '["tools"]'

log "Done"
