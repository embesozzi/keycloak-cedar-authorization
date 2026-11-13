// Resource server: documents-api (schema.cedarschema, namespace Documents)
// The planner agent (SPIFFE client) may read Documents.
@id("planner-agent-read")
permit (
  principal is Keycloak::Client,
  action == Documents::Action::"read",
  resource is Documents::Document
)
when
{ principal.clientId == "spiffe://example.org/ns/agents/sa/planner-agent" };
