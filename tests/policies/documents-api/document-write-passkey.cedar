// Resource server: documents-api (schema.cedarschema, namespace Documents)
// Document editors may write only after a passkey login at inherence assurance level.
// acr/amr are sent by the PEP in the AuthZEN `context` (declared in RequestContext).
@id("editors-write-with-passkey")
permit (
  principal in Keycloak::Role::"document-editor",
  action == Documents::Action::"write",
  resource is Documents::Document
)
when
{
  context has acr &&
  context.acr == "inherence" &&
  context has amr &&
  context.amr.contains("passkeys")
};
