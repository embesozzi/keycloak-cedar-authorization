// Resource server: documents-api (schema.cedarschema, namespace Documents)
// document-reader members may read Documents.
@id("document-readers-read")
permit (
  principal in Keycloak::Role::"document-reader",
  action == Documents::Action::"read",
  resource is Documents::Document
);

// document-writer members may write Documents.
@id("document-writers-write")
permit (
  principal in Keycloak::Role::"document-writer",
  action == Documents::Action::"write",
  resource is Documents::Document
);
