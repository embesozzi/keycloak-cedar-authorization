package com.twogenidentity.keycloak.authorization.cedar;

import com.cedarpolicy.model.entity.Entity;
import com.cedarpolicy.model.policy.PolicySet;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collection;
import java.util.List;
import java.util.Map;

/**
 * Shared test data: the demo Documents schema and policies from tests/policies/documents-api/, a few
 * principals, and decisions taken through {@link CedarPolicyProvider#decide}, the provider's own path.
 */
final class CedarFixture {

    static final String RS = "tests/policies/documents-api/";
    static final String MCP = "tests/policies/mcp-server/";
    static final String PLANNER = "spiffe://example.org/ns/agents/sa/planner-agent";

    private CedarFixture() {
    }

    static String file(String path) throws IOException {
        return Files.readString(Path.of(path));
    }

    static CedarSchemaModel docs() throws Exception {
        return CedarSchemas.compileUncached(file(RS + "schema.cedarschema"));
    }

    static CedarPrincipal user(String username, List<String> roles) {
        return user(username, roles, List.of(), Map.of());
    }

    static CedarPrincipal user(String username, List<String> roles, List<String> groups, Map<String, List<String>> tags) {
        return CedarPrincipal.user("id-" + username, username, username + "@example.com", true, true, roles, groups, tags);
    }

    static CedarPrincipal planner() {
        return CedarPrincipal.client("id-planner", PLANNER, true, List.of("document-reader"));
    }

    static Entity document(Map<String, List<String>> attributes) throws Exception {
        return CedarEntityBuilder.resourceEntity(docs(), "Document", "document-1", null, List.of(), attributes);
    }

    static CedarSchemaModel mcp() throws Exception {
        return CedarSchemas.compileUncached(file(MCP + "schema.cedarschema"));
    }

    /** An MCP tool resource of the mcp-server resource server: Mcp::Tool::"<name>". */
    static Entity tool(String name) throws Exception {
        return CedarEntityBuilder.resourceEntity(mcp(), "Tool", name, null, List.of(), Map.of());
    }

    /** Validates the code against the Documents schema, then decides with it. */
    static CedarPolicyProvider.Decision decide(String code, CedarPrincipal principal, List<String> actions,
            Map<String, List<String>> resourceAttributes, Map<String, Collection<String>> context) throws Exception {
        CedarSchemaModel model = docs();
        PolicySet policies = CedarPolicyValidator.validate("test", code, model.schema);
        return CedarPolicyProvider.decide(policies, model, principal, document(resourceAttributes), actions, context);
    }

    /** Decides with an already compiled policy set (e.g. several Keycloak policies together). */
    static CedarPolicyProvider.Decision decide(PolicySet policies, CedarPrincipal principal, String action,
            Map<String, Collection<String>> context) throws Exception {
        return CedarPolicyProvider.decide(policies, docs(), principal, document(Map.of()), List.of(action), context);
    }

    static boolean allowed(String code, CedarPrincipal principal, String action) throws Exception {
        return decide(code, principal, List.of(action), Map.of(), Map.of()).allowed();
    }

    static boolean allowed(String code, CedarPrincipal principal, String action,
            Map<String, List<String>> resourceAttributes, Map<String, Collection<String>> context) throws Exception {
        return decide(code, principal, List.of(action), resourceAttributes, context).allowed();
    }
}
