package com.twogenidentity.keycloak.authorization.cedar;

import com.cedarpolicy.model.policy.PolicySet;
import org.junit.jupiter.api.Test;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static com.twogenidentity.keycloak.authorization.cedar.CedarFixture.RS;
import static com.twogenidentity.keycloak.authorization.cedar.CedarFixture.allowed;
import static com.twogenidentity.keycloak.authorization.cedar.CedarFixture.file;
import static com.twogenidentity.keycloak.authorization.cedar.CedarFixture.user;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Decisions: the repository policies, and requests with several scopes. */
class CedarPolicyProviderTest {

    private static CedarPolicyProvider.Decision decide(List<String> roles, List<String> actions) throws Exception {
        return CedarFixture.decide(file(RS + "documents.cedar"), user("u", roles), actions, Map.of(), Map.of());
    }

    @Test
    void theRepositoryPoliciesDecideAsDocumented() throws Exception {
        String documents = file(RS + "documents.cedar");
        assertTrue(allowed(documents, user("alice", List.of("document-reader")), "read"));
        assertFalse(allowed(documents, user("alice", List.of("document-reader")), "write"));
        assertTrue(allowed(documents, user("bob", List.of("document-writer")), "write"));
    }

    @Test
    void theMcpToolPoliciesDecideByToolName() throws Exception {
        CedarSchemaModel model = CedarFixture.mcp();
        PolicySet policies = CedarPolicyValidator.validate("tools", file(CedarFixture.MCP + "tools.cedar"), model.schema);
        CedarPrincipal supportAgent = CedarPrincipal.client("id-planner", CedarFixture.PLANNER, true, List.of("support-agent"));
        CedarPrincipal toolAdmin = CedarPrincipal.client("id-admin", "admin-agent", true, List.of("tool-admin"));
        CedarPrincipal otherAgent = CedarPrincipal.client("id-other", "other-agent", true, List.of());
        Map<String, Collection<String>> withScope = Map.of("scope", List.of("mcp:tools"));

        assertTrue(callTool(policies, model, supportAgent, "get_customer", withScope));
        assertTrue(callTool(policies, model, supportAgent, "list_customers", withScope));
        assertFalse(callTool(policies, model, supportAgent, "get_customer", Map.of()), "without the mcp:tools scope");
        assertFalse(callTool(policies, model, supportAgent, "delete_customer", withScope), "a tool not in the list");
        assertFalse(callTool(policies, model, otherAgent, "get_customer", withScope), "without the role");

        assertTrue(callTool(policies, model, toolAdmin, "list_customers", Map.of()), "tool-admin calls every tool");
        assertFalse(callTool(policies, model, toolAdmin, "delete_customer", Map.of()), "the forbid overrides the permit");
    }

    private static boolean callTool(PolicySet policies, CedarSchemaModel model, CedarPrincipal principal,
            String tool, Map<String, Collection<String>> context) throws Exception {
        return CedarPolicyProvider.decide(policies, model, principal, CedarFixture.tool(tool),
                List.of("call"), context).allowed();
    }

    @Test
    void aMixedRequestIsDeniedAsAWhole() throws Exception {
        // document-reader may read but not write: asking for both must not grant both.
        CedarPolicyProvider.Decision decision = decide(List.of("document-reader"), List.of("read", "write"));
        assertFalse(decision.allowed());
        assertTrue(decision.reason().contains("'write'"), decision.reason());
    }

    @Test
    void allScopesAllowedReportsEachDeterminingStatement() throws Exception {
        CedarPolicyProvider.Decision decision = decide(List.of("document-reader", "document-writer"), List.of("read", "write"));
        assertTrue(decision.allowed());
        assertEquals(Map.of("read", Set.of("test#document-readers-read"), "write", Set.of("test#document-writers-write")),
                decision.determining());
    }

    @Test
    void anUndeclaredOrMissingScopeCannotBeEvaluated() {
        assertThrows(CedarException.class, () -> decide(List.of("document-reader"), List.of("read", "delete")));
        assertThrows(CedarException.class, () -> decide(List.of("document-reader"), List.of()));
    }
}
