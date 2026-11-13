package com.twogenidentity.keycloak.authorization.cedar;

import com.cedarpolicy.model.policy.PolicySet;
import org.junit.jupiter.api.Test;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static com.twogenidentity.keycloak.authorization.cedar.CedarFixture.RS;
import static com.twogenidentity.keycloak.authorization.cedar.CedarFixture.file;
import static com.twogenidentity.keycloak.authorization.cedar.CedarFixture.user;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** All Cedar policies of a resource server decide together, with Cedar's semantics. */
class CedarPolicySetsTest {

    private static final CedarPrincipal BOB = user("bob", List.of("document-writer"));

    private static final String NO_UNTRUSTED_WRITES = """
            @id("no-untrusted-writes")
            forbid (principal, action == Documents::Action::"write", resource)
            when { context has agent && context.agent == "untrusted-bot" };
            """;

    private static List<CedarPolicySets.Source> documentsAndForbid() throws Exception {
        return List.of(new CedarPolicySets.Source("documents", file(RS + "documents.cedar")),
                new CedarPolicySets.Source("no-untrusted-writes", NO_UNTRUSTED_WRITES));
    }

    private static boolean writes(PolicySet set, Map<String, Collection<String>> context) throws Exception {
        return CedarFixture.decide(set, BOB, "write", context).allowed();
    }

    @Test
    void aForbidInOnePolicyOverridesAPermitInAnother() throws Exception {
        PolicySet set = CedarPolicySets.compileUncached(documentsAndForbid());
        assertTrue(writes(set, Map.of("agent", List.of("orchestrator"))));
        assertFalse(writes(set, Map.of("agent", List.of("untrusted-bot"))));
    }

    @Test
    void aPolicyWithOnlyForbidsDoesNotDenyEverything() throws Exception {
        assertTrue(writes(CedarPolicySets.compileUncached(documentsAndForbid()), Map.of()));
    }

    @Test
    void statementIdsNameTheirKeycloakPolicy() throws Exception {
        Set<String> ids = CedarPolicySets.compileUncached(documentsAndForbid()).policies.stream()
                .map(p -> p.getID()).collect(Collectors.toSet());
        assertEquals(Set.of("documents#document-readers-read", "documents#document-writers-write",
                "no-untrusted-writes#no-untrusted-writes"), ids);
    }

    @Test
    void oneBrokenPolicyBreaksTheWholeSet() {
        assertThrows(CedarException.class, () -> CedarPolicySets.compileUncached(List.of(
                new CedarPolicySets.Source("documents", file(RS + "documents.cedar")),
                new CedarPolicySets.Source("broken", "forbid (principal, action, resource) when {"))));
    }

    @Test
    void theCacheIsKeyedByContentNotOrder() throws Exception {
        CedarPolicySets sets = new CedarPolicySets();
        var a = new CedarPolicySets.Source("documents", file(RS + "documents.cedar"));
        var b = new CedarPolicySets.Source("no-untrusted-writes", NO_UNTRUSTED_WRITES);
        assertSame(sets.compile(List.of(a, b)), sets.compile(List.of(b, a)));

        var changed = new CedarPolicySets.Source("no-untrusted-writes", NO_UNTRUSTED_WRITES + "\n");
        assertNotSame(sets.compile(List.of(a, b)), sets.compile(List.of(a, changed)));
    }
}
