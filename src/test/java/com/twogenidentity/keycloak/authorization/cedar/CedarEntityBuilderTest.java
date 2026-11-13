package com.twogenidentity.keycloak.authorization.cedar;

import com.cedarpolicy.model.entity.Entity;
import org.junit.jupiter.api.Test;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static com.twogenidentity.keycloak.authorization.cedar.CedarFixture.RS;
import static com.twogenidentity.keycloak.authorization.cedar.CedarFixture.allowed;
import static com.twogenidentity.keycloak.authorization.cedar.CedarFixture.docs;
import static com.twogenidentity.keycloak.authorization.cedar.CedarFixture.file;
import static com.twogenidentity.keycloak.authorization.cedar.CedarFixture.planner;
import static com.twogenidentity.keycloak.authorization.cedar.CedarFixture.user;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** How Keycloak data becomes Cedar entities and context, checked through real decisions. */
class CedarEntityBuilderTest {

    private static CedarPrincipal alice() {
        return user("alice", List.of("document-reader", "account/view-profile", "document-editor"),
                List.of("/engineering", "/engineering/agents"), Map.of("department", List.of("eng")));
    }

    @Test
    void resourcesAreTypedAndKeyedByName() throws Exception {
        Entity document = CedarFixture.document(Map.of());
        assertEquals("Documents::Document", document.getEUID().getType().toString());
        assertEquals("document-1", document.getEUID().getId().toString());
        assertTrue(allowed("permit(principal, action == Documents::Action::\"read\", resource == Documents::Document::\"document-1\");",
                alice(), "read"));
    }

    @Test
    void anUndeclaredResourceTypeOrActionIsRefused() throws Exception {
        CedarSchemaModel model = docs();
        assertThrows(CedarException.class,
                () -> CedarEntityBuilder.resourceEntity(model, "Vehicle", "car-1", null, List.of(), Map.of()));
        assertThrows(CedarException.class,
                () -> CedarEntityBuilder.resourceEntity(model, null, "x", null, List.of(), Map.of()));
        assertThrows(CedarException.class, () -> CedarEntityBuilder.actionUid(model, "delete"));
    }

    @Test
    void rolesAndGroupsAreAttributesAndParents() throws Exception {
        assertTrue(allowed("permit(principal, action == Documents::Action::\"read\", resource) "
                + "when { principal.roles.contains(\"document-reader\") };", alice(), "read"));
        assertTrue(allowed("permit(principal in Keycloak::Role::\"account/view-profile\", "
                + "action == Documents::Action::\"read\", resource);", alice(), "read"));
        assertTrue(allowed("permit(principal in Keycloak::Group::\"/engineering\", "
                + "action == Documents::Action::\"read\", resource);", alice(), "read"));
        assertFalse(allowed("permit(principal in Keycloak::Role::\"document-writer\", "
                + "action == Documents::Action::\"write\", resource);", alice(), "write"));
    }

    @Test
    void aPrincipalWithoutRolesOrGroupsHasEmptySets() throws Exception {
        assertFalse(allowed("permit(principal is Keycloak::User, action == Documents::Action::\"read\", resource) "
                + "when { principal.roles.contains(\"document-reader\") || principal.groups.contains(\"/eng\") };",
                user("nobody", List.of()), "read"));
    }

    @Test
    void clientIdComesFromTheClientModel() throws Exception {
        String policy = file(RS + "planner-agent-read.cedar");
        assertTrue(allowed(policy, planner(), "read"));
        assertFalse(allowed(policy, alice(), "read"));
    }

    @Test
    void thePrincipalOnlyCarriesDirectoryFacts() {
        assertEquals(Set.of("username", "email", "emailVerified", "enabled", "roles", "groups"),
                CedarEntityBuilder.principalEntity(alice()).attrs.keySet());
    }

    @Test
    void userAndResourceAttributesAreTags() throws Exception {
        String policy = "permit(principal is Keycloak::User, action == Documents::Action::\"read\", resource is Documents::Document) when { "
                + "principal.hasTag(\"department\") && principal.getTag(\"department\").contains(\"eng\") && "
                + "resource.hasTag(\"classification\") && resource.getTag(\"classification\").contains(\"public\") };";
        assertTrue(allowed(policy, alice(), "read", Map.of("classification", List.of("public")), Map.of()));
        assertFalse(allowed(policy, alice(), "read", Map.of("classification", List.of("secret")), Map.of()));
    }

    /** Login facts only the PEP knows travel in the AuthZEN context, declared by the schema. */
    @Test
    void loginFactsComeFromTheDeclaredContext() throws Exception {
        String policy = file(RS + "document-write-passkey.cedar");
        // Keycloak passes a JSON array from the AuthZEN context as its JSON text.
        Map<String, Collection<String>> passkey = Map.of("acr", List.of("inherence"), "amr", List.of("[\"passkeys\",\"mfa\"]"));
        Map<String, Collection<String>> password = Map.of("acr", List.of("inherence"), "amr", List.of("[\"pwd\"]"));
        assertTrue(allowed(policy, alice(), "write", Map.of(), passkey));
        assertFalse(allowed(policy, alice(), "write", Map.of(), password));
        assertFalse(allowed(policy, alice(), "write", Map.of(), Map.of()));
    }

    @Test
    void onlyDeclaredContextKeysReachCedar() throws Exception {
        Map<String, Collection<String>> context = Map.of(
                "agent", List.of("orchestrator"),
                "kc.client.network.ip_address", List.of("10.0.0.1"),
                "undeclared", List.of("ignored"));
        assertEquals(Set.of("agent"), CedarEntityBuilder.context(docs(), "read", context).keySet());
        String policy = "permit(principal, action == Documents::Action::\"read\", resource) "
                + "when { context has agent && context.agent == \"orchestrator\" };";
        assertTrue(allowed(policy, alice(), "read", Map.of(), context));
        assertFalse(allowed(policy, alice(), "read", Map.of(), Map.of()));
    }
}
