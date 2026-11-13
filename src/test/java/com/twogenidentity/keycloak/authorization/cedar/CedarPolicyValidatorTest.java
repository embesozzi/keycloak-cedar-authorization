package com.twogenidentity.keycloak.authorization.cedar;

import com.cedarpolicy.model.policy.PolicySet;
import com.cedarpolicy.model.schema.Schema;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CedarPolicyValidatorTest {

    private static PolicySet validate(String name, String code) throws Exception {
        return CedarPolicyValidator.validate(name, code, CedarFixture.docs().schema);
    }

    private static CedarException refused(String name, String code) {
        return assertThrows(CedarException.class, () -> validate(name, code));
    }

    /** Every policy file must validate against the schema in its own folder. */
    @Test
    void everyPolicyFileValidatesAgainstItsResourceServerSchema() throws Exception {
        List<Path> files;
        try (Stream<Path> walk = Files.walk(Path.of("tests/policies"))) {
            files = walk.filter(f -> f.toString().endsWith(".cedar")).sorted().toList();
        }
        assertFalse(files.isEmpty(), "no .cedar files under tests/policies/");
        for (Path file : files) {
            Schema schema = CedarSchemas.compileUncached(Files.readString(file.resolveSibling("schema.cedarschema"))).schema;
            String name = file.getFileName().toString().replace(".cedar", "");
            assertDoesNotThrow(() -> CedarPolicyValidator.validate(name, Files.readString(file), schema), file.toString());
        }
    }

    @Test
    void emptyCodeIsRefused() {
        refused("p", null);
        refused("p", "  \n ");
        refused("p", "// only a comment\n");
    }

    @Test
    void statementsAreNamedByIdAnnotationOrPosition() throws Exception {
        String code = Files.readString(Path.of("tests/policies/documents-api/documents.cedar"));
        assertEquals(Set.of("documents#document-readers-read", "documents#document-writers-write"),
                CedarPolicyValidator.ids(validate("documents", code)));

        String unannotated = """
                permit(principal, action == Documents::Action::"read", resource);
                permit(principal, action == Documents::Action::"write", resource);
                """;
        assertEquals(Set.of("docs#1", "docs#2"), CedarPolicyValidator.ids(validate("docs", unannotated)));
    }

    @Test
    void duplicateIdsAreRefused() {
        CedarException e = refused("docs", """
                @id("same") permit(principal, action == Documents::Action::"read", resource);
                @id("same") permit(principal, action == Documents::Action::"write", resource);
                """);
        assertTrue(e.getMessage().contains("duplicate"), e.getMessage());
    }

    @Test
    void aSyntaxErrorIsReported() {
        CedarException e = refused("docs", """
                permit(principal, action == Documents::Action::"read", resource);
                permit(principal, action == Documents::Action::"write" resource);
                """);
        assertTrue(e.errors.get(0).startsWith("docs:"), e.getMessage());
    }

    @Test
    void anUndeclaredActionIsRefusedByTheSchema() {
        refused("docs", "@id(\"del\") permit(principal, action == Documents::Action::\"delete\", resource);");
    }

    @Test
    void unnamespacedTypesAreRefused() {
        refused("docs", "permit(principal, action == Action::\"read\", resource);");
        refused("docs", "permit(principal in Role::\"document-reader\", action == Documents::Action::\"read\", resource);");
    }

    @Test
    void anUndeclaredAttributeIsRefusedByTheSchema() {
        refused("docs", "@id(\"x\") permit(principal, action == Documents::Action::\"read\", resource) "
                + "when { principal.department == \"eng\" };");
        refused("docs", "@id(\"x\") permit(principal, action == Documents::Action::\"read\", resource) "
                + "when { context.unknown == \"x\" };");
    }

    @Test
    void declaredContextAndTagsValidate() {
        assertDoesNotThrow(() -> validate("docs", """
                @id("agent-from-context")
                permit(principal is Keycloak::User, action == Documents::Action::"read", resource is Documents::Document)
                when {
                  context has agent && context.agent == "orchestrator" &&
                  resource.hasTag("classification") && resource.getTag("classification").contains("public") &&
                  principal.hasTag("department") && principal.getTag("department").contains("eng")
                };
                """));
    }

    @Test
    void callerClaimsAreContextKeysNotPrincipalAttributes() {
        refused("docs", "@id(\"x\") permit(principal, action == Documents::Action::\"write\", resource) "
                + "when { principal.asserted.acr == \"inherence\" };");
        assertDoesNotThrow(() -> validate("docs", "@id(\"x\") permit(principal, action == Documents::Action::\"write\", resource) "
                + "when { context has acr && context.acr == \"inherence\" };"));
    }

    @Test
    void clientOnlyAttributesNeedATypeTest() {
        refused("docs", "@id(\"x\") permit(principal, action == Documents::Action::\"read\", resource) "
                + "when { principal.clientId == \"spiffe://org/agent\" };");
        assertDoesNotThrow(() -> validate("docs", "@id(\"x\") permit(principal is Keycloak::Client, "
                + "action == Documents::Action::\"read\", resource) when { principal.clientId == \"spiffe://org/a;b\" };"));
    }

    @Test
    void templatesAreNotSupported() {
        refused("docs", "permit(principal == ?principal, action == Documents::Action::\"read\", resource);");
    }

    @Test
    void parseWorksWithoutSchema() {
        assertDoesNotThrow(() -> CedarPolicyValidator.parse("docs",
                Files.readString(Path.of("tests/policies/documents-api/documents.cedar"))));
    }
}
