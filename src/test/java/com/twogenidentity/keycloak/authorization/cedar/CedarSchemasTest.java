package com.twogenidentity.keycloak.authorization.cedar;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CedarSchemasTest {

    @Test
    void everySchemaInTheRepositoryCompiles() throws IOException {
        List<Path> schemas;
        try (Stream<Path> walk = Files.walk(Path.of("tests/policies"))) {
            schemas = walk.filter(f -> f.toString().endsWith(".cedarschema")).sorted().toList();
        }
        assertFalse(schemas.isEmpty());
        for (Path schema : schemas) {
            try {
                assertNotNull(CedarSchemas.compileUncached(Files.readString(schema)).namespace);
            } catch (CedarException e) {
                throw new AssertionError(schema + ": " + e.errors, e);
            }
        }
    }

    @Test
    void theModelDescribesDeclaredTypesAndContexts() throws Exception {
        CedarSchemaModel model = CedarFixture.docs();
        assertEquals("Documents", model.namespace);

        CedarSchemaModel.EntityType document = model.entityType("Documents::Document").orElseThrow();
        assertEquals(CedarSchemaModel.Kind.STRING, document.attributes().get("name"));
        assertEquals(CedarSchemaModel.Kind.STRING_SET, document.tags());

        // resolved through the RequestContext common type
        assertEquals(CedarSchemaModel.Kind.STRING, model.actionContext("read").orElseThrow().get("agent"));

        CedarSchemaModel.EntityType user = model.entityType("Keycloak::User").orElseThrow();
        assertEquals(CedarSchemaModel.Kind.STRING_SET, user.attributes().get("roles"));
        assertEquals(CedarSchemaModel.Kind.BOOL, user.attributes().get("enabled"));
        assertEquals(CedarSchemaModel.Kind.STRING_SET, user.tags());
    }

    @Test
    void typesAreResolved() throws Exception {
        CedarSchemaModel model = CedarSchemas.compileUncached("""
                namespace Shop {
                  type Money = Long;
                  entity Order = { total: Money, open: Bool, labels?: Set<String>, buyer?: Keycloak::User };
                  action pay appliesTo { principal: Keycloak::User, resource: Order, context: { amount: Money } };
                }
                """);
        var order = model.entityType("Shop::Order").orElseThrow().attributes();
        assertEquals(CedarSchemaModel.Kind.LONG, order.get("total"));
        assertEquals(CedarSchemaModel.Kind.BOOL, order.get("open"));
        assertEquals(CedarSchemaModel.Kind.STRING_SET, order.get("labels"));
        assertEquals(CedarSchemaModel.Kind.OTHER, order.get("buyer")); // entity reference: not filled
        assertEquals(CedarSchemaModel.Kind.LONG, model.actionContext("pay").orElseThrow().get("amount"));
    }

    @Test
    void theReservedNamespaceCannotBeExtended() {
        var e = assertThrows(CedarException.class, () -> CedarSchemas.compileUncached("""
                namespace Keycloak { entity Organization; }
                namespace Documents { entity Document; action read appliesTo { principal: Keycloak::User, resource: Document }; }
                """));
        assertTrue(e.getMessage().contains("reserved namespace"), e.getMessage());
    }

    @Test
    void typesMustLiveInExactlyOneNamespace() {
        var none = assertThrows(CedarException.class, () -> CedarSchemas.compileUncached(
                "entity Document; action read appliesTo { principal: Keycloak::User, resource: Document };"));
        assertTrue(none.getMessage().contains("outside a namespace"), none.getMessage());

        var two = assertThrows(CedarException.class, () -> CedarSchemas.compileUncached(
                "namespace A { entity X; } namespace B { entity Y; }"));
        assertTrue(two.getMessage().contains("exactly one namespace"), two.getMessage());
    }

    @Test
    void invalidOrEmptySchemasAreRefused() {
        assertThrows(CedarException.class, () -> CedarSchemas.compileUncached(""));
        assertThrows(CedarException.class, () -> CedarSchemas.compileUncached(
                "namespace Documents { entity Document = { owner: Nope }; }"));
    }

    @Test
    void compiledSchemasAreCachedByContent() throws Exception {
        CedarSchemas schemas = new CedarSchemas();
        String text = Files.readString(Path.of("tests/policies/documents-api/schema.cedarschema"));
        assertSame(schemas.compile(text), schemas.compile(new String(text)));
    }
}
