package com.twogenidentity.keycloak.authorization.cedar;

import org.junit.jupiter.api.Test;

import java.util.List;

import static com.twogenidentity.keycloak.authorization.cedar.CedarSchemaModel.Kind.BOOL;
import static com.twogenidentity.keycloak.authorization.cedar.CedarSchemaModel.Kind.LONG;
import static com.twogenidentity.keycloak.authorization.cedar.CedarSchemaModel.Kind.OTHER;
import static com.twogenidentity.keycloak.authorization.cedar.CedarSchemaModel.Kind.STRING_SET;
import static com.twogenidentity.keycloak.authorization.cedar.CedarValues.convert;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CedarValuesTest {

    @Test
    void valuesAreConvertedToTheDeclaredKind() {
        assertTrue(convert(LONG, List.of("42")).isPresent());
        assertTrue(convert(LONG, List.of("x")).isEmpty());
        assertTrue(convert(BOOL, List.of("true")).isPresent());
        assertTrue(convert(BOOL, List.of("yes")).isEmpty());
        assertTrue(convert(OTHER, List.of("x")).isEmpty());
    }

    @Test
    void aJsonArrayFromKeycloakBecomesASet() {
        assertEquals(convert(STRING_SET, List.of("a", "b")), convert(STRING_SET, List.of("[\"a\",\"b\"]")));
        // Not a JSON array: one element, never split on spaces.
        assertEquals(convert(STRING_SET, List.of("[\"New York\"]")), convert(STRING_SET, List.of("New York")));
    }
}
