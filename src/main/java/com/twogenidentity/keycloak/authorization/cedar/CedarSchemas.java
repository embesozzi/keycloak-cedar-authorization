package com.twogenidentity.keycloak.authorization.cedar;

import com.cedarpolicy.model.exception.InternalException;
import com.cedarpolicy.model.schema.Schema;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import org.keycloak.authorization.AuthorizationProvider;
import org.keycloak.authorization.model.ResourceServer;
import org.keycloak.models.ClientModel;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 * The Cedar schema of a resource server: the built-in {@code Keycloak} namespace shipped in the jar
 * plus the resource server's own schema, stored in its client attribute {@value #CLIENT_ATTRIBUTE}.
 * The resource server's schema must declare exactly one namespace of its own and nothing in
 * {@code Keycloak}. Compiled schemas are cached by a hash of their text.
 */
final class CedarSchemas {

    static final String CLIENT_ATTRIBUTE = "cedar.schema";
    static final String BUILTIN_NAMESPACE = "Keycloak";
    private static final String BUILTIN_RESOURCE = "cedar/keycloak.cedarschema";
    private static final String RESERVED = "the schema declares types in the reserved namespace '" + BUILTIN_NAMESPACE
            + "'; reference the built-in types (e.g. Keycloak::User) instead";

    static final String BUILTIN = loadBuiltin();

    /** Parsed on first use, so the native library is only needed once a schema is compiled. */
    private static final class Builtin {
        static final JsonNode JSON = builtinJson();
    }

    private final ContentCache<CedarSchemaModel> cache = new ContentCache<>();

    CedarSchemaModel forResourceServer(ResourceServer resourceServer, AuthorizationProvider authz)
            throws CedarException {
        ClientModel client = authz.getRealm().getClientById(resourceServer.getClientId());
        String source = client != null ? client.getAttribute(CLIENT_ATTRIBUTE) : null;
        if (source == null || source.isBlank()) {
            String name = client != null ? client.getClientId() : resourceServer.getClientId();
            throw new CedarException("resource server '" + name + "' has no Cedar schema: set the client attribute '"
                    + CLIENT_ATTRIBUTE + "' (Cedar format, one namespace of its own)");
        }
        return compile(source);
    }

    CedarSchemaModel compile(String source) throws CedarException {
        String key = ContentCache.key(source);
        CedarSchemaModel compiled = cache.get(key);
        if (compiled == null) {
            compiled = compileUncached(source);
            cache.put(key, compiled);
        }
        return compiled;
    }

    static CedarSchemaModel compileUncached(String source) throws CedarException {
        if (source == null || source.isBlank()) {
            throw new CedarException("Cedar schema is empty");
        }
        Schema schema;
        JsonNode json;
        try {
            schema = Schema.parse(Schema.JsonOrCedar.Cedar, BUILTIN + "\n" + source);
            json = schema.toJsonFormat();
        } catch (InternalException e) {
            List<String> errors = errors(e);
            if (errors.stream().anyMatch(m -> m.contains("duplicate namespace id: `" + BUILTIN_NAMESPACE + "`"))) {
                throw new CedarException(RESERVED);
            }
            throw new CedarException(errors);
        } catch (JsonProcessingException | RuntimeException e) {
            throw new CedarException("Cedar schema could not be read: " + e.getMessage());
        }

        List<String> problems = new ArrayList<>();
        if (!Builtin.JSON.path(BUILTIN_NAMESPACE).equals(json.path(BUILTIN_NAMESPACE))) {
            problems.add(RESERVED);
        }
        List<String> namespaces = new ArrayList<>();
        for (Iterator<String> it = json.fieldNames(); it.hasNext(); ) {
            String ns = it.next();
            if (ns.isEmpty()) {
                problems.add("the schema declares types outside a namespace; wrap them in `namespace <Name> { ... }`");
            } else if (!ns.equals(BUILTIN_NAMESPACE)) {
                namespaces.add(ns);
            }
        }
        if (namespaces.size() != 1) {
            problems.add("the schema must declare exactly one namespace of its own, found " + namespaces);
        }
        if (!problems.isEmpty()) {
            throw new CedarException(problems);
        }
        return CedarSchemaModel.from(schema, json, namespaces.get(0));
    }

    static List<String> errors(InternalException e) {
        List<String> errors = e.getErrors();
        return errors != null && !errors.isEmpty() ? errors : List.of(String.valueOf(e.getMessage()));
    }

    private static String loadBuiltin() {
        try (InputStream is = CedarSchemas.class.getClassLoader().getResourceAsStream(BUILTIN_RESOURCE)) {
            if (is == null) {
                throw new IllegalStateException("built-in Cedar schema not found on classpath: " + BUILTIN_RESOURCE);
            }
            return new String(is.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new IllegalStateException("cannot read built-in Cedar schema " + BUILTIN_RESOURCE, e);
        }
    }

    private static JsonNode builtinJson() {
        try {
            return Schema.parse(Schema.JsonOrCedar.Cedar, BUILTIN).toJsonFormat();
        } catch (InternalException e) {
            throw new IllegalStateException("built-in Cedar schema is invalid: " + errors(e), e);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("built-in Cedar schema could not be read", e);
        }
    }

}
