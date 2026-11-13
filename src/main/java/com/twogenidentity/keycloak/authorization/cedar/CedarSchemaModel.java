package com.twogenidentity.keycloak.authorization.cedar;

import com.cedarpolicy.model.schema.Schema;
import com.fasterxml.jackson.databind.JsonNode;

import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * A compiled resource-server schema (built-in {@code Keycloak} namespace + the resource server's
 * own namespace) and the parts of it the entity builder needs: which attributes each entity
 * type and each action context declares, with their types, so only declared values are sent to
 * Cedar and each with the declared type.
 */
final class CedarSchemaModel {

    /** Attribute value kinds the builder can fill from Keycloak's string-valued data. */
    enum Kind { STRING, LONG, BOOL, STRING_SET, OTHER }

    /** Declared attributes by name, and the kind of the type's tags ({@code null} when it has none). */
    record EntityType(Map<String, Kind> attributes, Kind tags) {
        boolean hasTags() {
            return tags != null;
        }
    }

    final Schema schema;
    /** The resource server's namespace, e.g. {@code Documents}. */
    final String namespace;
    /** Fully qualified, e.g. {@code Documents::Document}. */
    final Map<String, EntityType> entityTypes;
    /** Actions of the resource server's namespace, by name, with their declared context attributes. */
    final Map<String, Map<String, Kind>> actionContexts;

    private CedarSchemaModel(Schema schema, String namespace, Map<String, EntityType> entityTypes,
            Map<String, Map<String, Kind>> actionContexts) {
        this.schema = schema;
        this.namespace = namespace;
        this.entityTypes = Collections.unmodifiableMap(entityTypes);
        this.actionContexts = Collections.unmodifiableMap(actionContexts);
    }

    String qualify(String name) {
        return namespace + "::" + name;
    }

    Optional<EntityType> entityType(String qualifiedName) {
        return Optional.ofNullable(entityTypes.get(qualifiedName));
    }

    Optional<Map<String, Kind>> actionContext(String action) {
        return Optional.ofNullable(actionContexts.get(action));
    }

    /**
     * Builds the model from the schema's declarations. Schemas are written in the Cedar format;
     * cedar-java has no API to read their declarations, so this reads the JSON form that Cedar
     * generates from the parsed schema ({@link Schema#toJsonFormat()}).
     */
    static CedarSchemaModel from(Schema schema, JsonNode json, String namespace) {
        Map<String, EntityType> entityTypes = new HashMap<>();
        Map<String, Map<String, Kind>> actions = new HashMap<>();

        for (Iterator<Map.Entry<String, JsonNode>> it = json.fields(); it.hasNext(); ) {
            Map.Entry<String, JsonNode> ns = it.next();
            Types types = new Types(ns.getKey(), ns.getValue().path("commonTypes"));
            JsonNode declared = ns.getValue().path("entityTypes");
            for (Iterator<Map.Entry<String, JsonNode>> e = declared.fields(); e.hasNext(); ) {
                Map.Entry<String, JsonNode> type = e.next();
                JsonNode shape = type.getValue().path("shape");
                Map<String, Kind> attrs = shape.isMissingNode() ? Map.of() : types.record(shape);
                JsonNode tags = type.getValue().path("tags");
                entityTypes.put(ns.getKey() + "::" + type.getKey(),
                        new EntityType(attrs, tags.isMissingNode() ? null : types.kind(tags)));
            }
            if (ns.getKey().equals(namespace)) {
                for (Iterator<Map.Entry<String, JsonNode>> a = ns.getValue().path("actions").fields(); a.hasNext(); ) {
                    Map.Entry<String, JsonNode> action = a.next();
                    JsonNode context = action.getValue().path("appliesTo").path("context");
                    actions.put(action.getKey(), context.isMissingNode() ? Map.of() : types.record(context));
                }
            }
        }
        return new CedarSchemaModel(schema, namespace, entityTypes, actions);
    }

    /** Resolves Cedar JSON schema type nodes, following common-type references of one namespace. */
    private static final class Types {
        private final String namespace;
        private final JsonNode commonTypes;

        Types(String namespace, JsonNode commonTypes) {
            this.namespace = namespace;
            this.commonTypes = commonTypes;
        }

        Map<String, Kind> record(JsonNode node) {
            JsonNode resolved = resolveCommon(node, 0);
            if (resolved == null || !"Record".equals(resolved.path("type").asText())) {
                return Map.of();
            }
            Map<String, Kind> attrs = new LinkedHashMap<>();
            for (Iterator<Map.Entry<String, JsonNode>> it = resolved.path("attributes").fields(); it.hasNext(); ) {
                Map.Entry<String, JsonNode> attr = it.next();
                attrs.put(attr.getKey(), kind(attr.getValue()));
            }
            return attrs;
        }

        Kind kind(JsonNode node) {
            JsonNode resolved = resolveCommon(node, 0);
            if (resolved == null) {
                return Kind.OTHER;
            }
            String type = resolved.path("type").asText();
            if ("Set".equals(type)) {
                return kind(resolved.path("element")) == Kind.STRING ? Kind.STRING_SET : Kind.OTHER;
            }
            String name = "EntityOrCommon".equals(type) || "Entity".equals(type)
                    ? resolved.path("name").asText() : type;
            return primitive(name);
        }

        private static Kind primitive(String name) {
            return switch (name.replace("__cedar::", "")) {
                case "String" -> Kind.STRING;
                case "Long" -> Kind.LONG;
                case "Bool", "Boolean" -> Kind.BOOL;
                default -> Kind.OTHER;
            };
        }

        /** Follows references to common types; returns the node itself when it is not one. */
        private JsonNode resolveCommon(JsonNode node, int depth) {
            if (node == null || depth > 16) {
                return null;
            }
            String type = node.path("type").asText();
            String ref = switch (type) {
                case "EntityOrCommon" -> node.path("name").asText();
                case "Record", "Set", "String", "Long", "Boolean", "Bool", "Entity", "Extension" -> null;
                default -> type; // a bare common-type name, e.g. {"type": "Ctx"}
            };
            if (ref == null || primitive(ref) != Kind.OTHER) {
                return node;
            }
            String local = ref.startsWith(namespace + "::") ? ref.substring(namespace.length() + 2) : ref;
            JsonNode common = commonTypes.path(local);
            return common.isMissingNode() ? node : resolveCommon(common, depth + 1);
        }
    }
}
