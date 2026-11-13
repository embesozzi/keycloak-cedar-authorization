package com.twogenidentity.keycloak.authorization.cedar;

import com.cedarpolicy.model.entity.Entity;
import com.cedarpolicy.value.EntityTypeName;
import com.cedarpolicy.value.EntityUID;
import com.cedarpolicy.value.PrimBool;
import com.cedarpolicy.value.PrimString;
import com.cedarpolicy.value.Value;
import org.jboss.logging.Logger;
import org.keycloak.authorization.model.Resource;
import org.keycloak.authorization.policy.evaluation.Evaluation;

import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Maps Keycloak data to Cedar entities and context. Principals use the built-in {@code Keycloak::}
 * types; resources and actions use the resource server's namespace. Resource attributes, tags and
 * context values are only sent when the schema declares them, converted to the declared type.
 */
class CedarEntityBuilder {

    private static final Logger logger = Logger.getLogger(CedarEntityBuilder.class);

    static final String TYPE_USER   = CedarSchemas.BUILTIN_NAMESPACE + "::User";
    static final String TYPE_CLIENT = CedarSchemas.BUILTIN_NAMESPACE + "::Client";
    static final String TYPE_ROLE   = CedarSchemas.BUILTIN_NAMESPACE + "::Role";
    static final String TYPE_GROUP  = CedarSchemas.BUILTIN_NAMESPACE + "::Group";

    private CedarEntityBuilder() {
    }

    /** Principal plus the Role and Group entities it is a member of. */
    static Set<Entity> principalEntities(CedarPrincipal principal) {
        Set<Entity> entities = new HashSet<>();
        entities.add(principalEntity(principal));
        for (String role : principal.roles()) {
            entities.add(new Entity(euid(TYPE_ROLE, role), Map.of(), Set.of()));
        }
        for (String group : principal.groups()) {
            entities.add(new Entity(euid(TYPE_GROUP, group), Map.of(), Set.of()));
        }
        return entities;
    }

    static EntityUID principalUid(CedarPrincipal principal) {
        return euid(principal.kind() == CedarPrincipal.Kind.CLIENT ? TYPE_CLIENT : TYPE_USER, principal.id());
    }

    static Entity principalEntity(CedarPrincipal principal) {
        Map<String, Value> attrs = new HashMap<>();
        Set<EntityUID> parents = new HashSet<>();
        Map<String, Value> tags = new HashMap<>();

        if (principal.kind() == CedarPrincipal.Kind.CLIENT) {
            attrs.put("clientId", new PrimString(principal.name()));
        } else {
            attrs.put("username", new PrimString(principal.name()));
            attrs.put("emailVerified", new PrimBool(principal.emailVerified()));
            if (principal.email() != null && !principal.email().isBlank()) {
                attrs.put("email", new PrimString(principal.email()));
            }
            attrs.put("groups", CedarValues.stringSet(principal.groups()));
            principal.groups().forEach(g -> parents.add(euid(TYPE_GROUP, g)));
            principal.tags().forEach((key, values) -> tags.put(key, CedarValues.stringSet(values)));
        }
        attrs.put("enabled", new PrimBool(principal.enabled()));
        attrs.put("roles", CedarValues.stringSet(principal.roles()));
        principal.roles().forEach(r -> parents.add(euid(TYPE_ROLE, r)));

        EntityUID uid = principalUid(principal);
        logger.debugf("built %s attrs=%s parents=%d tags=%s",
                uid, attrs.keySet(), parents.size(), tags.keySet());
        return new Entity(uid, attrs, parents, tags);
    }

    // ---------------------------------------------------------------- action

    /** {@code <namespace>::Action::"<scope>"}; the scope must be declared as an action. */
    static EntityUID actionUid(CedarSchemaModel model, String action) throws CedarException {
        if (model.actionContext(action).isEmpty()) {
            throw new CedarException("action '" + action + "' is not declared in namespace " + model.namespace);
        }
        return euid(model.qualify("Action"), action);
    }

    // ---------------------------------------------------------------- resource

    /**
     * A Keycloak resource as {@code <namespace>::<resource type>::"<resource name>"}.
     * Declared attributes are filled from the resource's fields ({@code name}, {@code displayName},
     * {@code type}, {@code uris}, which take precedence) or its attributes of the same name;
     * when the type declares tags, every resource attribute is also sent as a tag.
     */
    static Entity resourceEntity(CedarSchemaModel model, String kcType, String name, String displayName,
            Collection<String> uris, Map<String, List<String>> kcAttributes) throws CedarException {
        String type = resourceType(model, kcType);
        CedarSchemaModel.EntityType declared = model.entityType(type).orElseThrow();

        Map<String, Collection<String>> sources = new HashMap<>();
        if (kcAttributes != null) {
            kcAttributes.forEach((k, v) -> { if (v != null) sources.put(k, v); });
        }
        sources.put("name", List.of(name));
        sources.put("type", List.of(kcType));
        if (displayName != null) sources.put("displayName", List.of(displayName));
        if (uris != null && !uris.isEmpty()) sources.put("uris", List.copyOf(uris));

        Map<String, Value> attrs = CedarValues.typed(declared.attributes(), sources);

        Map<String, Value> tags = new HashMap<>();
        if (declared.hasTags() && kcAttributes != null) {
            for (Map.Entry<String, List<String>> entry : kcAttributes.entrySet()) {
                CedarValues.convert(declared.tags(), entry.getValue()).ifPresent(v -> tags.put(entry.getKey(), v));
            }
        }
        EntityUID uid = euid(type, name);
        logger.debugf("built %s attrs=%s tags=%s", uid, attrs.keySet(), tags.keySet());
        return new Entity(uid, attrs, Set.of(), tags);
    }

    static Entity resourceEntity(Evaluation evaluation, CedarSchemaModel model) throws CedarException {
        Resource resource = evaluation.getPermission().getResource();
        return resourceEntity(model, resource.getType(), resource.getName(), resource.getDisplayName(),
                resource.getUris(), resource.getAttributes());
    }

    private static String resourceType(CedarSchemaModel model, String kcType) throws CedarException {
        if (kcType == null || kcType.isBlank()) {
            throw new CedarException("the resource has no type; give it a type declared as an entity in namespace "
                    + model.namespace);
        }
        String type = model.qualify(kcType);
        if (model.entityType(type).isEmpty()) {
            throw new CedarException("resource type '" + kcType + "' is not declared as an entity in namespace "
                    + model.namespace);
        }
        return type;
    }

    /** Only the keys the action's context declares in the schema, converted to the declared types. */
    static Map<String, Value> context(CedarSchemaModel model, String action, Map<String, Collection<String>> values) {
        return CedarValues.typed(model.actionContext(action).orElse(Map.of()), values);
    }

    static EntityUID euid(String type, String id) {
        return new EntityUID(EntityTypeName.parse(type).orElseThrow(
                () -> new IllegalArgumentException("invalid Cedar entity type '" + type + "'")), id);
    }
}
