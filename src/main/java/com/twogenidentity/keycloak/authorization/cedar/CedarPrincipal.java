package com.twogenidentity.keycloak.authorization.cedar;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Directory facts about the subject of an evaluation, read from Keycloak's stores, never from the
 * request. Free of Keycloak model types so the Cedar mapping can be unit-tested.
 *
 * @param id     Keycloak internal id: the user id, or the client's UUID
 * @param name   username for users, clientId for clients
 * @param roles  effective role names: realm roles as {@code name}, client roles as {@code clientId/name}
 * @param groups group paths ({@code /parent/child}), including ancestors of direct memberships
 * @param tags   the user attributes enabled with the {@code user-attributes} option
 */
record CedarPrincipal(Kind kind, String id, String name, String email, boolean emailVerified, boolean enabled,
        Set<String> roles, Set<String> groups, Map<String, List<String>> tags) {

    enum Kind { USER, CLIENT }

    CedarPrincipal {
        Objects.requireNonNull(kind);
        Objects.requireNonNull(id);
        roles = Set.copyOf(roles);
        groups = Set.copyOf(groups);
        tags = Map.copyOf(tags);
    }

    static CedarPrincipal user(String id, String username, String email, boolean emailVerified, boolean enabled,
            Collection<String> roles, Collection<String> groups, Map<String, List<String>> tags) {
        return new CedarPrincipal(Kind.USER, id, username, email, emailVerified, enabled,
                Set.copyOf(roles), Set.copyOf(groups), tags);
    }

    static CedarPrincipal client(String id, String clientId, boolean enabled, Collection<String> roles) {
        return new CedarPrincipal(Kind.CLIENT, id, clientId, null, false, enabled, Set.copyOf(roles), Set.of(), Map.of());
    }
}
