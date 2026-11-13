package com.twogenidentity.keycloak.authorization.cedar;

import org.jboss.logging.Logger;
import org.keycloak.authorization.AuthorizationProvider;
import org.keycloak.authorization.identity.Identity;
import org.keycloak.models.ClientModel;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleContainerModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.ModelToRepresentation;
import org.keycloak.models.utils.RoleUtils;

import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Resolves the evaluation subject against Keycloak's user and client stores.
 *
 * <p>Keycloak's AuthZEN endpoint has already mapped {@code subject.type/id} to a stored user
 * ({@code UserModelIdentity}, id = user id) or client ({@code ClientModelIdentity}, id = client UUID).
 * Other Authorization Services flows provide a token identity whose id is the {@code sub}, i.e. a user
 * id, which for a service account is linked back to its client. Either way the principal's roles,
 * groups and identifiers come from the store; {@code subject.properties} are ignored.
 */
final class CedarPrincipalResolver {

    private static final Logger logger = Logger.getLogger(CedarPrincipalResolver.class);

    private CedarPrincipalResolver() {
    }

    static Optional<CedarPrincipal> resolve(AuthorizationProvider authz, Identity identity, Set<String> userAttributes) {
        KeycloakSession session = authz.getKeycloakSession();
        RealmModel realm = authz.getRealm();
        String id = identity.getId();
        if (id == null || id.isBlank()) {
            return Optional.empty();
        }

        UserModel user = session.users().getUserById(realm, id);
        ClientModel client = null;
        if (user != null && user.getServiceAccountClientLink() != null) {
            client = realm.getClientById(user.getServiceAccountClientLink());
        } else if (user == null) {
            client = realm.getClientById(id);
            if (client != null && client.isServiceAccountsEnabled()) {
                user = session.users().getServiceAccount(client);
            }
        }

        if (client != null) {
            Set<String> roles = user != null ? roleNames(user) : Set.of();
            return Optional.of(CedarPrincipal.client(client.getId(), client.getClientId(), client.isEnabled(), roles));
        }
        if (user != null) {
            return Optional.of(CedarPrincipal.user(user.getId(), user.getUsername(), user.getEmail(),
                    user.isEmailVerified(), user.isEnabled(), roleNames(user), groupPaths(user),
                    userTags(user, userAttributes)));
        }
        logger.debugf("subject id='%s' is neither a user nor a client in realm '%s'",
                id, realm.getName());
        return Optional.empty();
    }

    /** Effective roles: direct, composite and inherited from groups. */
    private static Set<String> roleNames(UserModel user) {
        Set<String> names = new LinkedHashSet<>();
        for (RoleModel role : RoleUtils.getDeepUserRoleMappings(user)) {
            names.add(roleName(role));
        }
        return names;
    }

    static String roleName(RoleModel role) {
        if (role.isClientRole()) {
            RoleContainerModel container = role.getContainer();
            String clientId = container instanceof ClientModel c ? c.getClientId() : role.getContainerId();
            return clientId + "/" + role.getName();
        }
        return role.getName();
    }

    private static Set<String> groupPaths(UserModel user) {
        Set<String> paths = new LinkedHashSet<>();
        user.getGroupsStream().forEach(group -> {
            for (GroupModel g = group; g != null; g = g.getParent()) {
                if (!paths.add(ModelToRepresentation.buildGroupPath(g))) {
                    break; // ancestors already added
                }
            }
        });
        return paths;
    }

    /** The allowlisted user attributes, as Cedar tags. */
    private static Map<String, List<String>> userTags(UserModel user, Set<String> userAttributes) {
        if (userAttributes.isEmpty()) {
            return Map.of();
        }
        Map<String, List<String>> tags = new HashMap<>();
        for (String name : userAttributes) {
            List<String> values = user.getAttributeStream(name).filter(v -> v != null).toList();
            if (!values.isEmpty()) {
                tags.put(name, values);
            }
        }
        return tags;
    }
}
