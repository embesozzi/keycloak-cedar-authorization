package com.twogenidentity.keycloak.authorization.cedar;

import com.cedarpolicy.BasicAuthorizationEngine;
import com.cedarpolicy.model.AuthorizationRequest;
import com.cedarpolicy.model.AuthorizationResponse;
import com.cedarpolicy.model.AuthorizationSuccessResponse;
import com.cedarpolicy.model.entity.Entity;
import com.cedarpolicy.model.exception.AuthException;
import com.cedarpolicy.model.policy.PolicySet;
import com.cedarpolicy.value.EntityUID;
import com.cedarpolicy.value.Value;
import org.jboss.logging.Logger;
import org.keycloak.authorization.AuthorizationProvider;
import org.keycloak.authorization.model.ResourceServer;
import org.keycloak.authorization.model.Scope;
import org.keycloak.authorization.policy.evaluation.Evaluation;
import org.keycloak.authorization.policy.provider.PolicyProvider;

import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Decides a Keycloak permission with the resource server's Cedar policies. Any failure denies,
 * so the AuthZEN endpoint answers {@code decision: false} rather than an error.
 */
public class CedarPolicyProvider implements PolicyProvider {

    private static final Logger logger = Logger.getLogger(CedarPolicyProvider.class);
    private static final BasicAuthorizationEngine ENGINE = new BasicAuthorizationEngine();

    private final CedarPolicyProviderFactory factory;

    CedarPolicyProvider(CedarPolicyProviderFactory factory) {
        this.factory = factory;
    }

    @Override
    public void evaluate(Evaluation evaluation) {
        String policy = evaluation.getPolicy() != null ? evaluation.getPolicy().getName() : "?";
        try {
            Decision decision = decide(evaluation);
            if (decision.allowed()) {
                logger.debugf("decision=ALLOW policy=%s determining=%s", policy, decision.determining());
                evaluation.grant();
            } else {
                logger.debugf("decision=DENY policy=%s reason=%s", policy, decision.reason());
                evaluation.deny();
            }
        } catch (CedarException e) {
            logger.warnf("decision=DENY policy=%s, cannot evaluate: %s", policy, e.getMessage());
            evaluation.deny();
        } catch (RuntimeException e) {
            logger.warnf(e, "decision=DENY policy=%s, unexpected error", policy);
            evaluation.deny();
        }
    }

    private Decision decide(Evaluation evaluation) throws CedarException {
        AuthorizationProvider authz = evaluation.getAuthorizationProvider();
        ResourceServer resourceServer = evaluation.getPermission().getResourceServer();

        PolicySet policies = factory.policySets().forResourceServer(resourceServer, authz);
        CedarSchemaModel model = factory.schemas().forResourceServer(resourceServer, authz);
        CedarPrincipal principal = CedarPrincipalResolver.resolve(authz, evaluation.getContext().getIdentity(),
                factory.userAttributes())
                .orElseThrow(() -> new CedarException("the subject is not a user or client of the realm"));
        Entity resource = CedarEntityBuilder.resourceEntity(evaluation, model);
        Collection<Scope> scopes = evaluation.getPermission().getScopes();
        List<String> actions = scopes == null ? List.of()
                : scopes.stream().map(Scope::getName).sorted().distinct().toList();
        Map<String, Collection<String>> context = evaluation.getContext().getAttributes().toMap();

        logger.debugf("request principal=%s resource=%s actions=%s",
                CedarEntityBuilder.principalUid(principal), resource.getEUID(), actions);
        return decide(policies, model, principal, resource, actions, context);
    }

    /** Cedar's answer: allowed, with the statements that decided each action, or the reason it is not. */
    record Decision(boolean allowed, Map<String, Set<String>> determining, String reason) {
        static Decision deny(String reason) {
            return new Decision(false, Map.of(), reason);
        }
    }

    /**
     * Asks Cedar about every action and allows only if all of them are allowed: Keycloak can only
     * grant or deny the whole permission, and a resource permission then grants every requested scope.
     */
    static Decision decide(PolicySet policies, CedarSchemaModel model, CedarPrincipal principal, Entity resource,
            List<String> actions, Map<String, Collection<String>> rawContext) throws CedarException {
        if (actions.isEmpty()) {
            throw new CedarException("no scope requested");
        }
        Set<Entity> entities = new HashSet<>(CedarEntityBuilder.principalEntities(principal));
        entities.add(resource);
        EntityUID principalUid = CedarEntityBuilder.principalUid(principal);

        Map<String, Set<String>> determining = new LinkedHashMap<>();
        for (String action : actions) {
            Map<String, Value> context = CedarEntityBuilder.context(model, action, rawContext);
            AuthorizationRequest request = new AuthorizationRequest(principalUid,
                    CedarEntityBuilder.actionUid(model, action), resource.getEUID(),
                    Optional.of(context), Optional.of(model.schema), true);

            AuthorizationResponse response;
            try {
                response = ENGINE.isAuthorized(request, policies, entities);
            } catch (AuthException e) {
                throw new CedarException("Cedar engine error for action '" + action + "': " + e.getMessage());
            }
            AuthorizationSuccessResponse success = response.success.orElseThrow(() -> new CedarException(
                    "Cedar request failed for action '" + action + "': " + response.errors.map(List::toString).orElse("")));
            if (!success.isAllowed()) {
                return Decision.deny("action '" + action + "' not allowed; determining=" + success.getReason()
                        + (success.getErrors().isEmpty() ? "" : " errors=" + success.getErrors()));
            }
            determining.put(action, success.getReason());
        }
        return new Decision(true, determining, null);
    }

    @Override
    public void close() {
    }
}
