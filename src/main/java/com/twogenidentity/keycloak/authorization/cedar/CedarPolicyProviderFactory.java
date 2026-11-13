package com.twogenidentity.keycloak.authorization.cedar;

import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.authorization.AuthorizationProvider;
import org.keycloak.authorization.model.Policy;
import org.keycloak.authorization.policy.provider.PolicyProvider;
import org.keycloak.authorization.policy.provider.PolicyProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.keycloak.representations.idm.authorization.PolicyRepresentation;
import org.keycloak.services.ErrorResponseException;

import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class CedarPolicyProviderFactory implements PolicyProviderFactory<CedarPolicyRepresentation> {

    static final String PROVIDER_ID = "cedar";
    static final String CONFIG_CODE = "code";
    private static final Logger logger = Logger.getLogger(CedarPolicyProviderFactory.class);

    /**
     * Comma-separated user attributes sent as Cedar tags on {@code Keycloak::User}
     * ({@code principal.getTag("department")}). Default: none.
     * Set with {@code --spi-policy--cedar--user-attributes=department,country}.
     */
    static final String CONFIG_USER_ATTRIBUTES = "user-attributes";

    private final CedarPolicySets policySets = new CedarPolicySets();
    private final CedarSchemas schemas = new CedarSchemas();
    private volatile Set<String> userAttributes = Set.of();

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getName() {
        return "Cedar";
    }

    @Override
    public String getGroup() {
        return "Rule Based";
    }

    @Override
    public String getDescription() {
        return "Evaluates Cedar policies stored per-policy in the authorization server; code is validated "
                + "against the resource server's Cedar schema (client attribute " + CedarSchemas.CLIENT_ATTRIBUTE
                + ") on every write";
    }

    Set<String> userAttributes() {
        return userAttributes;
    }

    CedarSchemas schemas() {
        return schemas;
    }

    CedarPolicySets policySets() {
        return policySets;
    }

    @Override
    public void init(Config.Scope config) {
        userAttributes = parseList(config.getArray(CONFIG_USER_ATTRIBUTES));
        logger.infof("Cedar: user attributes as tags: %s",
                userAttributes.isEmpty() ? "none" : userAttributes);
    }

    static Set<String> parseList(String[] configured) {
        if (configured == null) {
            return Set.of();
        }
        Set<String> values = new LinkedHashSet<>();
        for (String raw : configured) {
            String value = raw == null ? "" : raw.trim();
            if (!value.isEmpty()) values.add(value);
        }
        return Set.copyOf(values);
    }

    @Override
    public List<ProviderConfigProperty> getConfigMetadata() {
        return ProviderConfigurationBuilder.create()
                .property()
                .name(CONFIG_USER_ATTRIBUTES)
                .type("string")
                .helpText("Comma-separated user attributes sent as Cedar tags on Keycloak::User, "
                        + "e.g. principal.getTag(\"department\"). Default: none.")
                .add()
                .build();
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        logger.infof("Cedar: language version %s",
                com.cedarpolicy.AuthorizationEngine.getCedarLangVersion());
    }

    @Override
    public PolicyProvider create(AuthorizationProvider authorization) {
        return new CedarPolicyProvider(this);
    }

    @Override
    public PolicyProvider create(KeycloakSession session) {
        return null;
    }

    @Override
    public CedarPolicyRepresentation toRepresentation(Policy policy,
            AuthorizationProvider authorization) {
        CedarPolicyRepresentation rep = new CedarPolicyRepresentation();
        rep.setId(policy.getId());
        rep.setName(policy.getName());
        rep.setDescription(policy.getDescription());
        rep.setCode(policy.getConfig().getOrDefault(CONFIG_CODE, ""));
        return rep;
    }

    @Override
    public Class<CedarPolicyRepresentation> getRepresentationType() {
        return CedarPolicyRepresentation.class;
    }

    // Every write is validated against the resource server's schema; invalid code is refused with
    // a 400, so an Admin API, kcadm or realm-import pipeline fails instead of storing it.

    @Override
    public void onCreate(Policy policy,
            CedarPolicyRepresentation representation, AuthorizationProvider authorization) {
        store(policy, representation.getCode(), authorization, "created");
    }

    @Override
    public void onUpdate(Policy policy,
            CedarPolicyRepresentation representation, AuthorizationProvider authorization) {
        // A null code means "not part of this update" (e.g. a rename); an empty code is refused.
        if (representation.getCode() != null) {
            store(policy, representation.getCode(), authorization, "updated");
        }
    }

    @Override
    public void onImport(Policy policy,
            PolicyRepresentation representation, AuthorizationProvider authorization) {
        String code = representation.getConfig() != null ? representation.getConfig().get(CONFIG_CODE) : null;
        store(policy, code, authorization, "imported");
    }

    private void store(Policy policy, String code,
            AuthorizationProvider authorization, String verb) {
        try {
            CedarSchemaModel model = schemas.forResourceServer(policy.getResourceServer(), authorization);
            Set<String> statements = CedarPolicyValidator.ids(CedarPolicyValidator.validate(policy.getName(), code, model.schema));
            putConfig(policy, CONFIG_CODE, code);
            logger.infof("Cedar policy %s: %s, statements=%s", verb, policy.getName(), statements);
        } catch (CedarException e) {
            throw refused(policy, e.errors);
        }
    }

    private static ErrorResponseException refused(Policy policy, List<String> errors) {
        logger.infof("Cedar policy refused: %s: %s", policy.getName(), errors);
        return new ErrorResponseException("invalid_cedar_policy",
                "Invalid Cedar policy '" + policy.getName() + "': " + String.join(" | ", errors),
                Response.Status.BAD_REQUEST);
    }

    private static void putConfig(Policy policy, String key, String value) {
        Map<String, String> config = new HashMap<>(policy.getConfig());
        config.put(key, value);
        policy.setConfig(config);
    }

    @Override
    public void close() {
    }
}
