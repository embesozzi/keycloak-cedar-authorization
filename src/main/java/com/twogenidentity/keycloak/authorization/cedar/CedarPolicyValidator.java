package com.twogenidentity.keycloak.authorization.cedar;

import com.cedarpolicy.BasicAuthorizationEngine;
import com.cedarpolicy.model.DetailedError;
import com.cedarpolicy.model.ValidationRequest;
import com.cedarpolicy.model.ValidationResponse;
import com.cedarpolicy.model.exception.AuthException;
import com.cedarpolicy.model.exception.InternalException;
import com.cedarpolicy.model.policy.Policy;
import com.cedarpolicy.model.policy.PolicySet;
import com.cedarpolicy.model.schema.Schema;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Parses and validates the Cedar code of one Keycloak Cedar policy.
 *
 * <p>Each statement gets the id {@code <keycloak-policy-name>#<@id>}, or
 * {@code <keycloak-policy-name>#<n>} (1-based, in source order) without an {@code @id}
 * annotation, so decisions and errors point to the file and statement they came from.
 */
final class CedarPolicyValidator {

    private static final BasicAuthorizationEngine ENGINE = new BasicAuthorizationEngine();

    private CedarPolicyValidator() {
    }

    /** Parses the code into a policy set with named statements. */
    static PolicySet parse(String policyName, String code) throws CedarException {
        if (code == null || code.isBlank()) {
            throw new CedarException(policyName + ": Cedar code is empty; add at least one permit or forbid statement");
        }
        PolicySet parsed;
        try {
            parsed = PolicySet.parsePolicies(code);
        } catch (InternalException e) {
            throw new CedarException(prefixed(policyName, CedarSchemas.errors(e)));
        }
        if (parsed.getNumTemplates() > 0) {
            throw new CedarException(policyName + ": policy templates are not supported; use static policies");
        }
        Map<String, String> statements = parsed.getStaticPolicies();
        if (statements.isEmpty()) {
            throw new CedarException(policyName + ": Cedar code has no permit or forbid statement");
        }

        // Cedar names parsed statements policy0, policy1, ... in source order.
        List<Map.Entry<String, String>> ordered = new ArrayList<>(statements.entrySet());
        ordered.sort(Comparator.comparingInt(e -> Integer.parseInt(e.getKey().replaceAll("\\D", ""))));

        List<String> errors = new ArrayList<>();
        Set<String> ids = new LinkedHashSet<>();
        Set<Policy> named = new LinkedHashSet<>();
        int n = 0;
        for (Map.Entry<String, String> statement : ordered) {
            String id = policyName + "#" + (++n);
            try {
                String annotated = new Policy(statement.getValue(), id).getAnnotation("id");
                if (annotated != null && !annotated.isBlank()) {
                    id = policyName + "#" + annotated;
                }
            } catch (InternalException e) {
                errors.addAll(prefixed(id, CedarSchemas.errors(e)));
            }
            if (!ids.add(id)) {
                errors.add(id + ": duplicate statement id");
            }
            named.add(new Policy(statement.getValue(), id));
        }
        if (!errors.isEmpty()) {
            throw new CedarException(errors);
        }
        return new PolicySet(named);
    }

    /** Parses, then validates the statements against the schema in Cedar's strict mode. */
    static PolicySet validate(String policyName, String code, Schema schema) throws CedarException {
        PolicySet policies = parse(policyName, code);
        ValidationResponse response;
        try {
            response = ENGINE.validate(new ValidationRequest(schema, policies));
        } catch (AuthException e) {
            throw new CedarException(policyName + ": Cedar validation failed: " + e.getMessage());
        }
        if (response.validationPassed()) {
            return policies;
        }
        List<String> errors = new ArrayList<>();
        response.errors.ifPresent(list -> list.forEach(e -> errors.add(policyName + ": " + message(e))));
        response.success.ifPresent(success -> success.validationErrors.forEach(
                e -> errors.add(e.getPolicyId() + ": " + message(e.getError()))));
        throw new CedarException(errors.isEmpty() ? List.of(policyName + ": Cedar validation failed") : errors);
    }

    static Set<String> ids(PolicySet policies) {
        Set<String> ids = new LinkedHashSet<>();
        policies.policies.forEach(p -> ids.add(p.getID()));
        return ids;
    }

    private static String message(DetailedError error) {
        if (error == null) {
            return "unknown error";
        }
        return error.help.map(help -> error.message + " (" + help + ")").orElse(error.message);
    }

    private static List<String> prefixed(String prefix, List<String> messages) {
        return messages.stream().map(m -> prefix + ": " + m).toList();
    }
}
