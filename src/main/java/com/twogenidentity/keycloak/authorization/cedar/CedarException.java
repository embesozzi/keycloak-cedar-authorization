package com.twogenidentity.keycloak.authorization.cedar;

import java.util.List;

/**
 * Something about the Cedar setup or the request prevents a decision: an invalid schema or
 * policy, or a request naming a type or action the schema does not declare. Evaluations deny;
 * writes are refused with these errors.
 */
final class CedarException extends Exception {

    final List<String> errors;

    CedarException(String error) {
        this(List.of(error));
    }

    CedarException(List<String> errors) {
        super(String.join(" | ", errors));
        this.errors = List.copyOf(errors);
    }
}
