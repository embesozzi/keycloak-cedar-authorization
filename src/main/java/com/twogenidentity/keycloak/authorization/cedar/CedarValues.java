package com.twogenidentity.keycloak.authorization.cedar;

import com.cedarpolicy.value.CedarList;
import com.cedarpolicy.value.PrimBool;
import com.cedarpolicy.value.PrimLong;
import com.cedarpolicy.value.PrimString;
import com.cedarpolicy.value.Value;
import com.fasterxml.jackson.core.type.TypeReference;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/** Converts Keycloak's string values to the Cedar types a schema declares. */
final class CedarValues {

    private static final TypeReference<List<String>> STRING_LIST = new TypeReference<>() { };

    private CedarValues() {
    }

    /** The declared keys that have a value in {@code sources}, each converted to its declared kind. */
    static Map<String, Value> typed(Map<String, CedarSchemaModel.Kind> declared, Map<String, Collection<String>> sources) {
        Map<String, Value> out = new LinkedHashMap<>();
        declared.forEach((key, kind) -> {
            Collection<String> raw = sources.get(key);
            if (raw != null) {
                convert(kind, raw).ifPresent(v -> out.put(key, v));
            }
        });
        return out;
    }

    static Optional<Value> convert(CedarSchemaModel.Kind kind, Collection<String> raw) {
        if (raw == null || kind == null) {
            return Optional.empty();
        }
        List<String> values = raw.stream().filter(v -> v != null).toList();
        Optional<String> first = values.stream().findFirst();
        switch (kind) {
            case STRING:
                return first.map(PrimString::new);
            case LONG:
                try {
                    return first.map(v -> new PrimLong(Long.parseLong(v.trim())));
                } catch (NumberFormatException e) {
                    return Optional.empty();
                }
            case BOOL:
                return first.map(String::trim)
                        .filter(v -> v.equalsIgnoreCase("true") || v.equalsIgnoreCase("false"))
                        .map(v -> new PrimBool(Boolean.parseBoolean(v)));
            case STRING_SET:
                List<String> elements = new ArrayList<>();
                values.forEach(v -> elements.addAll(jsonArray(v).orElse(List.of(v))));
                return Optional.of(stringSet(elements));
            default:
                return Optional.empty();
        }
    }

    static CedarList stringSet(Collection<String> values) {
        return new CedarList(values.stream().<Value>map(PrimString::new).toList());
    }

    /**
     * Keycloak limitation (26.7): {@code AuthZenResource.convertValues()} turns every AuthZEN
     * {@code context} value into one string, so {@code ["passkeys","mfa"]} arrives as its JSON text.
     * This reads such an array back; empty when the value is not a JSON array of strings.
     */
    private static Optional<List<String>> jsonArray(String value) {
        if (!value.trim().startsWith("[")) {
            return Optional.empty();
        }
        try {
            return Optional.of(JsonSerialization.readValue(value, STRING_LIST));
        } catch (IOException e) {
            return Optional.empty();
        }
    }
}
