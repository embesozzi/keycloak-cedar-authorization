package com.twogenidentity.keycloak.authorization.cedar;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * A small cache keyed by a hash of the content it was built from. Changed content is a new key, so
 * the cache is correct on every cluster node without invalidation. When full it is simply cleared.
 */
final class ContentCache<V> {

    private static final int MAX_ENTRIES = 256;

    private final Map<String, V> entries = new ConcurrentHashMap<>();

    V get(String key) {
        return entries.get(key);
    }

    void put(String key, V value) {
        if (entries.size() >= MAX_ENTRIES) {
            entries.clear();
        }
        entries.put(key, value);
    }

    /** SHA-256 of the parts, separated so that ("ab", "c") and ("a", "bc") differ. */
    static String key(String... parts) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            for (String part : parts) {
                digest.update(String.valueOf(part).getBytes(StandardCharsets.UTF_8));
                digest.update((byte) 0);
            }
            return HexFormat.of().formatHex(digest.digest());
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
