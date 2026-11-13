package com.twogenidentity.keycloak.authorization.cedar;

import com.cedarpolicy.model.policy.Policy;
import com.cedarpolicy.model.policy.PolicySet;
import org.jboss.logging.Logger;
import org.keycloak.authorization.AuthorizationProvider;
import org.keycloak.authorization.model.ResourceServer;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

/**
 * Compiles all Cedar policies of a resource server into one policy set, so Cedar's semantics hold
 * across policies: a {@code forbid} in one overrides a {@code permit} in another.
 *
 * <p>Fails closed: if any of them cannot be compiled, the whole set is refused (skipping one could
 * drop a {@code forbid}). Results are cached by a hash of every policy's name and code, so a change
 * is picked up on every cluster node without invalidation.
 */
final class CedarPolicySets {

    private static final Logger logger = Logger.getLogger(CedarPolicySets.class);

    /** One Keycloak Cedar policy: its name (unique per resource server) and code. */
    record Source(String name, String code) {
    }

    /** A compiled set, or the error that prevented it; failures are cached too. */
    private record Entry(PolicySet policies, CedarException error) {
    }

    private final ContentCache<Entry> cache = new ContentCache<>();

    PolicySet forResourceServer(ResourceServer resourceServer, AuthorizationProvider authz) throws CedarException {
        List<Source> sources = authz.getStoreFactory().getPolicyStore()
                .findByType(resourceServer, CedarPolicyProviderFactory.PROVIDER_ID).stream()
                .map(p -> new Source(p.getName(), p.getConfig().get(CedarPolicyProviderFactory.CONFIG_CODE)))
                .toList();
        return compile(sources);
    }

    /** Compiles the sources into one set; the order they are given in does not matter. */
    PolicySet compile(List<Source> sources) throws CedarException {
        List<Source> ordered = new ArrayList<>(sources);
        ordered.sort(Comparator.comparing(Source::name));
        String key = ContentCache.key(ordered.stream()
                .flatMap(s -> Stream.of(s.name(), s.code())).toArray(String[]::new));
        Entry entry = cache.get(key);
        if (entry == null) {
            try {
                entry = new Entry(compileUncached(ordered), null);
            } catch (CedarException e) {
                logger.errorf("Cedar policies %s cannot be compiled, every evaluation will deny: %s",
                        ordered.stream().map(Source::name).toList(), e.errors);
                entry = new Entry(null, e);
            }
            cache.put(key, entry);
        }
        if (entry.error() != null) {
            throw entry.error();
        }
        return entry.policies();
    }

    static PolicySet compileUncached(List<Source> sources) throws CedarException {
        if (sources.isEmpty()) {
            throw new CedarException("the resource server has no Cedar policies");
        }
        Set<Policy> statements = new LinkedHashSet<>();
        List<String> errors = new ArrayList<>();
        for (Source source : sources) {
            try {
                statements.addAll(CedarPolicyValidator.parse(source.name(), source.code()).policies);
            } catch (CedarException e) {
                errors.addAll(e.errors);
            }
        }
        if (!errors.isEmpty()) {
            throw new CedarException(errors);
        }
        return new PolicySet(statements);
    }

}
