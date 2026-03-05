package com.vecta.kms.internal;

import java.lang.ref.Cleaner;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Thread-safe local key material cache with automatic zeroization.
 */
public class KeyCache {

    private static final Cleaner CLEANER = Cleaner.create();

    private final ConcurrentHashMap<String, CacheEntry> entries = new ConcurrentHashMap<>();
    private final Duration ttl;
    private final boolean enabled;

    public KeyCache() {
        int ttlSec = envInt("VECTA_KEY_CACHE_TTL", 300);
        this.enabled = ttlSec > 0;
        this.ttl = Duration.ofSeconds(ttlSec);
    }

    public boolean isEnabled() {
        return enabled;
    }

    public CacheEntry get(String keyId) {
        if (!enabled) return null;
        CacheEntry e = entries.get(keyId);
        if (e == null) return null;
        if (Instant.now().isAfter(e.expiresAt)) {
            evict(keyId);
            return null;
        }
        return e;
    }

    public void put(String keyId, byte[] material, String algorithm, int version) {
        if (!enabled || material == null || material.length == 0) return;

        byte[] copy = Arrays.copyOf(material, material.length);

        CacheEntry old = entries.get(keyId);
        if (old != null) {
            old.zeroize();
        }

        CacheEntry entry = new CacheEntry(keyId, copy, algorithm, version,
                Instant.now(), Instant.now().plus(ttl));

        // Register cleaner for GC-triggered zeroization
        CLEANER.register(entry, () -> Arrays.fill(copy, (byte) 0));

        entries.put(keyId, entry);
    }

    public void evict(String keyId) {
        CacheEntry e = entries.remove(keyId);
        if (e != null) {
            e.zeroize();
        }
    }

    public void close() {
        entries.forEach((k, v) -> v.zeroize());
        entries.clear();
    }

    public int size() {
        return entries.size();
    }

    public static class CacheEntry {
        public final String keyId;
        public final byte[] material;
        public final String algorithm;
        public final int version;
        public final Instant exportedAt;
        public final Instant expiresAt;

        CacheEntry(String keyId, byte[] material, String algorithm, int version,
                   Instant exportedAt, Instant expiresAt) {
            this.keyId = keyId;
            this.material = material;
            this.algorithm = algorithm;
            this.version = version;
            this.exportedAt = exportedAt;
            this.expiresAt = expiresAt;
        }

        void zeroize() {
            if (material != null) {
                Arrays.fill(material, (byte) 0);
            }
        }
    }

    private static int envInt(String key, int fallback) {
        String v = System.getenv(key);
        if (v == null || v.trim().isEmpty()) return fallback;
        try {
            return Integer.parseInt(v.trim());
        } catch (NumberFormatException e) {
            return fallback;
        }
    }
}
