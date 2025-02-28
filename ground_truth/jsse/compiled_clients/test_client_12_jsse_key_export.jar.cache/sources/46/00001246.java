package org.openjsse.sun.security.util;

import org.openjsse.sun.security.util.Cache;

/* compiled from: Cache.java */
/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/util/NullCache.class */
class NullCache<K, V> extends Cache<K, V> {
    static final Cache<Object, Object> INSTANCE = new NullCache();

    private NullCache() {
    }

    @Override // org.openjsse.sun.security.util.Cache
    public int size() {
        return 0;
    }

    @Override // org.openjsse.sun.security.util.Cache
    public void clear() {
    }

    @Override // org.openjsse.sun.security.util.Cache
    public void put(K key, V value) {
    }

    @Override // org.openjsse.sun.security.util.Cache
    public V get(Object key) {
        return null;
    }

    @Override // org.openjsse.sun.security.util.Cache
    public void remove(Object key) {
    }

    @Override // org.openjsse.sun.security.util.Cache
    public V pull(Object key) {
        return null;
    }

    @Override // org.openjsse.sun.security.util.Cache
    public void setCapacity(int size) {
    }

    @Override // org.openjsse.sun.security.util.Cache
    public void setTimeout(int timeout) {
    }

    @Override // org.openjsse.sun.security.util.Cache
    public void accept(Cache.CacheVisitor<K, V> visitor) {
    }
}