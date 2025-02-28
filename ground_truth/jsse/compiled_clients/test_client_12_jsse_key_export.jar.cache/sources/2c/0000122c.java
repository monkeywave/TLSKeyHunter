package org.openjsse.sun.security.util;

import java.util.Arrays;
import java.util.Map;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/util/Cache.class */
public abstract class Cache<K, V> {

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/util/Cache$CacheVisitor.class */
    public interface CacheVisitor<K, V> {
        void visit(Map<K, V> map);
    }

    public abstract int size();

    public abstract void clear();

    public abstract void put(K k, V v);

    public abstract V get(Object obj);

    public abstract void remove(Object obj);

    public abstract V pull(Object obj);

    public abstract void setCapacity(int i);

    public abstract void setTimeout(int i);

    public abstract void accept(CacheVisitor<K, V> cacheVisitor);

    public static <K, V> Cache<K, V> newSoftMemoryCache(int size) {
        return new MemoryCache(true, size);
    }

    public static <K, V> Cache<K, V> newSoftMemoryCache(int size, int timeout) {
        return new MemoryCache(true, size, timeout);
    }

    public static <K, V> Cache<K, V> newHardMemoryCache(int size) {
        return new MemoryCache(false, size);
    }

    public static <K, V> Cache<K, V> newNullCache() {
        return (Cache<K, V>) NullCache.INSTANCE;
    }

    public static <K, V> Cache<K, V> newHardMemoryCache(int size, int timeout) {
        return new MemoryCache(false, size, timeout);
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/util/Cache$EqualByteArray.class */
    public static class EqualByteArray {

        /* renamed from: b */
        private final byte[] f1012b;
        private int hash;

        public EqualByteArray(byte[] b) {
            this.f1012b = b;
        }

        public int hashCode() {
            int h = this.hash;
            if (h == 0 && this.f1012b.length > 0) {
                int hashCode = Arrays.hashCode(this.f1012b);
                h = hashCode;
                this.hash = hashCode;
            }
            return h;
        }

        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof EqualByteArray)) {
                return false;
            }
            EqualByteArray other = (EqualByteArray) obj;
            return Arrays.equals(this.f1012b, other.f1012b);
        }
    }
}