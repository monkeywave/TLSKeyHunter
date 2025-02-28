package org.openjsse.sun.security.util;

import java.lang.ref.ReferenceQueue;
import java.lang.ref.SoftReference;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import org.openjsse.sun.security.util.Cache;

/* compiled from: Cache.java */
/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/util/MemoryCache.class */
class MemoryCache<K, V> extends Cache<K, V> {
    private static final float LOAD_FACTOR = 0.75f;
    private static final boolean DEBUG = false;
    private final Map<K, CacheEntry<K, V>> cacheMap;
    private int maxSize;
    private long lifetime;
    private long nextExpirationTime;
    private final ReferenceQueue<V> queue;

    /* JADX INFO: Access modifiers changed from: private */
    /* compiled from: Cache.java */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/util/MemoryCache$CacheEntry.class */
    public interface CacheEntry<K, V> {
        boolean isValid(long j);

        void invalidate();

        K getKey();

        V getValue();

        long getExpirationTime();
    }

    public MemoryCache(boolean soft, int maxSize) {
        this(soft, maxSize, 0);
    }

    public MemoryCache(boolean soft, int maxSize, int lifetime) {
        this.nextExpirationTime = Long.MAX_VALUE;
        this.maxSize = maxSize;
        this.lifetime = lifetime * 1000;
        if (soft) {
            this.queue = new ReferenceQueue<>();
        } else {
            this.queue = null;
        }
        this.cacheMap = new LinkedHashMap(1, LOAD_FACTOR, true);
    }

    private void emptyQueue() {
        CacheEntry<K, V> currentEntry;
        if (this.queue == null) {
            return;
        }
        this.cacheMap.size();
        while (true) {
            CacheEntry<K, V> entry = (CacheEntry) this.queue.poll();
            if (entry != null) {
                K key = entry.getKey();
                if (key != null && (currentEntry = this.cacheMap.remove(key)) != null && entry != currentEntry) {
                    this.cacheMap.put(key, currentEntry);
                }
            } else {
                return;
            }
        }
    }

    private void expungeExpiredEntries() {
        emptyQueue();
        if (this.lifetime == 0) {
            return;
        }
        int cnt = 0;
        long time = System.currentTimeMillis();
        if (this.nextExpirationTime > time) {
            return;
        }
        this.nextExpirationTime = Long.MAX_VALUE;
        Iterator<CacheEntry<K, V>> t = this.cacheMap.values().iterator();
        while (t.hasNext()) {
            CacheEntry<K, V> entry = t.next();
            if (!entry.isValid(time)) {
                t.remove();
                cnt++;
            } else if (this.nextExpirationTime > entry.getExpirationTime()) {
                this.nextExpirationTime = entry.getExpirationTime();
            }
        }
    }

    @Override // org.openjsse.sun.security.util.Cache
    public synchronized int size() {
        expungeExpiredEntries();
        return this.cacheMap.size();
    }

    @Override // org.openjsse.sun.security.util.Cache
    public synchronized void clear() {
        if (this.queue != null) {
            for (CacheEntry<K, V> entry : this.cacheMap.values()) {
                entry.invalidate();
            }
            do {
            } while (this.queue.poll() != null);
            this.cacheMap.clear();
        }
        this.cacheMap.clear();
    }

    @Override // org.openjsse.sun.security.util.Cache
    public synchronized void put(K key, V value) {
        emptyQueue();
        long expirationTime = this.lifetime == 0 ? 0L : System.currentTimeMillis() + this.lifetime;
        if (expirationTime < this.nextExpirationTime) {
            this.nextExpirationTime = expirationTime;
        }
        CacheEntry<K, V> newEntry = newEntry(key, value, expirationTime, this.queue);
        CacheEntry<K, V> oldEntry = this.cacheMap.put(key, newEntry);
        if (oldEntry != null) {
            oldEntry.invalidate();
        } else if (this.maxSize > 0 && this.cacheMap.size() > this.maxSize) {
            expungeExpiredEntries();
            if (this.cacheMap.size() > this.maxSize) {
                Iterator<CacheEntry<K, V>> t = this.cacheMap.values().iterator();
                CacheEntry<K, V> lruEntry = t.next();
                t.remove();
                lruEntry.invalidate();
            }
        }
    }

    @Override // org.openjsse.sun.security.util.Cache
    public synchronized V get(Object key) {
        emptyQueue();
        CacheEntry<K, V> entry = this.cacheMap.get(key);
        if (entry == null) {
            return null;
        }
        long time = this.lifetime == 0 ? 0L : System.currentTimeMillis();
        if (!entry.isValid(time)) {
            this.cacheMap.remove(key);
            return null;
        }
        return entry.getValue();
    }

    @Override // org.openjsse.sun.security.util.Cache
    public synchronized void remove(Object key) {
        emptyQueue();
        CacheEntry<K, V> entry = this.cacheMap.remove(key);
        if (entry != null) {
            entry.invalidate();
        }
    }

    @Override // org.openjsse.sun.security.util.Cache
    public synchronized V pull(Object key) {
        emptyQueue();
        CacheEntry<K, V> entry = this.cacheMap.remove(key);
        if (entry == null) {
            return null;
        }
        long time = this.lifetime == 0 ? 0L : System.currentTimeMillis();
        if (entry.isValid(time)) {
            V value = entry.getValue();
            entry.invalidate();
            return value;
        }
        return null;
    }

    @Override // org.openjsse.sun.security.util.Cache
    public synchronized void setCapacity(int size) {
        expungeExpiredEntries();
        if (size > 0 && this.cacheMap.size() > size) {
            Iterator<CacheEntry<K, V>> t = this.cacheMap.values().iterator();
            for (int i = this.cacheMap.size() - size; i > 0; i--) {
                CacheEntry<K, V> lruEntry = t.next();
                t.remove();
                lruEntry.invalidate();
            }
        }
        this.maxSize = size > 0 ? size : 0;
    }

    @Override // org.openjsse.sun.security.util.Cache
    public synchronized void setTimeout(int timeout) {
        emptyQueue();
        this.lifetime = timeout > 0 ? timeout * 1000 : 0L;
    }

    @Override // org.openjsse.sun.security.util.Cache
    public synchronized void accept(Cache.CacheVisitor<K, V> visitor) {
        expungeExpiredEntries();
        Map<K, V> cached = getCachedEntries();
        visitor.visit(cached);
    }

    private Map<K, V> getCachedEntries() {
        Map<K, V> kvmap = new HashMap<>(this.cacheMap.size());
        for (CacheEntry<K, V> entry : this.cacheMap.values()) {
            kvmap.put(entry.getKey(), entry.getValue());
        }
        return kvmap;
    }

    protected CacheEntry<K, V> newEntry(K key, V value, long expirationTime, ReferenceQueue<V> queue) {
        if (queue != null) {
            return new SoftCacheEntry(key, value, expirationTime, queue);
        }
        return new HardCacheEntry(key, value, expirationTime);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* compiled from: Cache.java */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/util/MemoryCache$HardCacheEntry.class */
    public static class HardCacheEntry<K, V> implements CacheEntry<K, V> {
        private K key;
        private V value;
        private long expirationTime;

        HardCacheEntry(K key, V value, long expirationTime) {
            this.key = key;
            this.value = value;
            this.expirationTime = expirationTime;
        }

        @Override // org.openjsse.sun.security.util.MemoryCache.CacheEntry
        public K getKey() {
            return this.key;
        }

        @Override // org.openjsse.sun.security.util.MemoryCache.CacheEntry
        public V getValue() {
            return this.value;
        }

        @Override // org.openjsse.sun.security.util.MemoryCache.CacheEntry
        public long getExpirationTime() {
            return this.expirationTime;
        }

        @Override // org.openjsse.sun.security.util.MemoryCache.CacheEntry
        public boolean isValid(long currentTime) {
            boolean valid = currentTime <= this.expirationTime;
            if (!valid) {
                invalidate();
            }
            return valid;
        }

        @Override // org.openjsse.sun.security.util.MemoryCache.CacheEntry
        public void invalidate() {
            this.key = null;
            this.value = null;
            this.expirationTime = -1L;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* compiled from: Cache.java */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/util/MemoryCache$SoftCacheEntry.class */
    public static class SoftCacheEntry<K, V> extends SoftReference<V> implements CacheEntry<K, V> {
        private K key;
        private long expirationTime;

        SoftCacheEntry(K key, V value, long expirationTime, ReferenceQueue<V> queue) {
            super(value, queue);
            this.key = key;
            this.expirationTime = expirationTime;
        }

        @Override // org.openjsse.sun.security.util.MemoryCache.CacheEntry
        public K getKey() {
            return this.key;
        }

        @Override // org.openjsse.sun.security.util.MemoryCache.CacheEntry
        public V getValue() {
            return get();
        }

        @Override // org.openjsse.sun.security.util.MemoryCache.CacheEntry
        public long getExpirationTime() {
            return this.expirationTime;
        }

        @Override // org.openjsse.sun.security.util.MemoryCache.CacheEntry
        public boolean isValid(long currentTime) {
            boolean valid = currentTime <= this.expirationTime && get() != null;
            if (!valid) {
                invalidate();
            }
            return valid;
        }

        @Override // org.openjsse.sun.security.util.MemoryCache.CacheEntry
        public void invalidate() {
            clear();
            this.key = null;
            this.expirationTime = -1L;
        }
    }
}