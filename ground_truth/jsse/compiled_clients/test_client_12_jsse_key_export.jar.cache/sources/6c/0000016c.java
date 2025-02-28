package javassist.scopedpool;

import java.lang.ref.ReferenceQueue;
import java.lang.ref.SoftReference;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/* loaded from: test_client_12_jsse_key_export.jar:javassist/scopedpool/SoftValueHashMap.class */
public class SoftValueHashMap<K, V> implements Map<K, V> {
    private Map<K, SoftValueRef<K, V>> hash;
    private ReferenceQueue<V> queue;

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: test_client_12_jsse_key_export.jar:javassist/scopedpool/SoftValueHashMap$SoftValueRef.class */
    public static class SoftValueRef<K, V> extends SoftReference<V> {
        public K key;

        private SoftValueRef(K key, V val, ReferenceQueue<V> q) {
            super(val, q);
            this.key = key;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static <K, V> SoftValueRef<K, V> create(K key, V val, ReferenceQueue<V> q) {
            if (val == null) {
                return null;
            }
            return new SoftValueRef<>(key, val, q);
        }
    }

    @Override // java.util.Map
    public Set<Map.Entry<K, V>> entrySet() {
        processQueue();
        Set<Map.Entry<K, V>> ret = new HashSet<>();
        for (Map.Entry<K, SoftValueRef<K, V>> e : this.hash.entrySet()) {
            ret.add(new AbstractMap.SimpleImmutableEntry<>(e.getKey(), e.getValue().get()));
        }
        return ret;
    }

    private void processQueue() {
        if (this.hash.isEmpty()) {
            return;
        }
        while (true) {
            Object ref = this.queue.poll();
            if (ref != null) {
                if (ref instanceof SoftValueRef) {
                    SoftValueRef que = (SoftValueRef) ref;
                    if (ref == this.hash.get(que.key)) {
                        this.hash.remove(que.key);
                    }
                }
            } else {
                return;
            }
        }
    }

    public SoftValueHashMap(int initialCapacity, float loadFactor) {
        this.queue = new ReferenceQueue<>();
        this.hash = new ConcurrentHashMap(initialCapacity, loadFactor);
    }

    public SoftValueHashMap(int initialCapacity) {
        this.queue = new ReferenceQueue<>();
        this.hash = new ConcurrentHashMap(initialCapacity);
    }

    public SoftValueHashMap() {
        this.queue = new ReferenceQueue<>();
        this.hash = new ConcurrentHashMap();
    }

    /* JADX WARN: Multi-variable type inference failed */
    public SoftValueHashMap(Map<K, V> t) {
        this(Math.max(2 * t.size(), 11), 0.75f);
        putAll(t);
    }

    @Override // java.util.Map
    public int size() {
        processQueue();
        return this.hash.size();
    }

    @Override // java.util.Map
    public boolean isEmpty() {
        processQueue();
        return this.hash.isEmpty();
    }

    @Override // java.util.Map
    public boolean containsKey(Object key) {
        processQueue();
        return this.hash.containsKey(key);
    }

    @Override // java.util.Map
    public V get(Object key) {
        processQueue();
        return valueOrNull(this.hash.get(key));
    }

    @Override // java.util.Map
    public V put(K key, V value) {
        processQueue();
        return valueOrNull(this.hash.put(key, SoftValueRef.create(key, value, this.queue)));
    }

    @Override // java.util.Map
    public V remove(Object key) {
        processQueue();
        return valueOrNull(this.hash.remove(key));
    }

    @Override // java.util.Map
    public void clear() {
        processQueue();
        this.hash.clear();
    }

    @Override // java.util.Map
    public boolean containsValue(Object arg0) {
        processQueue();
        if (null == arg0) {
            return false;
        }
        for (SoftValueRef<K, V> e : this.hash.values()) {
            if (null != e && arg0.equals(e.get())) {
                return true;
            }
        }
        return false;
    }

    @Override // java.util.Map
    public Set<K> keySet() {
        processQueue();
        return this.hash.keySet();
    }

    @Override // java.util.Map
    public void putAll(Map<? extends K, ? extends V> arg0) {
        processQueue();
        for (K key : arg0.keySet()) {
            put(key, arg0.get(key));
        }
    }

    @Override // java.util.Map
    public Collection<V> values() {
        processQueue();
        List<V> ret = new ArrayList<>();
        for (SoftValueRef<K, V> e : this.hash.values()) {
            ret.add(e.get());
        }
        return ret;
    }

    private V valueOrNull(SoftValueRef<K, V> rtn) {
        if (null == rtn) {
            return null;
        }
        return rtn.get();
    }
}