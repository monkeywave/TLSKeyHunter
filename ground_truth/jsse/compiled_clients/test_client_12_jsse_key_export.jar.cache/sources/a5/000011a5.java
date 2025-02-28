package org.openjsse.sun.security.ssl;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Locale;
import java.util.Map;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionContext;
import org.openjsse.sun.security.util.Cache;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLSessionContextImpl.class */
public final class SSLSessionContextImpl implements SSLSessionContext {
    private static final int DEFAULT_MAX_CACHE_SIZE = 20480;
    private int cacheLimit = getDefaultCacheLimit();
    private int timeout = 86400;
    private final Cache<SessionId, SSLSessionImpl> sessionCache = Cache.newSoftMemoryCache(this.cacheLimit, this.timeout);
    private final Cache<String, SSLSessionImpl> sessionHostPortCache = Cache.newSoftMemoryCache(this.cacheLimit, this.timeout);

    @Override // javax.net.ssl.SSLSessionContext
    public SSLSession getSession(byte[] sessionId) {
        if (sessionId == null) {
            throw new NullPointerException("session id cannot be null");
        }
        SSLSessionImpl sess = this.sessionCache.get(new SessionId(sessionId));
        if (!isTimedout(sess)) {
            return sess;
        }
        return null;
    }

    @Override // javax.net.ssl.SSLSessionContext
    public Enumeration<byte[]> getIds() {
        SessionCacheVisitor scVisitor = new SessionCacheVisitor();
        this.sessionCache.accept(scVisitor);
        return scVisitor.getSessionIds();
    }

    @Override // javax.net.ssl.SSLSessionContext
    public void setSessionTimeout(int seconds) throws IllegalArgumentException {
        if (seconds < 0) {
            throw new IllegalArgumentException();
        }
        if (this.timeout != seconds) {
            this.sessionCache.setTimeout(seconds);
            this.sessionHostPortCache.setTimeout(seconds);
            this.timeout = seconds;
        }
    }

    @Override // javax.net.ssl.SSLSessionContext
    public int getSessionTimeout() {
        return this.timeout;
    }

    @Override // javax.net.ssl.SSLSessionContext
    public void setSessionCacheSize(int size) throws IllegalArgumentException {
        if (size < 0) {
            throw new IllegalArgumentException();
        }
        if (this.cacheLimit != size) {
            this.sessionCache.setCapacity(size);
            this.sessionHostPortCache.setCapacity(size);
            this.cacheLimit = size;
        }
    }

    @Override // javax.net.ssl.SSLSessionContext
    public int getSessionCacheSize() {
        return this.cacheLimit;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public SSLSessionImpl get(byte[] id) {
        return (SSLSessionImpl) getSession(id);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public SSLSessionImpl pull(byte[] id) {
        if (id != null) {
            return this.sessionCache.pull(new SessionId(id));
        }
        return null;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public SSLSessionImpl get(String hostname, int port) {
        if (hostname == null && port == -1) {
            return null;
        }
        SSLSessionImpl sess = this.sessionHostPortCache.get(getKey(hostname, port));
        if (!isTimedout(sess)) {
            return sess;
        }
        return null;
    }

    private static String getKey(String hostname, int port) {
        return (hostname + ":" + String.valueOf(port)).toLowerCase(Locale.ENGLISH);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void put(SSLSessionImpl s) {
        this.sessionCache.put(s.getSessionId(), s);
        if (s.getPeerHost() != null && s.getPeerPort() != -1) {
            this.sessionHostPortCache.put(getKey(s.getPeerHost(), s.getPeerPort()), s);
        }
        s.setContext(this);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void remove(SessionId key) {
        SSLSessionImpl s = this.sessionCache.get(key);
        if (s != null) {
            this.sessionCache.remove(key);
            this.sessionHostPortCache.remove(getKey(s.getPeerHost(), s.getPeerPort()));
        }
    }

    private static int getDefaultCacheLimit() {
        try {
            String s = (String) AccessController.doPrivileged(new PrivilegedAction<String>() { // from class: org.openjsse.sun.security.ssl.SSLSessionContextImpl.1
                /* JADX WARN: Can't rename method to resolve collision */
                @Override // java.security.PrivilegedAction
                public String run() {
                    return System.getProperty("javax.net.ssl.sessionCacheSize");
                }
            });
            int defaultCacheLimit = s != null ? Integer.parseInt(s) : DEFAULT_MAX_CACHE_SIZE;
            if (defaultCacheLimit >= 0) {
                return defaultCacheLimit;
            }
            if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                SSLLogger.warning("invalid System Property javax.net.ssl.sessionCacheSize, use the default session cache size (20480) instead", new Object[0]);
            }
            return DEFAULT_MAX_CACHE_SIZE;
        } catch (Exception e) {
            if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                SSLLogger.warning("the System Property javax.net.ssl.sessionCacheSize is not available, use the default value (20480) instead", new Object[0]);
                return DEFAULT_MAX_CACHE_SIZE;
            }
            return DEFAULT_MAX_CACHE_SIZE;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public boolean isTimedout(SSLSession sess) {
        if (this.timeout != 0 && sess != null && sess.getCreationTime() + (this.timeout * 1000) <= System.currentTimeMillis()) {
            sess.invalidate();
            return true;
        }
        return false;
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLSessionContextImpl$SessionCacheVisitor.class */
    private final class SessionCacheVisitor implements Cache.CacheVisitor<SessionId, SSLSessionImpl> {
        ArrayList<byte[]> ids;

        private SessionCacheVisitor() {
            this.ids = null;
        }

        @Override // org.openjsse.sun.security.util.Cache.CacheVisitor
        public void visit(Map<SessionId, SSLSessionImpl> map) {
            this.ids = new ArrayList<>(map.size());
            for (SessionId key : map.keySet()) {
                SSLSessionImpl value = map.get(key);
                if (!SSLSessionContextImpl.this.isTimedout(value)) {
                    this.ids.add(key.getId());
                }
            }
        }

        Enumeration<byte[]> getSessionIds() {
            return this.ids != null ? Collections.enumeration(this.ids) : Collections.emptyEnumeration();
        }
    }
}