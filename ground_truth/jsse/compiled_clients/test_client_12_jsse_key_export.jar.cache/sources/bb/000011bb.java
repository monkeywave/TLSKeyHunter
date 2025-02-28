package org.openjsse.sun.security.ssl;

/* JADX INFO: Access modifiers changed from: package-private */
/* compiled from: SSLSessionImpl.java */
/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SecureKey.class */
public class SecureKey {
    private static final Object nullObject = new Object();
    private final Object appKey;
    private final Object securityCtx = getCurrentSecurityContext();

    /* JADX INFO: Access modifiers changed from: package-private */
    public static Object getCurrentSecurityContext() {
        SecurityManager sm = System.getSecurityManager();
        Object context = null;
        if (sm != null) {
            context = sm.getSecurityContext();
        }
        if (context == null) {
            context = nullObject;
        }
        return context;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public SecureKey(Object key) {
        this.appKey = key;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public Object getAppKey() {
        return this.appKey;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public Object getSecurityContext() {
        return this.securityCtx;
    }

    public int hashCode() {
        return this.appKey.hashCode() ^ this.securityCtx.hashCode();
    }

    public boolean equals(Object o) {
        return (o instanceof SecureKey) && ((SecureKey) o).appKey.equals(this.appKey) && ((SecureKey) o).securityCtx.equals(this.securityCtx);
    }
}