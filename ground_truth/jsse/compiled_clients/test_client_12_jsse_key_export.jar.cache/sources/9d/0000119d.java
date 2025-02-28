package org.openjsse.sun.security.ssl;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLPossession.class */
public interface SSLPossession {
    default byte[] encode() {
        return new byte[0];
    }
}