package org.openjsse.com.sun.net.ssl;

import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/* compiled from: SSLSecurity.java */
/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/com/sun/net/ssl/X509KeyManagerComSunWrapper.class */
final class X509KeyManagerComSunWrapper implements X509KeyManager {
    private javax.net.ssl.X509KeyManager theX509KeyManager;

    /* JADX INFO: Access modifiers changed from: package-private */
    public X509KeyManagerComSunWrapper(javax.net.ssl.X509KeyManager obj) {
        this.theX509KeyManager = obj;
    }

    @Override // org.openjsse.com.sun.net.ssl.X509KeyManager
    public String[] getClientAliases(String keyType, Principal[] issuers) {
        return this.theX509KeyManager.getClientAliases(keyType, issuers);
    }

    @Override // org.openjsse.com.sun.net.ssl.X509KeyManager
    public String chooseClientAlias(String keyType, Principal[] issuers) {
        String[] keyTypes = {keyType};
        return this.theX509KeyManager.chooseClientAlias(keyTypes, issuers, null);
    }

    @Override // org.openjsse.com.sun.net.ssl.X509KeyManager
    public String[] getServerAliases(String keyType, Principal[] issuers) {
        return this.theX509KeyManager.getServerAliases(keyType, issuers);
    }

    @Override // org.openjsse.com.sun.net.ssl.X509KeyManager
    public String chooseServerAlias(String keyType, Principal[] issuers) {
        return this.theX509KeyManager.chooseServerAlias(keyType, issuers, null);
    }

    @Override // org.openjsse.com.sun.net.ssl.X509KeyManager
    public X509Certificate[] getCertificateChain(String alias) {
        return this.theX509KeyManager.getCertificateChain(alias);
    }

    @Override // org.openjsse.com.sun.net.ssl.X509KeyManager
    public PrivateKey getPrivateKey(String alias) {
        return this.theX509KeyManager.getPrivateKey(alias);
    }
}