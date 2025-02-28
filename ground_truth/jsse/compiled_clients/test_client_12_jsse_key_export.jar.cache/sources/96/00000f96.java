package org.openjsse.sun.security.ssl;

import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509KeyManager;

/* compiled from: SSLContextImpl.java */
/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/AbstractKeyManagerWrapper.class */
final class AbstractKeyManagerWrapper extends X509ExtendedKeyManager {

    /* renamed from: km */
    private final X509KeyManager f958km;

    /* JADX INFO: Access modifiers changed from: package-private */
    public AbstractKeyManagerWrapper(X509KeyManager km) {
        this.f958km = km;
    }

    @Override // javax.net.ssl.X509KeyManager
    public String[] getClientAliases(String keyType, Principal[] issuers) {
        return this.f958km.getClientAliases(keyType, issuers);
    }

    @Override // javax.net.ssl.X509KeyManager
    public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
        return this.f958km.chooseClientAlias(keyType, issuers, socket);
    }

    @Override // javax.net.ssl.X509KeyManager
    public String[] getServerAliases(String keyType, Principal[] issuers) {
        return this.f958km.getServerAliases(keyType, issuers);
    }

    @Override // javax.net.ssl.X509KeyManager
    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
        return this.f958km.chooseServerAlias(keyType, issuers, socket);
    }

    @Override // javax.net.ssl.X509KeyManager
    public X509Certificate[] getCertificateChain(String alias) {
        return this.f958km.getCertificateChain(alias);
    }

    @Override // javax.net.ssl.X509KeyManager
    public PrivateKey getPrivateKey(String alias) {
        return this.f958km.getPrivateKey(alias);
    }
}