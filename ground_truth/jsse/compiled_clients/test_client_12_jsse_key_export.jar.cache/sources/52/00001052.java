package org.openjsse.sun.security.ssl;

import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedKeyManager;

/* compiled from: SSLContextImpl.java */
/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/DummyX509KeyManager.class */
final class DummyX509KeyManager extends X509ExtendedKeyManager {
    static final X509ExtendedKeyManager INSTANCE = new DummyX509KeyManager();

    private DummyX509KeyManager() {
    }

    @Override // javax.net.ssl.X509KeyManager
    public String[] getClientAliases(String keyType, Principal[] issuers) {
        return null;
    }

    @Override // javax.net.ssl.X509KeyManager
    public String chooseClientAlias(String[] keyTypes, Principal[] issuers, Socket socket) {
        return null;
    }

    @Override // javax.net.ssl.X509ExtendedKeyManager
    public String chooseEngineClientAlias(String[] keyTypes, Principal[] issuers, SSLEngine engine) {
        return null;
    }

    @Override // javax.net.ssl.X509KeyManager
    public String[] getServerAliases(String keyType, Principal[] issuers) {
        return null;
    }

    @Override // javax.net.ssl.X509KeyManager
    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
        return null;
    }

    @Override // javax.net.ssl.X509ExtendedKeyManager
    public String chooseEngineServerAlias(String keyType, Principal[] issuers, SSLEngine engine) {
        return null;
    }

    @Override // javax.net.ssl.X509KeyManager
    public X509Certificate[] getCertificateChain(String alias) {
        return null;
    }

    @Override // javax.net.ssl.X509KeyManager
    public PrivateKey getPrivateKey(String alias) {
        return null;
    }
}