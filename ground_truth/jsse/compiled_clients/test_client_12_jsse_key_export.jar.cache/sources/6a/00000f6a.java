package org.openjsse.com.sun.net.ssl;

import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import org.openjsse.javax.net.ssl.SSLEngine;

/* compiled from: SSLSecurity.java */
/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/com/sun/net/ssl/X509KeyManagerJavaxWrapper.class */
final class X509KeyManagerJavaxWrapper implements javax.net.ssl.X509KeyManager {
    private X509KeyManager theX509KeyManager;

    /* JADX INFO: Access modifiers changed from: package-private */
    public X509KeyManagerJavaxWrapper(X509KeyManager obj) {
        this.theX509KeyManager = obj;
    }

    @Override // javax.net.ssl.X509KeyManager
    public String[] getClientAliases(String keyType, Principal[] issuers) {
        return this.theX509KeyManager.getClientAliases(keyType, issuers);
    }

    @Override // javax.net.ssl.X509KeyManager
    public String chooseClientAlias(String[] keyTypes, Principal[] issuers, Socket socket) {
        if (keyTypes == null) {
            return null;
        }
        for (String str : keyTypes) {
            String retval = this.theX509KeyManager.chooseClientAlias(str, issuers);
            if (retval != null) {
                return retval;
            }
        }
        return null;
    }

    public String chooseEngineClientAlias(String[] keyTypes, Principal[] issuers, SSLEngine engine) {
        if (keyTypes == null) {
            return null;
        }
        for (String str : keyTypes) {
            String retval = this.theX509KeyManager.chooseClientAlias(str, issuers);
            if (retval != null) {
                return retval;
            }
        }
        return null;
    }

    @Override // javax.net.ssl.X509KeyManager
    public String[] getServerAliases(String keyType, Principal[] issuers) {
        return this.theX509KeyManager.getServerAliases(keyType, issuers);
    }

    @Override // javax.net.ssl.X509KeyManager
    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
        if (keyType == null) {
            return null;
        }
        return this.theX509KeyManager.chooseServerAlias(keyType, issuers);
    }

    public String chooseEngineServerAlias(String keyType, Principal[] issuers, SSLEngine engine) {
        if (keyType == null) {
            return null;
        }
        return this.theX509KeyManager.chooseServerAlias(keyType, issuers);
    }

    @Override // javax.net.ssl.X509KeyManager
    public X509Certificate[] getCertificateChain(String alias) {
        return this.theX509KeyManager.getCertificateChain(alias);
    }

    @Override // javax.net.ssl.X509KeyManager
    public PrivateKey getPrivateKey(String alias) {
        return this.theX509KeyManager.getPrivateKey(alias);
    }
}