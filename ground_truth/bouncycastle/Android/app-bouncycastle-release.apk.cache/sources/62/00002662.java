package org.bouncycastle.jsse.provider;

import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import org.bouncycastle.jsse.BCX509ExtendedKeyManager;
import org.bouncycastle.jsse.BCX509Key;

/* loaded from: classes2.dex */
final class DummyX509KeyManager extends BCX509ExtendedKeyManager {
    static final BCX509ExtendedKeyManager INSTANCE = new DummyX509KeyManager();

    private DummyX509KeyManager() {
    }

    @Override // javax.net.ssl.X509KeyManager
    public String chooseClientAlias(String[] strArr, Principal[] principalArr, Socket socket) {
        return null;
    }

    @Override // javax.net.ssl.X509KeyManager
    public String chooseServerAlias(String str, Principal[] principalArr, Socket socket) {
        return null;
    }

    @Override // javax.net.ssl.X509KeyManager
    public X509Certificate[] getCertificateChain(String str) {
        return null;
    }

    @Override // javax.net.ssl.X509KeyManager
    public String[] getClientAliases(String str, Principal[] principalArr) {
        return null;
    }

    @Override // org.bouncycastle.jsse.BCX509ExtendedKeyManager
    protected BCX509Key getKeyBC(String str, String str2) {
        return null;
    }

    @Override // javax.net.ssl.X509KeyManager
    public PrivateKey getPrivateKey(String str) {
        return null;
    }

    @Override // javax.net.ssl.X509KeyManager
    public String[] getServerAliases(String str, Principal[] principalArr) {
        return null;
    }
}