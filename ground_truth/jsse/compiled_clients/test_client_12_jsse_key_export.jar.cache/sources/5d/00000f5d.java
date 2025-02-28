package org.openjsse.com.sun.net.ssl;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.UnrecoverableKeyException;

/* compiled from: SSLSecurity.java */
/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/com/sun/net/ssl/KeyManagerFactorySpiWrapper.class */
final class KeyManagerFactorySpiWrapper extends KeyManagerFactorySpi {
    private javax.net.ssl.KeyManagerFactory theKeyManagerFactory;

    /* JADX INFO: Access modifiers changed from: package-private */
    public KeyManagerFactorySpiWrapper(String algName, Provider prov) throws NoSuchAlgorithmException {
        this.theKeyManagerFactory = javax.net.ssl.KeyManagerFactory.getInstance(algName, prov);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // org.openjsse.com.sun.net.ssl.KeyManagerFactorySpi
    public void engineInit(KeyStore ks, char[] password) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
        this.theKeyManagerFactory.init(ks, password);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // org.openjsse.com.sun.net.ssl.KeyManagerFactorySpi
    public KeyManager[] engineGetKeyManagers() {
        javax.net.ssl.KeyManager[] kma = this.theKeyManagerFactory.getKeyManagers();
        KeyManager[] kmaw = new KeyManager[kma.length];
        int src = 0;
        int dst = 0;
        while (src < kma.length) {
            if (!(kma[src] instanceof KeyManager)) {
                if (kma[src] instanceof javax.net.ssl.X509KeyManager) {
                    kmaw[dst] = new X509KeyManagerComSunWrapper((javax.net.ssl.X509KeyManager) kma[src]);
                    dst++;
                }
            } else {
                kmaw[dst] = (KeyManager) kma[src];
                dst++;
            }
            src++;
        }
        if (dst != src) {
            kmaw = (KeyManager[]) SSLSecurity.truncateArray(kmaw, new KeyManager[dst]);
        }
        return kmaw;
    }
}