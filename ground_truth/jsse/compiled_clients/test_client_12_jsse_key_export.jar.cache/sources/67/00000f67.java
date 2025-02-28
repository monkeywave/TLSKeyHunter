package org.openjsse.com.sun.net.ssl;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;

/* JADX INFO: Access modifiers changed from: package-private */
/* compiled from: SSLSecurity.java */
/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/com/sun/net/ssl/TrustManagerFactorySpiWrapper.class */
public final class TrustManagerFactorySpiWrapper extends TrustManagerFactorySpi {
    private javax.net.ssl.TrustManagerFactory theTrustManagerFactory;

    /* JADX INFO: Access modifiers changed from: package-private */
    public TrustManagerFactorySpiWrapper(String algName, Provider prov) throws NoSuchAlgorithmException {
        this.theTrustManagerFactory = javax.net.ssl.TrustManagerFactory.getInstance(algName, prov);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // org.openjsse.com.sun.net.ssl.TrustManagerFactorySpi
    public void engineInit(KeyStore ks) throws KeyStoreException {
        this.theTrustManagerFactory.init(ks);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // org.openjsse.com.sun.net.ssl.TrustManagerFactorySpi
    public TrustManager[] engineGetTrustManagers() {
        javax.net.ssl.TrustManager[] tma = this.theTrustManagerFactory.getTrustManagers();
        TrustManager[] tmaw = new TrustManager[tma.length];
        int src = 0;
        int dst = 0;
        while (src < tma.length) {
            if (!(tma[src] instanceof TrustManager)) {
                if (tma[src] instanceof javax.net.ssl.X509TrustManager) {
                    tmaw[dst] = new X509TrustManagerComSunWrapper((javax.net.ssl.X509TrustManager) tma[src]);
                    dst++;
                }
            } else {
                tmaw[dst] = (TrustManager) tma[src];
                dst++;
            }
            src++;
        }
        if (dst != src) {
            tmaw = (TrustManager[]) SSLSecurity.truncateArray(tmaw, new TrustManager[dst]);
        }
        return tmaw;
    }
}