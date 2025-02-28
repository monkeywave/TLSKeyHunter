package org.openjsse.com.sun.net.ssl;

import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocketFactory;

/* compiled from: SSLSecurity.java */
/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/com/sun/net/ssl/SSLContextSpiWrapper.class */
final class SSLContextSpiWrapper extends SSLContextSpi {
    private javax.net.ssl.SSLContext theSSLContext;

    /* JADX INFO: Access modifiers changed from: package-private */
    public SSLContextSpiWrapper(String algName, Provider prov) throws NoSuchAlgorithmException {
        this.theSSLContext = javax.net.ssl.SSLContext.getInstance(algName, prov);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // org.openjsse.com.sun.net.ssl.SSLContextSpi
    public void engineInit(KeyManager[] kma, TrustManager[] tma, SecureRandom sr) throws KeyManagementException {
        javax.net.ssl.KeyManager[] kmaw;
        javax.net.ssl.TrustManager[] tmaw;
        if (kma != null) {
            kmaw = new javax.net.ssl.KeyManager[kma.length];
            int src = 0;
            int dst = 0;
            while (src < kma.length) {
                if (!(kma[src] instanceof javax.net.ssl.KeyManager)) {
                    if (kma[src] instanceof X509KeyManager) {
                        kmaw[dst] = new X509KeyManagerJavaxWrapper((X509KeyManager) kma[src]);
                        dst++;
                    }
                } else {
                    kmaw[dst] = (javax.net.ssl.KeyManager) kma[src];
                    dst++;
                }
                src++;
            }
            if (dst != src) {
                kmaw = (javax.net.ssl.KeyManager[]) SSLSecurity.truncateArray(kmaw, new javax.net.ssl.KeyManager[dst]);
            }
        } else {
            kmaw = null;
        }
        if (tma != null) {
            tmaw = new javax.net.ssl.TrustManager[tma.length];
            int src2 = 0;
            int dst2 = 0;
            while (src2 < tma.length) {
                if (!(tma[src2] instanceof javax.net.ssl.TrustManager)) {
                    if (tma[src2] instanceof X509TrustManager) {
                        tmaw[dst2] = new X509TrustManagerJavaxWrapper((X509TrustManager) tma[src2]);
                        dst2++;
                    }
                } else {
                    tmaw[dst2] = (javax.net.ssl.TrustManager) tma[src2];
                    dst2++;
                }
                src2++;
            }
            if (dst2 != src2) {
                tmaw = (javax.net.ssl.TrustManager[]) SSLSecurity.truncateArray(tmaw, new javax.net.ssl.TrustManager[dst2]);
            }
        } else {
            tmaw = null;
        }
        this.theSSLContext.init(kmaw, tmaw, sr);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // org.openjsse.com.sun.net.ssl.SSLContextSpi
    public SSLSocketFactory engineGetSocketFactory() {
        return this.theSSLContext.getSocketFactory();
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // org.openjsse.com.sun.net.ssl.SSLContextSpi
    public SSLServerSocketFactory engineGetServerSocketFactory() {
        return this.theSSLContext.getServerSocketFactory();
    }
}