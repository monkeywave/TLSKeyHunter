package org.bouncycastle.jsse.provider;

import java.security.KeyManagementException;
import java.security.SecureRandom;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.KeyManager;
import javax.net.ssl.TrustManager;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCryptoProvider;

/* loaded from: classes2.dex */
class DefaultSSLContextSpi extends ProvSSLContextSpi {
    private static final Logger LOG = Logger.getLogger(DefaultSSLContextSpi.class.getName());

    /* loaded from: classes2.dex */
    private static class LazyInstance {
        private static final Exception initException;
        private static final DefaultSSLContextSpi instance;

        static {
            Exception exc = LazyManagers.initException;
            DefaultSSLContextSpi defaultSSLContextSpi = null;
            if (exc == null) {
                try {
                    defaultSSLContextSpi = new DefaultSSLContextSpi(false, new JcaTlsCryptoProvider());
                } catch (Exception e) {
                    DefaultSSLContextSpi.LOG.log(Level.WARNING, "Failed to load default SSLContext", (Throwable) e);
                    exc = DefaultSSLContextSpi.avoidCapturingException(e);
                }
            }
            initException = exc;
            instance = defaultSSLContextSpi;
        }

        private LazyInstance() {
        }
    }

    /* loaded from: classes2.dex */
    private static class LazyManagers {
        private static final Exception initException;
        private static final KeyManager[] keyManagers;
        private static final TrustManager[] trustManagers;

        /* JADX WARN: Removed duplicated region for block: B:14:0x002b  */
        /* JADX WARN: Removed duplicated region for block: B:15:0x0031  */
        static {
            /*
                r0 = 0
                javax.net.ssl.TrustManager[] r1 = org.bouncycastle.jsse.provider.ProvSSLContextSpi.getDefaultTrustManagers()     // Catch: java.lang.Exception -> L8
                r2 = r1
                r1 = r0
                goto L15
            L8:
                r1 = move-exception
                java.util.logging.Logger r2 = org.bouncycastle.jsse.provider.DefaultSSLContextSpi.access$100()
                java.util.logging.Level r3 = java.util.logging.Level.WARNING
                java.lang.String r4 = "Failed to load default trust managers"
                r2.log(r3, r4, r1)
                r2 = r0
            L15:
                if (r1 != 0) goto L28
                javax.net.ssl.KeyManager[] r3 = org.bouncycastle.jsse.provider.ProvSSLContextSpi.getDefaultKeyManagers()     // Catch: java.lang.Exception -> L1c
                goto L29
            L1c:
                r1 = move-exception
                java.util.logging.Logger r3 = org.bouncycastle.jsse.provider.DefaultSSLContextSpi.access$100()
                java.util.logging.Level r4 = java.util.logging.Level.WARNING
                java.lang.String r5 = "Failed to load default key managers"
                r3.log(r4, r5, r1)
            L28:
                r3 = r0
            L29:
                if (r1 == 0) goto L31
                java.lang.Exception r1 = org.bouncycastle.jsse.provider.DefaultSSLContextSpi.access$200(r1)
                r2 = r0
                goto L32
            L31:
                r0 = r3
            L32:
                org.bouncycastle.jsse.provider.DefaultSSLContextSpi.LazyManagers.initException = r1
                org.bouncycastle.jsse.provider.DefaultSSLContextSpi.LazyManagers.keyManagers = r0
                org.bouncycastle.jsse.provider.DefaultSSLContextSpi.LazyManagers.trustManagers = r2
                return
            */
            throw new UnsupportedOperationException("Method not decompiled: org.bouncycastle.jsse.provider.DefaultSSLContextSpi.LazyManagers.<clinit>():void");
        }

        private LazyManagers() {
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public DefaultSSLContextSpi(boolean z, JcaTlsCryptoProvider jcaTlsCryptoProvider) throws KeyManagementException {
        super(z, jcaTlsCryptoProvider, null);
        if (LazyManagers.initException != null) {
            throw new KeyManagementException("Default key/trust managers unavailable", LazyManagers.initException);
        }
        super.engineInit(LazyManagers.keyManagers, LazyManagers.trustManagers, null);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static Exception avoidCapturingException(Exception exc) {
        return new KeyManagementException(exc.getMessage());
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static ProvSSLContextSpi getDefaultInstance() throws Exception {
        if (LazyInstance.initException == null) {
            return LazyInstance.instance;
        }
        throw LazyInstance.initException;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // org.bouncycastle.jsse.provider.ProvSSLContextSpi, javax.net.ssl.SSLContextSpi
    public void engineInit(KeyManager[] keyManagerArr, TrustManager[] trustManagerArr, SecureRandom secureRandom) throws KeyManagementException {
        throw new KeyManagementException("Default SSLContext is initialized automatically");
    }
}