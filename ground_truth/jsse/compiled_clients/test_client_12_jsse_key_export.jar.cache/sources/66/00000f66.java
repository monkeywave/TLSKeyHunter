package org.openjsse.com.sun.net.ssl;

import java.security.KeyStore;
import java.security.KeyStoreException;

@Deprecated
/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/com/sun/net/ssl/TrustManagerFactorySpi.class */
public abstract class TrustManagerFactorySpi {
    /* JADX INFO: Access modifiers changed from: protected */
    public abstract void engineInit(KeyStore keyStore) throws KeyStoreException;

    /* JADX INFO: Access modifiers changed from: protected */
    public abstract TrustManager[] engineGetTrustManagers();
}