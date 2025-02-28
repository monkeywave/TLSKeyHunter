package org.openjsse.com.sun.net.ssl;

import java.security.KeyManagementException;
import java.security.SecureRandom;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocketFactory;

@Deprecated
/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/com/sun/net/ssl/SSLContextSpi.class */
public abstract class SSLContextSpi {
    /* JADX INFO: Access modifiers changed from: protected */
    public abstract void engineInit(KeyManager[] keyManagerArr, TrustManager[] trustManagerArr, SecureRandom secureRandom) throws KeyManagementException;

    /* JADX INFO: Access modifiers changed from: protected */
    public abstract SSLSocketFactory engineGetSocketFactory();

    /* JADX INFO: Access modifiers changed from: protected */
    public abstract SSLServerSocketFactory engineGetServerSocketFactory();
}