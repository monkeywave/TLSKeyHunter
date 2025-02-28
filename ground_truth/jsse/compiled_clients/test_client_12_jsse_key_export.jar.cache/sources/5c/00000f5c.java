package org.openjsse.com.sun.net.ssl;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;

@Deprecated
/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/com/sun/net/ssl/KeyManagerFactorySpi.class */
public abstract class KeyManagerFactorySpi {
    /* JADX INFO: Access modifiers changed from: protected */
    public abstract void engineInit(KeyStore keyStore, char[] cArr) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException;

    /* JADX INFO: Access modifiers changed from: protected */
    public abstract KeyManager[] engineGetKeyManagers();
}