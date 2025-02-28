package org.openjsse.com.sun.net.ssl;

import java.security.AccessController;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.security.Security;

@Deprecated
/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/com/sun/net/ssl/TrustManagerFactory.class */
public class TrustManagerFactory {
    private Provider provider;
    private TrustManagerFactorySpi factorySpi;
    private String algorithm;

    public static final String getDefaultAlgorithm() {
        String type = (String) AccessController.doPrivileged(new PrivilegedAction<String>() { // from class: org.openjsse.com.sun.net.ssl.TrustManagerFactory.1
            /* JADX WARN: Can't rename method to resolve collision */
            @Override // java.security.PrivilegedAction
            public String run() {
                return Security.getProperty("sun.ssl.trustmanager.type");
            }
        });
        if (type == null) {
            type = "SunX509";
        }
        return type;
    }

    protected TrustManagerFactory(TrustManagerFactorySpi factorySpi, Provider provider, String algorithm) {
        this.factorySpi = factorySpi;
        this.provider = provider;
        this.algorithm = algorithm;
    }

    public final String getAlgorithm() {
        return this.algorithm;
    }

    public static final TrustManagerFactory getInstance(String algorithm) throws NoSuchAlgorithmException {
        try {
            Object[] objs = SSLSecurity.getImpl(algorithm, "TrustManagerFactory", (String) null);
            return new TrustManagerFactory((TrustManagerFactorySpi) objs[0], (Provider) objs[1], algorithm);
        } catch (NoSuchProviderException e) {
            throw new NoSuchAlgorithmException(algorithm + " not found");
        }
    }

    public static final TrustManagerFactory getInstance(String algorithm, String provider) throws NoSuchAlgorithmException, NoSuchProviderException {
        if (provider == null || provider.length() == 0) {
            throw new IllegalArgumentException("missing provider");
        }
        Object[] objs = SSLSecurity.getImpl(algorithm, "TrustManagerFactory", provider);
        return new TrustManagerFactory((TrustManagerFactorySpi) objs[0], (Provider) objs[1], algorithm);
    }

    public static final TrustManagerFactory getInstance(String algorithm, Provider provider) throws NoSuchAlgorithmException {
        if (provider == null) {
            throw new IllegalArgumentException("missing provider");
        }
        Object[] objs = SSLSecurity.getImpl(algorithm, "TrustManagerFactory", provider);
        return new TrustManagerFactory((TrustManagerFactorySpi) objs[0], (Provider) objs[1], algorithm);
    }

    public final Provider getProvider() {
        return this.provider;
    }

    public void init(KeyStore ks) throws KeyStoreException {
        this.factorySpi.engineInit(ks);
    }

    public TrustManager[] getTrustManagers() {
        return this.factorySpi.engineGetTrustManagers();
    }
}