package org.openjsse.com.sun.net.ssl;

import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.SecureRandom;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocketFactory;

@Deprecated
/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/com/sun/net/ssl/SSLContext.class */
public class SSLContext {
    private Provider provider;
    private SSLContextSpi contextSpi;
    private String protocol;

    protected SSLContext(SSLContextSpi contextSpi, Provider provider, String protocol) {
        this.contextSpi = contextSpi;
        this.provider = provider;
        this.protocol = protocol;
    }

    public static SSLContext getInstance(String protocol) throws NoSuchAlgorithmException {
        try {
            Object[] objs = SSLSecurity.getImpl(protocol, "SSLContext", (String) null);
            return new SSLContext((SSLContextSpi) objs[0], (Provider) objs[1], protocol);
        } catch (NoSuchProviderException e) {
            throw new NoSuchAlgorithmException(protocol + " not found");
        }
    }

    public static SSLContext getInstance(String protocol, String provider) throws NoSuchAlgorithmException, NoSuchProviderException {
        if (provider == null || provider.length() == 0) {
            throw new IllegalArgumentException("missing provider");
        }
        Object[] objs = SSLSecurity.getImpl(protocol, "SSLContext", provider);
        return new SSLContext((SSLContextSpi) objs[0], (Provider) objs[1], protocol);
    }

    public static SSLContext getInstance(String protocol, Provider provider) throws NoSuchAlgorithmException {
        if (provider == null) {
            throw new IllegalArgumentException("missing provider");
        }
        Object[] objs = SSLSecurity.getImpl(protocol, "SSLContext", provider);
        return new SSLContext((SSLContextSpi) objs[0], (Provider) objs[1], protocol);
    }

    public final String getProtocol() {
        return this.protocol;
    }

    public final Provider getProvider() {
        return this.provider;
    }

    public final void init(KeyManager[] km, TrustManager[] tm, SecureRandom random) throws KeyManagementException {
        this.contextSpi.engineInit(km, tm, random);
    }

    public final SSLSocketFactory getSocketFactory() {
        return this.contextSpi.engineGetSocketFactory();
    }

    public final SSLServerSocketFactory getServerSocketFactory() {
        return this.contextSpi.engineGetServerSocketFactory();
    }
}