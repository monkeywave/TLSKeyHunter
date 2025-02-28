package org.openjsse.sun.security.ssl;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.security.ProviderException;
import java.security.Security;
import org.openjsse.sun.security.validator.Validator;
import sun.security.util.ObjectIdentifier;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/OpenJSSE.class */
public abstract class OpenJSSE extends Provider {
    private static final long serialVersionUID = 3231825739635378733L;
    private static Boolean fips;
    static Provider cryptoProvider;
    private static String fipsInfo = "JDK JSSE provider (FIPS mode, crypto provider ";
    public static final double PROVIDER_VER = Double.parseDouble(System.getProperty("java.specification.version"));
    private static String info = "JDK JSSE provider(PKCS12, SunX509/PKIX key/trust factories, SSLv3/TLSv1/TLSv1.1/TLSv1.2/TLSv1.3)";

    /* JADX INFO: Access modifiers changed from: protected */
    public static synchronized boolean isFIPS() {
        if (fips == null) {
            fips = false;
        }
        return fips.booleanValue();
    }

    private static synchronized void ensureFIPS(Provider p) {
        if (fips == null) {
            fips = true;
            cryptoProvider = p;
        } else if (!fips.booleanValue()) {
            throw new ProviderException("OpenJSSE already initialized in non-FIPS mode");
        } else {
            if (cryptoProvider != p) {
                throw new ProviderException("OpenJSSE already initialized with FIPS crypto provider " + cryptoProvider);
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public OpenJSSE() {
        super("OpenJSSE", PROVIDER_VER, info);
        subclassCheck();
        if (Boolean.TRUE.equals(fips)) {
            throw new ProviderException("OpenJSSE is already initialized in FIPS mode");
        }
        registerAlgorithms(false);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public OpenJSSE(Provider cryptoProvider2) {
        this((Provider) checkNull(cryptoProvider2), cryptoProvider2.getName());
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public OpenJSSE(String cryptoProvider2) {
        this(null, (String) checkNull(cryptoProvider2));
    }

    private static <T> T checkNull(T t) {
        if (t == null) {
            throw new ProviderException("cryptoProvider must not be null");
        }
        return t;
    }

    private OpenJSSE(Provider cryptoProvider2, String providerName) {
        super("OpenJSSE", PROVIDER_VER, fipsInfo + providerName + ")");
        subclassCheck();
        if (cryptoProvider2 == null) {
            cryptoProvider2 = Security.getProvider(providerName);
            if (cryptoProvider2 == null) {
                throw new ProviderException("Crypto provider not installed: " + providerName);
            }
        }
        ensureFIPS(cryptoProvider2);
        registerAlgorithms(true);
    }

    private void registerAlgorithms(final boolean isfips) {
        AccessController.doPrivileged(new PrivilegedAction<Object>() { // from class: org.openjsse.sun.security.ssl.OpenJSSE.1
            @Override // java.security.PrivilegedAction
            public Object run() {
                OpenJSSE.this.doRegister(isfips);
                return null;
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void doRegister(boolean isfips) {
        if (!isfips) {
            put("KeyFactory.RSA", "sun.security.rsa.RSAKeyFactory$Legacy");
            put("Alg.Alias.KeyFactory.1.2.840.113549.1.1", "RSA");
            put("Alg.Alias.KeyFactory.OID.1.2.840.113549.1.1", "RSA");
            put("KeyPairGenerator.RSA", "sun.security.rsa.RSAKeyPairGenerator$Legacy");
            put("Alg.Alias.KeyPairGenerator.1.2.840.113549.1.1", "RSA");
            put("Alg.Alias.KeyPairGenerator.OID.1.2.840.113549.1.1", "RSA");
            put("Signature.MD2withRSA", "sun.security.rsa.RSASignature$MD2withRSA");
            put("Alg.Alias.Signature.1.2.840.113549.1.1.2", "MD2withRSA");
            put("Alg.Alias.Signature.OID.1.2.840.113549.1.1.2", "MD2withRSA");
            put("Signature.MD5withRSA", "sun.security.rsa.RSASignature$MD5withRSA");
            put("Alg.Alias.Signature.1.2.840.113549.1.1.4", "MD5withRSA");
            put("Alg.Alias.Signature.OID.1.2.840.113549.1.1.4", "MD5withRSA");
            put("Signature.SHA1withRSA", "sun.security.rsa.RSASignature$SHA1withRSA");
            put("Alg.Alias.Signature.1.2.840.113549.1.1.5", "SHA1withRSA");
            put("Alg.Alias.Signature.OID.1.2.840.113549.1.1.5", "SHA1withRSA");
            put("Alg.Alias.Signature.1.3.14.3.2.29", "SHA1withRSA");
            put("Alg.Alias.Signature.OID.1.3.14.3.2.29", "SHA1withRSA");
        }
        put("Signature.MD5andSHA1withRSA", "sun.security.ssl.RSASignature");
        put("Cipher.ChaCha20", "org.openjsse.com.sun.crypto.provider.ChaCha20Cipher$ChaCha20Only");
        put("Cipher.ChaCha20 SupportedKeyFormats", "RAW");
        put("Cipher.ChaCha20-Poly1305", "org.openjsse.com.sun.crypto.provider.ChaCha20Cipher$ChaCha20Poly1305");
        put("Cipher.ChaCha20-Poly1305 SupportedKeyFormats", "RAW");
        put("Alg.Alias.Cipher.1.2.840.113549.1.9.16.3.18", "ChaCha20-Poly1305");
        put("Alg.Alias.Cipher.OID.1.2.840.113549.1.9.16.3.18", "ChaCha20-Poly1305");
        put("KeyGenerator.ChaCha20", "org.openjsse.com.sun.crypto.provider.KeyGeneratorCore$ChaCha20KeyGenerator");
        put("AlgorithmParameters.ChaCha20-Poly1305", "org.openjsse.com.sun.crypto.provider.ChaCha20Poly1305Parameters");
        put("KeyManagerFactory.SunX509", "org.openjsse.sun.security.ssl.KeyManagerFactoryImpl$SunX509");
        put("KeyManagerFactory.NewSunX509", "org.openjsse.sun.security.ssl.KeyManagerFactoryImpl$X509");
        put("Alg.Alias.KeyManagerFactory.PKIX", "NewSunX509");
        put("TrustManagerFactory.SunX509", "org.openjsse.sun.security.ssl.TrustManagerFactoryImpl$SimpleFactory");
        put("TrustManagerFactory.PKIX", "org.openjsse.sun.security.ssl.TrustManagerFactoryImpl$PKIXFactory");
        put("Alg.Alias.TrustManagerFactory.SunPKIX", Validator.TYPE_PKIX);
        put("Alg.Alias.TrustManagerFactory.X509", Validator.TYPE_PKIX);
        put("Alg.Alias.TrustManagerFactory.X.509", Validator.TYPE_PKIX);
        put("SSLContext.TLSv1", "org.openjsse.sun.security.ssl.SSLContextImpl$TLS10Context");
        put("SSLContext.TLSv1.1", "org.openjsse.sun.security.ssl.SSLContextImpl$TLS11Context");
        put("SSLContext.TLSv1.2", "org.openjsse.sun.security.ssl.SSLContextImpl$TLS12Context");
        put("SSLContext.TLSv1.3", "org.openjsse.sun.security.ssl.SSLContextImpl$TLS13Context");
        put("SSLContext.TLS", "org.openjsse.sun.security.ssl.SSLContextImpl$TLSContext");
        if (!isfips) {
            put("Alg.Alias.SSLContext.SSL", "TLS");
            put("Alg.Alias.SSLContext.SSLv3", "TLSv1");
        }
        put("SSLContext.Default", "org.openjsse.sun.security.ssl.SSLContextImpl$DefaultSSLContext");
        put("KeyStore.PKCS12", "sun.security.pkcs12.PKCS12KeyStore");
        put("KeyGenerator.SunTlsPrf", "org.openjsse.com.sun.crypto.provider.TlsPrfGenerator$V10");
        put("KeyGenerator.SunTls12Prf", "org.openjsse.com.sun.crypto.provider.TlsPrfGenerator$V12");
        put("KeyGenerator.SunTlsMasterSecret", "org.openjsse.com.sun.crypto.provider.TlsMasterSecretGenerator");
        put("Alg.Alias.KeyGenerator.SunTls12MasterSecret", "SunTlsMasterSecret");
        put("Alg.Alias.KeyGenerator.SunTlsExtendedMasterSecret", "SunTlsMasterSecret");
        put("KeyGenerator.SunTlsKeyMaterial", "org.openjsse.com.sun.crypto.provider.TlsKeyMaterialGenerator");
        put("Alg.Alias.KeyGenerator.SunTls12KeyMaterial", "SunTlsKeyMaterial");
        put("KeyGenerator.SunTlsRsaPremasterSecret", "org.openjsse.com.sun.crypto.provider.TlsRsaPremasterSecretGenerator");
        put("Alg.Alias.KeyGenerator.SunTls12RsaPremasterSecret", "SunTlsRsaPremasterSecret");
        if (PROVIDER_VER == 1.8d) {
            put("MessageDigest.SHA3-224", "org.openjsse.sun.security.provider.SHA3$SHA224");
            put("MessageDigest.SHA3-256", "org.openjsse.sun.security.provider.SHA3$SHA256");
            put("MessageDigest.SHA3-384", "org.openjsse.sun.security.provider.SHA3$SHA384");
            put("MessageDigest.SHA3-512", "org.openjsse.sun.security.provider.SHA3$SHA512");
        }
        put("Alg.Alias.MessageDigest.2.16.840.1.101.3.4.2.7", "SHA3-224");
        put("Alg.Alias.MessageDigest.OID.2.16.840.1.101.3.4.2.7", "SHA3-224");
        put("Alg.Alias.MessageDigest.2.16.840.1.101.3.4.2.8", "SHA3-256");
        put("Alg.Alias.MessageDigest.OID.2.16.840.1.101.3.4.2.8", "SHA3-256");
        put("Alg.Alias.MessageDigest.2.16.840.1.101.3.4.2.9", "SHA3-384");
        put("Alg.Alias.MessageDigest.OID.2.16.840.1.101.3.4.2.9", "SHA3-384");
        put("Alg.Alias.MessageDigest.2.16.840.1.101.3.4.2.10", "SHA3-512");
        put("Alg.Alias.MessageDigest.OID.2.16.840.1.101.3.4.2.10", "SHA3-512");
    }

    private void subclassCheck() {
        if (getClass() != org.openjsse.net.ssl.OpenJSSE.class) {
            throw new AssertionError("Illegal subclass: " + getClass());
        }
    }

    protected final void finalize() throws Throwable {
        super.finalize();
    }

    private static ObjectIdentifier oid(final int... values) {
        return (ObjectIdentifier) AccessController.doPrivileged(new PrivilegedAction<ObjectIdentifier>() { // from class: org.openjsse.sun.security.ssl.OpenJSSE.2
            /* JADX WARN: Can't rename method to resolve collision */
            @Override // java.security.PrivilegedAction
            public ObjectIdentifier run() {
                return ObjectIdentifier.newInternal(values);
            }
        });
    }
}