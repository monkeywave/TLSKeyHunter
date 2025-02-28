package org.openjsse.sun.security.ssl;

import java.io.IOException;
import java.math.BigInteger;
import java.security.AccessController;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyManagementException;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.security.spec.RSAPublicKeySpec;
import java.util.Map;
import javassist.bytecode.SignatureAttribute;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import sun.security.jca.ProviderList;
import sun.security.jca.Providers;
import sun.security.util.ECUtil;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/JsseJce.class */
final class JsseJce {
    public static double PROVIDER_VER = 1.8d;
    static final boolean ALLOW_ECC = Utilities.getBooleanProperty("com.sun.net.ssl.enableECC", true);
    private static final ProviderList fipsProviderList;
    static final String CIPHER_RSA_PKCS1 = "RSA/ECB/PKCS1Padding";
    static final String CIPHER_RC4 = "RC4";
    static final String CIPHER_DES = "DES/CBC/NoPadding";
    static final String CIPHER_3DES = "DESede/CBC/NoPadding";
    static final String CIPHER_AES = "AES/CBC/NoPadding";
    static final String CIPHER_AES_GCM = "AES/GCM/NoPadding";
    static final String CIPHER_CHACHA20_POLY1305 = "ChaCha20-Poly1305";
    static final String SIGNATURE_DSA = "DSA";
    static final String SIGNATURE_ECDSA = "SHA1withECDSA";
    static final String SIGNATURE_RAWDSA = "RawDSA";
    static final String SIGNATURE_RAWECDSA = "NONEwithECDSA";
    static final String SIGNATURE_RAWRSA = "NONEwithRSA";
    static final String SIGNATURE_SSLRSA = "MD5andSHA1withRSA";

    static {
        if (!OpenJSSE.isFIPS()) {
            fipsProviderList = null;
            return;
        }
        Provider sun = Security.getProvider("SUN");
        if (sun == null) {
            throw new RuntimeException("FIPS mode: SUN provider must be installed");
        }
        Provider sunCerts = new SunCertificates(sun);
        fipsProviderList = ProviderList.newList(new Provider[]{OpenJSSE.cryptoProvider, sunCerts});
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/JsseJce$SunCertificates.class */
    private static final class SunCertificates extends Provider {
        private static final long serialVersionUID = -3284138292032213752L;

        SunCertificates(final Provider p) {
            super("SunCertificates", JsseJce.PROVIDER_VER, "OpenJSSE internal");
            AccessController.doPrivileged(new PrivilegedAction<Object>() { // from class: org.openjsse.sun.security.ssl.JsseJce.SunCertificates.1
                @Override // java.security.PrivilegedAction
                public Object run() {
                    for (Map.Entry<Object, Object> entry : p.entrySet()) {
                        String key = (String) entry.getKey();
                        if (key.startsWith("CertPathValidator.") || key.startsWith("CertPathBuilder.") || key.startsWith("CertStore.") || key.startsWith("CertificateFactory.")) {
                            SunCertificates.this.put(key, entry.getValue());
                        }
                    }
                    return null;
                }
            });
        }
    }

    private JsseJce() {
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static boolean isEcAvailable() {
        return EcAvailability.isAvailable;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static Cipher getCipher(String transformation) throws NoSuchAlgorithmException {
        try {
            if (OpenJSSE.cryptoProvider == null) {
                return Cipher.getInstance(transformation);
            }
            return Cipher.getInstance(transformation, OpenJSSE.cryptoProvider);
        } catch (NoSuchPaddingException e) {
            throw new NoSuchAlgorithmException(e);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static Signature getSignature(String algorithm) throws NoSuchAlgorithmException {
        if (OpenJSSE.cryptoProvider == null) {
            return Signature.getInstance(algorithm);
        }
        if (algorithm == SIGNATURE_SSLRSA && OpenJSSE.cryptoProvider.getService(SignatureAttribute.tag, algorithm) == null) {
            try {
                return Signature.getInstance(algorithm, "OpenJSSE");
            } catch (NoSuchProviderException e) {
                throw new NoSuchAlgorithmException(e);
            }
        }
        return Signature.getInstance(algorithm, OpenJSSE.cryptoProvider);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static KeyGenerator getKeyGenerator(String algorithm) throws NoSuchAlgorithmException {
        if (OpenJSSE.cryptoProvider == null) {
            return KeyGenerator.getInstance(algorithm);
        }
        return KeyGenerator.getInstance(algorithm, OpenJSSE.cryptoProvider);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static KeyPairGenerator getKeyPairGenerator(String algorithm) throws NoSuchAlgorithmException {
        if (OpenJSSE.cryptoProvider == null) {
            return KeyPairGenerator.getInstance(algorithm);
        }
        return KeyPairGenerator.getInstance(algorithm, OpenJSSE.cryptoProvider);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static KeyAgreement getKeyAgreement(String algorithm) throws NoSuchAlgorithmException {
        if (OpenJSSE.cryptoProvider == null) {
            return KeyAgreement.getInstance(algorithm);
        }
        return KeyAgreement.getInstance(algorithm, OpenJSSE.cryptoProvider);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static Mac getMac(String algorithm) throws NoSuchAlgorithmException {
        if (OpenJSSE.cryptoProvider == null) {
            return Mac.getInstance(algorithm);
        }
        return Mac.getInstance(algorithm, OpenJSSE.cryptoProvider);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static KeyFactory getKeyFactory(String algorithm) throws NoSuchAlgorithmException {
        if (OpenJSSE.cryptoProvider == null) {
            return KeyFactory.getInstance(algorithm);
        }
        return KeyFactory.getInstance(algorithm, OpenJSSE.cryptoProvider);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static AlgorithmParameters getAlgorithmParameters(String algorithm) throws NoSuchAlgorithmException {
        if (OpenJSSE.cryptoProvider == null) {
            return AlgorithmParameters.getInstance(algorithm);
        }
        return AlgorithmParameters.getInstance(algorithm, OpenJSSE.cryptoProvider);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static SecureRandom getSecureRandom() throws KeyManagementException {
        if (OpenJSSE.cryptoProvider == null) {
            return new SecureRandom();
        }
        try {
            return SecureRandom.getInstance("PKCS11", OpenJSSE.cryptoProvider);
        } catch (NoSuchAlgorithmException e) {
            for (Provider.Service s : OpenJSSE.cryptoProvider.getServices()) {
                if (s.getType().equals("SecureRandom")) {
                    try {
                        return SecureRandom.getInstance(s.getAlgorithm(), OpenJSSE.cryptoProvider);
                    } catch (NoSuchAlgorithmException e2) {
                    }
                }
            }
            throw new KeyManagementException("FIPS mode: no SecureRandom  implementation found in provider " + OpenJSSE.cryptoProvider.getName());
        }
    }

    static MessageDigest getMD5() {
        return getMessageDigest("MD5");
    }

    static MessageDigest getSHA() {
        return getMessageDigest("SHA");
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static MessageDigest getMessageDigest(String algorithm) {
        try {
            if (OpenJSSE.cryptoProvider == null) {
                return MessageDigest.getInstance(algorithm);
            }
            return MessageDigest.getInstance(algorithm, OpenJSSE.cryptoProvider);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Algorithm " + algorithm + " not available", e);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static int getRSAKeyLength(PublicKey key) {
        BigInteger modulus;
        if (key instanceof RSAPublicKey) {
            modulus = ((RSAPublicKey) key).getModulus();
        } else {
            RSAPublicKeySpec spec = getRSAPublicKeySpec(key);
            modulus = spec.getModulus();
        }
        return modulus.bitLength();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static RSAPublicKeySpec getRSAPublicKeySpec(PublicKey key) {
        if (key instanceof RSAPublicKey) {
            RSAPublicKey rsaKey = (RSAPublicKey) key;
            return new RSAPublicKeySpec(rsaKey.getModulus(), rsaKey.getPublicExponent());
        }
        try {
            KeyFactory factory = getKeyFactory("RSA");
            return (RSAPublicKeySpec) factory.getKeySpec(key, RSAPublicKeySpec.class);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static ECParameterSpec getECParameterSpec(String namedCurveOid) {
        return ECUtil.getECParameterSpec(OpenJSSE.cryptoProvider, namedCurveOid);
    }

    static String getNamedCurveOid(ECParameterSpec params) {
        return ECUtil.getCurveName(OpenJSSE.cryptoProvider, params);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static ECPoint decodePoint(byte[] encoded, EllipticCurve curve) throws IOException {
        return ECUtil.decodePoint(encoded, curve);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static byte[] encodePoint(ECPoint point, EllipticCurve curve) {
        return ECUtil.encodePoint(point, curve);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static Object beginFipsProvider() {
        if (fipsProviderList == null) {
            return null;
        }
        return Providers.beginThreadProviderList(fipsProviderList);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void endFipsProvider(Object o) {
        if (fipsProviderList != null) {
            Providers.endThreadProviderList((ProviderList) o);
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/JsseJce$EcAvailability.class */
    private static class EcAvailability {
        private static final boolean isAvailable;

        private EcAvailability() {
        }

        static {
            boolean mediator = true;
            try {
                JsseJce.getSignature(JsseJce.SIGNATURE_ECDSA);
                JsseJce.getSignature(JsseJce.SIGNATURE_RAWECDSA);
                JsseJce.getKeyAgreement("ECDH");
                JsseJce.getKeyFactory("EC");
                JsseJce.getKeyPairGenerator("EC");
                JsseJce.getAlgorithmParameters("EC");
            } catch (Exception e) {
                mediator = false;
            }
            isAvailable = mediator;
        }
    }
}