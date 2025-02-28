package org.openjsse.sun.security.ssl;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Iterator;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.net.ssl.SSLHandshakeException;
import sun.security.internal.spec.TlsRsaPremasterSecretParameterSpec;
import sun.security.util.KeyUtil;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/RSAKeyExchange.class */
final class RSAKeyExchange {
    static final SSLPossessionGenerator poGenerator = new EphemeralRSAPossessionGenerator();
    static final SSLKeyAgreementGenerator kaGenerator = new RSAKAGenerator();

    RSAKeyExchange() {
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/RSAKeyExchange$EphemeralRSAPossession.class */
    public static final class EphemeralRSAPossession implements SSLPossession {
        final RSAPublicKey popPublicKey;
        final PrivateKey popPrivateKey;

        EphemeralRSAPossession(PrivateKey popPrivateKey, RSAPublicKey popPublicKey) {
            this.popPublicKey = popPublicKey;
            this.popPrivateKey = popPrivateKey;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/RSAKeyExchange$EphemeralRSACredentials.class */
    static final class EphemeralRSACredentials implements SSLCredentials {
        final RSAPublicKey popPublicKey;

        /* JADX INFO: Access modifiers changed from: package-private */
        public EphemeralRSACredentials(RSAPublicKey popPublicKey) {
            this.popPublicKey = popPublicKey;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/RSAKeyExchange$EphemeralRSAPossessionGenerator.class */
    private static final class EphemeralRSAPossessionGenerator implements SSLPossessionGenerator {
        private EphemeralRSAPossessionGenerator() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLPossessionGenerator
        public SSLPossession createPossession(HandshakeContext context) {
            try {
                EphemeralKeyManager ekm = context.sslContext.getEphemeralKeyManager();
                KeyPair kp = ekm.getRSAKeyPair(true, context.sslContext.getSecureRandom());
                if (kp != null) {
                    return new EphemeralRSAPossession(kp.getPrivate(), (RSAPublicKey) kp.getPublic());
                }
                return null;
            } catch (RuntimeException e) {
                return null;
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/RSAKeyExchange$RSAPremasterSecret.class */
    static final class RSAPremasterSecret implements SSLPossession, SSLCredentials {
        final SecretKey premasterSecret;

        RSAPremasterSecret(SecretKey premasterSecret) {
            this.premasterSecret = premasterSecret;
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public byte[] getEncoded(PublicKey publicKey, SecureRandom secureRandom) throws GeneralSecurityException {
            Cipher cipher = JsseJce.getCipher("RSA/ECB/PKCS1Padding");
            cipher.init(3, publicKey, secureRandom);
            return cipher.wrap(this.premasterSecret);
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public static RSAPremasterSecret createPremasterSecret(ClientHandshakeContext chc) throws GeneralSecurityException {
            String algorithm = chc.negotiatedProtocol.useTLS12PlusSpec() ? "SunTls12RsaPremasterSecret" : "SunTlsRsaPremasterSecret";
            KeyGenerator kg = JsseJce.getKeyGenerator(algorithm);
            TlsRsaPremasterSecretParameterSpec spec = new TlsRsaPremasterSecretParameterSpec(chc.clientHelloVersion, chc.negotiatedProtocol.f978id);
            kg.init((AlgorithmParameterSpec) spec, chc.sslContext.getSecureRandom());
            return new RSAPremasterSecret(kg.generateKey());
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public static RSAPremasterSecret decode(ServerHandshakeContext shc, PrivateKey privateKey, byte[] encrypted) throws GeneralSecurityException {
            boolean needFailover;
            SecretKey preMaster;
            byte[] encoded = null;
            Cipher cipher = JsseJce.getCipher("RSA/ECB/PKCS1Padding");
            try {
                cipher.init(4, (Key) privateKey, (AlgorithmParameterSpec) new TlsRsaPremasterSecretParameterSpec(shc.clientHelloVersion, shc.negotiatedProtocol.f978id), shc.sslContext.getSecureRandom());
                needFailover = !KeyUtil.isOracleJCEProvider(cipher.getProvider().getName());
            } catch (UnsupportedOperationException | InvalidKeyException iue) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.warning("The Cipher provider " + safeProviderName(cipher) + " caused exception: " + iue.getMessage(), new Object[0]);
                }
                needFailover = true;
            }
            if (needFailover) {
                Cipher cipher2 = JsseJce.getCipher("RSA/ECB/PKCS1Padding");
                cipher2.init(2, privateKey);
                boolean failed = false;
                try {
                    encoded = cipher2.doFinal(encrypted);
                } catch (BadPaddingException e) {
                    failed = true;
                }
                preMaster = generatePremasterSecret(shc.clientHelloVersion, shc.negotiatedProtocol.f978id, KeyUtil.checkTlsPreMasterSecretKey(shc.clientHelloVersion, shc.negotiatedProtocol.f978id, shc.sslContext.getSecureRandom(), encoded, failed), shc.sslContext.getSecureRandom());
            } else {
                preMaster = (SecretKey) cipher.unwrap(encrypted, "TlsRsaPremasterSecret", 3);
            }
            return new RSAPremasterSecret(preMaster);
        }

        private static String safeProviderName(Cipher cipher) {
            try {
                return cipher.getProvider().toString();
            } catch (Exception e) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("Retrieving The Cipher provider name caused exception ", e);
                }
                try {
                    return cipher.toString() + " (provider name not available)";
                } catch (Exception e2) {
                    if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                        SSLLogger.fine("Retrieving The Cipher name caused exception ", e2);
                        return "(cipher/provider names not available)";
                    }
                    return "(cipher/provider names not available)";
                }
            }
        }

        private static SecretKey generatePremasterSecret(int clientVersion, int serverVersion, byte[] encodedSecret, SecureRandom generator) throws GeneralSecurityException {
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("Generating a premaster secret", new Object[0]);
            }
            try {
                String s = clientVersion >= ProtocolVersion.TLS12.f978id ? "SunTls12RsaPremasterSecret" : "SunTlsRsaPremasterSecret";
                KeyGenerator kg = JsseJce.getKeyGenerator(s);
                kg.init((AlgorithmParameterSpec) new TlsRsaPremasterSecretParameterSpec(clientVersion, serverVersion, encodedSecret), generator);
                return kg.generateKey();
            } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException iae) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("RSA premaster secret generation error:", new Object[0]);
                    iae.printStackTrace(System.out);
                }
                throw new GeneralSecurityException("Could not generate premaster secret", iae);
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/RSAKeyExchange$RSAKAGenerator.class */
    private static final class RSAKAGenerator implements SSLKeyAgreementGenerator {
        private RSAKAGenerator() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLKeyAgreementGenerator
        public SSLKeyDerivation createKeyDerivation(HandshakeContext context) throws IOException {
            RSAPremasterSecret premaster = null;
            if (context instanceof ClientHandshakeContext) {
                Iterator<SSLPossession> it = context.handshakePossessions.iterator();
                while (true) {
                    if (!it.hasNext()) {
                        break;
                    }
                    SSLPossession possession = it.next();
                    if (possession instanceof RSAPremasterSecret) {
                        premaster = (RSAPremasterSecret) possession;
                        break;
                    }
                }
            } else {
                Iterator<SSLCredentials> it2 = context.handshakeCredentials.iterator();
                while (true) {
                    if (!it2.hasNext()) {
                        break;
                    }
                    SSLCredentials credential = it2.next();
                    if (credential instanceof RSAPremasterSecret) {
                        premaster = (RSAPremasterSecret) credential;
                        break;
                    }
                }
            }
            if (premaster == null) {
                throw context.conContext.fatal(Alert.HANDSHAKE_FAILURE, "No sufficient RSA key agreement parameters negotiated");
            }
            return new RSAKAKeyDerivation(context, premaster.premasterSecret);
        }

        /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/RSAKeyExchange$RSAKAGenerator$RSAKAKeyDerivation.class */
        private static final class RSAKAKeyDerivation implements SSLKeyDerivation {
            private final HandshakeContext context;
            private final SecretKey preMasterSecret;

            RSAKAKeyDerivation(HandshakeContext context, SecretKey preMasterSecret) {
                this.context = context;
                this.preMasterSecret = preMasterSecret;
            }

            @Override // org.openjsse.sun.security.ssl.SSLKeyDerivation
            public SecretKey deriveKey(String algorithm, AlgorithmParameterSpec params) throws IOException {
                SSLMasterKeyDerivation mskd = SSLMasterKeyDerivation.valueOf(this.context.negotiatedProtocol);
                if (mskd == null) {
                    throw new SSLHandshakeException("No expected master key derivation for protocol: " + this.context.negotiatedProtocol.name);
                }
                SSLKeyDerivation kd = mskd.createKeyDerivation(this.context, this.preMasterSecret);
                return kd.deriveKey("MasterSecret", params);
            }
        }
    }
}