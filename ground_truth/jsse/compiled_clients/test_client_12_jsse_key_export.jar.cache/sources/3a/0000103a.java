package org.openjsse.sun.security.ssl;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Iterator;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.SSLHandshakeException;
import org.openjsse.sun.security.ssl.CipherSuite;
import org.openjsse.sun.security.ssl.SupportedGroupsExtension;
import org.openjsse.sun.security.ssl.X509Authentication;
import sun.security.action.GetPropertyAction;
import sun.security.util.KeyUtil;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/DHKeyExchange.class */
final class DHKeyExchange {
    static final SSLPossessionGenerator poGenerator = new DHEPossessionGenerator(false);
    static final SSLPossessionGenerator poExportableGenerator = new DHEPossessionGenerator(true);
    static final SSLKeyAgreementGenerator kaGenerator = new DHEKAGenerator();

    DHKeyExchange() {
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/DHKeyExchange$DHECredentials.class */
    static final class DHECredentials implements SSLCredentials {
        final DHPublicKey popPublicKey;
        final SupportedGroupsExtension.NamedGroup namedGroup;

        /* JADX INFO: Access modifiers changed from: package-private */
        public DHECredentials(DHPublicKey popPublicKey, SupportedGroupsExtension.NamedGroup namedGroup) {
            this.popPublicKey = popPublicKey;
            this.namedGroup = namedGroup;
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public static DHECredentials valueOf(SupportedGroupsExtension.NamedGroup ng, byte[] encodedPublic) throws IOException, GeneralSecurityException {
            DHParameterSpec params;
            if (ng.type != SupportedGroupsExtension.NamedGroupType.NAMED_GROUP_FFDHE) {
                throw new RuntimeException("Credentials decoding:  Not FFDHE named group");
            }
            if (encodedPublic == null || encodedPublic.length == 0 || (params = (DHParameterSpec) ng.getParameterSpec()) == null) {
                return null;
            }
            KeyFactory kf = JsseJce.getKeyFactory("DiffieHellman");
            DHPublicKeySpec spec = new DHPublicKeySpec(new BigInteger(1, encodedPublic), params.getP(), params.getG());
            DHPublicKey publicKey = (DHPublicKey) kf.generatePublic(spec);
            return new DHECredentials(publicKey, ng);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/DHKeyExchange$DHEPossession.class */
    public static final class DHEPossession implements SSLPossession {
        final PrivateKey privateKey;
        final DHPublicKey publicKey;
        final SupportedGroupsExtension.NamedGroup namedGroup;

        /* JADX INFO: Access modifiers changed from: package-private */
        public DHEPossession(SupportedGroupsExtension.NamedGroup namedGroup, SecureRandom random) {
            try {
                KeyPairGenerator kpg = JsseJce.getKeyPairGenerator("DiffieHellman");
                DHParameterSpec params = (DHParameterSpec) namedGroup.getParameterSpec();
                kpg.initialize(params, random);
                KeyPair kp = generateDHKeyPair(kpg);
                if (kp == null) {
                    throw new RuntimeException("Could not generate DH keypair");
                }
                this.privateKey = kp.getPrivate();
                this.publicKey = (DHPublicKey) kp.getPublic();
                this.namedGroup = namedGroup;
            } catch (GeneralSecurityException gse) {
                throw new RuntimeException("Could not generate DH keypair", gse);
            }
        }

        DHEPossession(int keyLength, SecureRandom random) {
            DHParameterSpec params = PredefinedDHParameterSpecs.definedParams.get(Integer.valueOf(keyLength));
            try {
                KeyPairGenerator kpg = JsseJce.getKeyPairGenerator("DiffieHellman");
                if (params != null) {
                    kpg.initialize(params, random);
                } else {
                    kpg.initialize(keyLength, random);
                }
                KeyPair kp = generateDHKeyPair(kpg);
                if (kp == null) {
                    throw new RuntimeException("Could not generate DH keypair of " + keyLength + " bits");
                }
                this.privateKey = kp.getPrivate();
                this.publicKey = (DHPublicKey) kp.getPublic();
                this.namedGroup = SupportedGroupsExtension.NamedGroup.valueOf(this.publicKey.getParams());
            } catch (GeneralSecurityException gse) {
                throw new RuntimeException("Could not generate DH keypair", gse);
            }
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public DHEPossession(DHECredentials credentials, SecureRandom random) {
            try {
                KeyPairGenerator kpg = JsseJce.getKeyPairGenerator("DiffieHellman");
                kpg.initialize(credentials.popPublicKey.getParams(), random);
                KeyPair kp = generateDHKeyPair(kpg);
                if (kp == null) {
                    throw new RuntimeException("Could not generate DH keypair");
                }
                this.privateKey = kp.getPrivate();
                this.publicKey = (DHPublicKey) kp.getPublic();
                this.namedGroup = credentials.namedGroup;
            } catch (GeneralSecurityException gse) {
                throw new RuntimeException("Could not generate DH keypair", gse);
            }
        }

        private KeyPair generateDHKeyPair(KeyPairGenerator kpg) throws GeneralSecurityException {
            boolean doExtraValiadtion = !KeyUtil.isOracleJCEProvider(kpg.getProvider().getName());
            boolean isRecovering = false;
            for (int i = 0; i <= 2; i++) {
                KeyPair kp = kpg.generateKeyPair();
                if (doExtraValiadtion) {
                    DHPublicKeySpec spec = getDHPublicKeySpec(kp.getPublic());
                    try {
                        KeyUtil.validate(spec);
                    } catch (InvalidKeyException ivke) {
                        if (isRecovering) {
                            throw ivke;
                        }
                        isRecovering = true;
                    }
                }
                return kp;
            }
            return null;
        }

        private static DHPublicKeySpec getDHPublicKeySpec(PublicKey key) {
            if (key instanceof DHPublicKey) {
                DHPublicKey dhKey = (DHPublicKey) key;
                DHParameterSpec params = dhKey.getParams();
                return new DHPublicKeySpec(dhKey.getY(), params.getP(), params.getG());
            }
            try {
                KeyFactory factory = JsseJce.getKeyFactory("DiffieHellman");
                return (DHPublicKeySpec) factory.getKeySpec(key, DHPublicKeySpec.class);
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                throw new RuntimeException("Unable to get DHPublicKeySpec", e);
            }
        }

        @Override // org.openjsse.sun.security.ssl.SSLPossession
        public byte[] encode() {
            byte[] encoded = Utilities.toByteArray(this.publicKey.getY());
            int pSize = (KeyUtil.getKeySize(this.publicKey) + 7) >>> 3;
            if (pSize > 0 && encoded.length < pSize) {
                byte[] buffer = new byte[pSize];
                System.arraycopy(encoded, 0, buffer, pSize - encoded.length, encoded.length);
                encoded = buffer;
            }
            return encoded;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/DHKeyExchange$DHEPossessionGenerator.class */
    private static final class DHEPossessionGenerator implements SSLPossessionGenerator {
        private static final boolean useSmartEphemeralDHKeys;
        private static final boolean useLegacyEphemeralDHKeys;
        private static final int customizedDHKeySize;
        private final boolean exportable;

        static {
            String property = GetPropertyAction.privilegedGetProperty("jdk.tls.ephemeralDHKeySize");
            if (property == null || property.length() == 0) {
                useLegacyEphemeralDHKeys = false;
                useSmartEphemeralDHKeys = false;
                customizedDHKeySize = -1;
            } else if ("matched".equals(property)) {
                useLegacyEphemeralDHKeys = false;
                useSmartEphemeralDHKeys = true;
                customizedDHKeySize = -1;
            } else if ("legacy".equals(property)) {
                useLegacyEphemeralDHKeys = true;
                useSmartEphemeralDHKeys = false;
                customizedDHKeySize = -1;
            } else {
                useLegacyEphemeralDHKeys = false;
                useSmartEphemeralDHKeys = false;
                try {
                    customizedDHKeySize = Integer.parseUnsignedInt(property);
                    if (customizedDHKeySize < 1024 || customizedDHKeySize > 8192 || (customizedDHKeySize & 63) != 0) {
                        throw new IllegalArgumentException("Unsupported customized DH key size: " + customizedDHKeySize + ". The key size must be multiple of 64, and range from 1024 to 8192 (inclusive)");
                    }
                } catch (NumberFormatException e) {
                    throw new IllegalArgumentException("Invalid system property jdk.tls.ephemeralDHKeySize");
                }
            }
        }

        private DHEPossessionGenerator(boolean exportable) {
            this.exportable = exportable;
        }

        @Override // org.openjsse.sun.security.ssl.SSLPossessionGenerator
        public SSLPossession createPossession(HandshakeContext context) {
            SupportedGroupsExtension.NamedGroup preferableNamedGroup;
            if (!useLegacyEphemeralDHKeys && context.clientRequestedNamedGroups != null && !context.clientRequestedNamedGroups.isEmpty() && (preferableNamedGroup = SupportedGroupsExtension.SupportedGroups.getPreferredGroup(context.negotiatedProtocol, context.algorithmConstraints, SupportedGroupsExtension.NamedGroupType.NAMED_GROUP_FFDHE, context.clientRequestedNamedGroups)) != null) {
                return new DHEPossession(preferableNamedGroup, context.sslContext.getSecureRandom());
            }
            int keySize = this.exportable ? 512 : 1024;
            if (!this.exportable) {
                if (useLegacyEphemeralDHKeys) {
                    keySize = 768;
                } else if (useSmartEphemeralDHKeys) {
                    PrivateKey key = null;
                    ServerHandshakeContext shc = (ServerHandshakeContext) context;
                    if (shc.interimAuthn instanceof X509Authentication.X509Possession) {
                        key = ((X509Authentication.X509Possession) shc.interimAuthn).popPrivateKey;
                    }
                    if (key != null) {
                        int ks = KeyUtil.getKeySize(key);
                        keySize = ks <= 1024 ? 1024 : 2048;
                    }
                } else if (customizedDHKeySize > 0) {
                    keySize = customizedDHKeySize;
                }
            }
            return new DHEPossession(keySize, context.sslContext.getSecureRandom());
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/DHKeyExchange$DHEKAGenerator.class */
    private static final class DHEKAGenerator implements SSLKeyAgreementGenerator {
        private static DHEKAGenerator instance = new DHEKAGenerator();

        private DHEKAGenerator() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLKeyAgreementGenerator
        public SSLKeyDerivation createKeyDerivation(HandshakeContext context) throws IOException {
            DHEPossession dhePossession = null;
            DHECredentials dheCredentials = null;
            Iterator<SSLPossession> it = context.handshakePossessions.iterator();
            while (true) {
                if (!it.hasNext()) {
                    break;
                }
                SSLPossession poss = it.next();
                if (poss instanceof DHEPossession) {
                    DHEPossession dhep = (DHEPossession) poss;
                    Iterator<SSLCredentials> it2 = context.handshakeCredentials.iterator();
                    while (true) {
                        if (!it2.hasNext()) {
                            break;
                        }
                        SSLCredentials cred = it2.next();
                        if (cred instanceof DHECredentials) {
                            DHECredentials dhec = (DHECredentials) cred;
                            if (dhep.namedGroup != null && dhec.namedGroup != null) {
                                if (dhep.namedGroup.equals(dhec.namedGroup)) {
                                    dheCredentials = (DHECredentials) cred;
                                    break;
                                }
                            } else {
                                DHParameterSpec pps = dhep.publicKey.getParams();
                                DHParameterSpec cps = dhec.popPublicKey.getParams();
                                if (pps.getP().equals(cps.getP()) && pps.getG().equals(cps.getG())) {
                                    dheCredentials = (DHECredentials) cred;
                                    break;
                                }
                            }
                        }
                    }
                    if (dheCredentials != null) {
                        dhePossession = (DHEPossession) poss;
                        break;
                    }
                }
            }
            if (dhePossession == null || dheCredentials == null) {
                throw context.conContext.fatal(Alert.HANDSHAKE_FAILURE, "No sufficient DHE key agreement parameters negotiated");
            }
            return new DHEKAKeyDerivation(context, dhePossession.privateKey, dheCredentials.popPublicKey);
        }

        /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/DHKeyExchange$DHEKAGenerator$DHEKAKeyDerivation.class */
        private static final class DHEKAKeyDerivation implements SSLKeyDerivation {
            private final HandshakeContext context;
            private final PrivateKey localPrivateKey;
            private final PublicKey peerPublicKey;

            DHEKAKeyDerivation(HandshakeContext context, PrivateKey localPrivateKey, PublicKey peerPublicKey) {
                this.context = context;
                this.localPrivateKey = localPrivateKey;
                this.peerPublicKey = peerPublicKey;
            }

            @Override // org.openjsse.sun.security.ssl.SSLKeyDerivation
            public SecretKey deriveKey(String algorithm, AlgorithmParameterSpec params) throws IOException {
                if (!this.context.negotiatedProtocol.useTLS13PlusSpec()) {
                    return t12DeriveKey(algorithm, params);
                }
                return t13DeriveKey(algorithm, params);
            }

            private SecretKey t12DeriveKey(String algorithm, AlgorithmParameterSpec params) throws IOException {
                try {
                    KeyAgreement ka = JsseJce.getKeyAgreement("DiffieHellman");
                    ka.init(this.localPrivateKey);
                    ka.doPhase(this.peerPublicKey, true);
                    SecretKey preMasterSecret = ka.generateSecret("TlsPremasterSecret");
                    SSLMasterKeyDerivation mskd = SSLMasterKeyDerivation.valueOf(this.context.negotiatedProtocol);
                    if (mskd == null) {
                        throw new SSLHandshakeException("No expected master key derivation for protocol: " + this.context.negotiatedProtocol.name);
                    }
                    SSLKeyDerivation kd = mskd.createKeyDerivation(this.context, preMasterSecret);
                    return kd.deriveKey("MasterSecret", params);
                } catch (GeneralSecurityException gse) {
                    throw ((SSLHandshakeException) new SSLHandshakeException("Could not generate secret").initCause(gse));
                }
            }

            private SecretKey t13DeriveKey(String algorithm, AlgorithmParameterSpec params) throws IOException {
                try {
                    KeyAgreement ka = JsseJce.getKeyAgreement("DiffieHellman");
                    ka.init(this.localPrivateKey);
                    ka.doPhase(this.peerPublicKey, true);
                    SecretKey sharedSecret = ka.generateSecret("TlsPremasterSecret");
                    CipherSuite.HashAlg hashAlg = this.context.negotiatedCipherSuite.hashAlg;
                    SSLKeyDerivation kd = this.context.handshakeKeyDerivation;
                    HKDF hkdf = new HKDF(hashAlg.name);
                    if (kd == null) {
                        byte[] zeros = new byte[hashAlg.hashLength];
                        SecretKeySpec ikm = new SecretKeySpec(zeros, "TlsPreSharedSecret");
                        SecretKey earlySecret = hkdf.extract(zeros, ikm, "TlsEarlySecret");
                        kd = new SSLSecretDerivation(this.context, earlySecret);
                    }
                    SecretKey saltSecret = kd.deriveKey("TlsSaltSecret", null);
                    return hkdf.extract(saltSecret, sharedSecret, algorithm);
                } catch (GeneralSecurityException gse) {
                    throw ((SSLHandshakeException) new SSLHandshakeException("Could not generate secret").initCause(gse));
                }
            }
        }
    }
}