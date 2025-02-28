package org.openjsse.sun.security.ssl;

import java.io.IOException;
import java.security.AlgorithmConstraints;
import java.security.CryptoPrimitive;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.util.EnumSet;
import java.util.Iterator;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.SSLHandshakeException;
import org.openjsse.sun.security.ssl.CipherSuite;
import org.openjsse.sun.security.ssl.SupportedGroupsExtension;
import org.openjsse.sun.security.ssl.X509Authentication;
import sun.security.util.ECUtil;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/ECDHKeyExchange.class */
final class ECDHKeyExchange {
    static final SSLPossessionGenerator poGenerator = new ECDHEPossessionGenerator();
    static final SSLKeyAgreementGenerator ecdheKAGenerator = new ECDHEKAGenerator();
    static final SSLKeyAgreementGenerator ecdhKAGenerator = new ECDHKAGenerator();

    ECDHKeyExchange() {
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/ECDHKeyExchange$ECDHECredentials.class */
    public static final class ECDHECredentials implements SSLCredentials {
        final ECPublicKey popPublicKey;
        final SupportedGroupsExtension.NamedGroup namedGroup;

        /* JADX INFO: Access modifiers changed from: package-private */
        public ECDHECredentials(ECPublicKey popPublicKey, SupportedGroupsExtension.NamedGroup namedGroup) {
            this.popPublicKey = popPublicKey;
            this.namedGroup = namedGroup;
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public static ECDHECredentials valueOf(SupportedGroupsExtension.NamedGroup namedGroup, byte[] encodedPoint) throws IOException, GeneralSecurityException {
            ECParameterSpec parameters;
            if (namedGroup.type != SupportedGroupsExtension.NamedGroupType.NAMED_GROUP_ECDHE) {
                throw new RuntimeException("Credentials decoding:  Not ECDHE named group");
            }
            if (encodedPoint == null || encodedPoint.length == 0 || (parameters = JsseJce.getECParameterSpec(namedGroup.oid)) == null) {
                return null;
            }
            ECPoint point = JsseJce.decodePoint(encodedPoint, parameters.getCurve());
            KeyFactory factory = JsseJce.getKeyFactory("EC");
            ECPublicKey publicKey = (ECPublicKey) factory.generatePublic(new ECPublicKeySpec(point, parameters));
            return new ECDHECredentials(publicKey, namedGroup);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/ECDHKeyExchange$ECDHEPossession.class */
    public static final class ECDHEPossession implements SSLPossession {
        final PrivateKey privateKey;
        final ECPublicKey publicKey;
        final SupportedGroupsExtension.NamedGroup namedGroup;

        /* JADX INFO: Access modifiers changed from: package-private */
        public ECDHEPossession(SupportedGroupsExtension.NamedGroup namedGroup, SecureRandom random) {
            try {
                KeyPairGenerator kpg = JsseJce.getKeyPairGenerator("EC");
                ECGenParameterSpec params = (ECGenParameterSpec) namedGroup.getParameterSpec();
                kpg.initialize(params, random);
                KeyPair kp = kpg.generateKeyPair();
                this.privateKey = kp.getPrivate();
                this.publicKey = (ECPublicKey) kp.getPublic();
                this.namedGroup = namedGroup;
            } catch (GeneralSecurityException e) {
                throw new RuntimeException("Could not generate ECDH keypair", e);
            }
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public ECDHEPossession(ECDHECredentials credentials, SecureRandom random) {
            ECParameterSpec params = credentials.popPublicKey.getParams();
            try {
                KeyPairGenerator kpg = JsseJce.getKeyPairGenerator("EC");
                kpg.initialize(params, random);
                KeyPair kp = kpg.generateKeyPair();
                this.privateKey = kp.getPrivate();
                this.publicKey = (ECPublicKey) kp.getPublic();
                this.namedGroup = credentials.namedGroup;
            } catch (GeneralSecurityException e) {
                throw new RuntimeException("Could not generate ECDH keypair", e);
            }
        }

        @Override // org.openjsse.sun.security.ssl.SSLPossession
        public byte[] encode() {
            return ECUtil.encodePoint(this.publicKey.getW(), this.publicKey.getParams().getCurve());
        }

        SecretKey getAgreedSecret(PublicKey peerPublicKey) throws SSLHandshakeException {
            try {
                KeyAgreement ka = JsseJce.getKeyAgreement("ECDH");
                ka.init(this.privateKey);
                ka.doPhase(peerPublicKey, true);
                return ka.generateSecret("TlsPremasterSecret");
            } catch (GeneralSecurityException e) {
                throw ((SSLHandshakeException) new SSLHandshakeException("Could not generate secret").initCause(e));
            }
        }

        SecretKey getAgreedSecret(byte[] encodedPoint) throws SSLHandshakeException {
            try {
                ECParameterSpec params = this.publicKey.getParams();
                ECPoint point = JsseJce.decodePoint(encodedPoint, params.getCurve());
                KeyFactory kf = JsseJce.getKeyFactory("EC");
                ECPublicKeySpec spec = new ECPublicKeySpec(point, params);
                PublicKey peerPublicKey = kf.generatePublic(spec);
                return getAgreedSecret(peerPublicKey);
            } catch (IOException | GeneralSecurityException e) {
                throw ((SSLHandshakeException) new SSLHandshakeException("Could not generate secret").initCause(e));
            }
        }

        void checkConstraints(AlgorithmConstraints constraints, byte[] encodedPoint) throws SSLHandshakeException {
            try {
                ECParameterSpec params = this.publicKey.getParams();
                ECPoint point = JsseJce.decodePoint(encodedPoint, params.getCurve());
                ECPublicKeySpec spec = new ECPublicKeySpec(point, params);
                KeyFactory kf = JsseJce.getKeyFactory("EC");
                ECPublicKey pubKey = (ECPublicKey) kf.generatePublic(spec);
                if (!constraints.permits(EnumSet.of(CryptoPrimitive.KEY_AGREEMENT), pubKey)) {
                    throw new SSLHandshakeException("ECPublicKey does not comply to algorithm constraints");
                }
            } catch (IOException | GeneralSecurityException e) {
                throw ((SSLHandshakeException) new SSLHandshakeException("Could not generate ECPublicKey").initCause(e));
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/ECDHKeyExchange$ECDHEPossessionGenerator.class */
    private static final class ECDHEPossessionGenerator implements SSLPossessionGenerator {
        private ECDHEPossessionGenerator() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLPossessionGenerator
        public SSLPossession createPossession(HandshakeContext context) {
            SupportedGroupsExtension.NamedGroup preferableNamedGroup;
            if (context.clientRequestedNamedGroups != null && !context.clientRequestedNamedGroups.isEmpty()) {
                preferableNamedGroup = SupportedGroupsExtension.SupportedGroups.getPreferredGroup(context.negotiatedProtocol, context.algorithmConstraints, SupportedGroupsExtension.NamedGroupType.NAMED_GROUP_ECDHE, context.clientRequestedNamedGroups);
            } else {
                preferableNamedGroup = SupportedGroupsExtension.SupportedGroups.getPreferredGroup(context.negotiatedProtocol, context.algorithmConstraints, SupportedGroupsExtension.NamedGroupType.NAMED_GROUP_ECDHE);
            }
            if (preferableNamedGroup != null) {
                return new ECDHEPossession(preferableNamedGroup, context.sslContext.getSecureRandom());
            }
            return null;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/ECDHKeyExchange$ECDHKAGenerator.class */
    private static final class ECDHKAGenerator implements SSLKeyAgreementGenerator {
        private ECDHKAGenerator() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLKeyAgreementGenerator
        public SSLKeyDerivation createKeyDerivation(HandshakeContext context) throws IOException {
            if (context instanceof ServerHandshakeContext) {
                return createServerKeyDerivation((ServerHandshakeContext) context);
            }
            return createClientKeyDerivation((ClientHandshakeContext) context);
        }

        private SSLKeyDerivation createServerKeyDerivation(ServerHandshakeContext shc) throws IOException {
            ECParameterSpec params;
            X509Authentication.X509Possession x509Possession = null;
            ECDHECredentials ecdheCredentials = null;
            Iterator<SSLPossession> it = shc.handshakePossessions.iterator();
            while (true) {
                if (!it.hasNext()) {
                    break;
                }
                SSLPossession poss = it.next();
                if ((poss instanceof X509Authentication.X509Possession) && (params = ((X509Authentication.X509Possession) poss).getECParameterSpec()) != null) {
                    SupportedGroupsExtension.NamedGroup ng = SupportedGroupsExtension.NamedGroup.valueOf(params);
                    if (ng == null) {
                        throw shc.conContext.fatal(Alert.ILLEGAL_PARAMETER, "Unsupported EC server cert for ECDH key exchange");
                    }
                    Iterator<SSLCredentials> it2 = shc.handshakeCredentials.iterator();
                    while (true) {
                        if (!it2.hasNext()) {
                            break;
                        }
                        SSLCredentials cred = it2.next();
                        if ((cred instanceof ECDHECredentials) && ng.equals(((ECDHECredentials) cred).namedGroup)) {
                            ecdheCredentials = (ECDHECredentials) cred;
                            break;
                        }
                    }
                    if (ecdheCredentials != null) {
                        x509Possession = (X509Authentication.X509Possession) poss;
                        break;
                    }
                }
            }
            if (x509Possession == null || ecdheCredentials == null) {
                throw shc.conContext.fatal(Alert.HANDSHAKE_FAILURE, "No sufficient ECDHE key agreement parameters negotiated");
            }
            return new ECDHEKAKeyDerivation(shc, x509Possession.popPrivateKey, ecdheCredentials.popPublicKey);
        }

        /* JADX WARN: Code restructure failed: missing block: B:26:0x00be, code lost:
            if (r9 == null) goto L35;
         */
        /* JADX WARN: Code restructure failed: missing block: B:27:0x00c1, code lost:
            r8 = (org.openjsse.sun.security.ssl.ECDHKeyExchange.ECDHEPossession) r0;
         */
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct code enable 'Show inconsistent code' option in preferences
        */
        private org.openjsse.sun.security.ssl.SSLKeyDerivation createClientKeyDerivation(org.openjsse.sun.security.ssl.ClientHandshakeContext r7) throws java.io.IOException {
            /*
                r6 = this;
                r0 = 0
                r8 = r0
                r0 = 0
                r9 = r0
                r0 = r7
                java.util.List<org.openjsse.sun.security.ssl.SSLPossession> r0 = r0.handshakePossessions
                java.util.Iterator r0 = r0.iterator()
                r10 = r0
            Lf:
                r0 = r10
                boolean r0 = r0.hasNext()
                if (r0 == 0) goto Lcd
                r0 = r10
                java.lang.Object r0 = r0.next()
                org.openjsse.sun.security.ssl.SSLPossession r0 = (org.openjsse.sun.security.ssl.SSLPossession) r0
                r11 = r0
                r0 = r11
                boolean r0 = r0 instanceof org.openjsse.sun.security.ssl.ECDHKeyExchange.ECDHEPossession
                if (r0 != 0) goto L30
                goto Lf
            L30:
                r0 = r11
                org.openjsse.sun.security.ssl.ECDHKeyExchange$ECDHEPossession r0 = (org.openjsse.sun.security.ssl.ECDHKeyExchange.ECDHEPossession) r0
                org.openjsse.sun.security.ssl.SupportedGroupsExtension$NamedGroup r0 = r0.namedGroup
                r12 = r0
                r0 = r7
                java.util.List<org.openjsse.sun.security.ssl.SSLCredentials> r0 = r0.handshakeCredentials
                java.util.Iterator r0 = r0.iterator()
                r13 = r0
            L45:
                r0 = r13
                boolean r0 = r0.hasNext()
                if (r0 == 0) goto Lbd
                r0 = r13
                java.lang.Object r0 = r0.next()
                org.openjsse.sun.security.ssl.SSLCredentials r0 = (org.openjsse.sun.security.ssl.SSLCredentials) r0
                r14 = r0
                r0 = r14
                boolean r0 = r0 instanceof org.openjsse.sun.security.ssl.X509Authentication.X509Credentials
                if (r0 != 0) goto L66
                goto L45
            L66:
                r0 = r14
                org.openjsse.sun.security.ssl.X509Authentication$X509Credentials r0 = (org.openjsse.sun.security.ssl.X509Authentication.X509Credentials) r0
                java.security.PublicKey r0 = r0.popPublicKey
                r15 = r0
                r0 = r15
                java.lang.String r0 = r0.getAlgorithm()
                java.lang.String r1 = "EC"
                boolean r0 = r0.equals(r1)
                if (r0 != 0) goto L82
                goto L45
            L82:
                r0 = r15
                java.security.interfaces.ECPublicKey r0 = (java.security.interfaces.ECPublicKey) r0
                java.security.spec.ECParameterSpec r0 = r0.getParams()
                r16 = r0
                r0 = r16
                org.openjsse.sun.security.ssl.SupportedGroupsExtension$NamedGroup r0 = org.openjsse.sun.security.ssl.SupportedGroupsExtension.NamedGroup.valueOf(r0)
                r17 = r0
                r0 = r17
                if (r0 != 0) goto La7
                r0 = r7
                org.openjsse.sun.security.ssl.TransportContext r0 = r0.conContext
                org.openjsse.sun.security.ssl.Alert r1 = org.openjsse.sun.security.ssl.Alert.ILLEGAL_PARAMETER
                java.lang.String r2 = "Unsupported EC server cert for ECDH key exchange"
                javax.net.ssl.SSLException r0 = r0.fatal(r1, r2)
                throw r0
            La7:
                r0 = r12
                r1 = r17
                boolean r0 = r0.equals(r1)
                if (r0 == 0) goto Lba
                r0 = r14
                org.openjsse.sun.security.ssl.X509Authentication$X509Credentials r0 = (org.openjsse.sun.security.ssl.X509Authentication.X509Credentials) r0
                r9 = r0
                goto Lbd
            Lba:
                goto L45
            Lbd:
                r0 = r9
                if (r0 == 0) goto Lca
                r0 = r11
                org.openjsse.sun.security.ssl.ECDHKeyExchange$ECDHEPossession r0 = (org.openjsse.sun.security.ssl.ECDHKeyExchange.ECDHEPossession) r0
                r8 = r0
                goto Lcd
            Lca:
                goto Lf
            Lcd:
                r0 = r8
                if (r0 == 0) goto Ld5
                r0 = r9
                if (r0 != 0) goto Le2
            Ld5:
                r0 = r7
                org.openjsse.sun.security.ssl.TransportContext r0 = r0.conContext
                org.openjsse.sun.security.ssl.Alert r1 = org.openjsse.sun.security.ssl.Alert.HANDSHAKE_FAILURE
                java.lang.String r2 = "No sufficient ECDH key agreement parameters negotiated"
                javax.net.ssl.SSLException r0 = r0.fatal(r1, r2)
                throw r0
            Le2:
                org.openjsse.sun.security.ssl.ECDHKeyExchange$ECDHEKAKeyDerivation r0 = new org.openjsse.sun.security.ssl.ECDHKeyExchange$ECDHEKAKeyDerivation
                r1 = r0
                r2 = r7
                r3 = r8
                java.security.PrivateKey r3 = r3.privateKey
                r4 = r9
                java.security.PublicKey r4 = r4.popPublicKey
                r1.<init>(r2, r3, r4)
                return r0
            */
            throw new UnsupportedOperationException("Method not decompiled: org.openjsse.sun.security.ssl.ECDHKeyExchange.ECDHKAGenerator.createClientKeyDerivation(org.openjsse.sun.security.ssl.ClientHandshakeContext):org.openjsse.sun.security.ssl.SSLKeyDerivation");
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/ECDHKeyExchange$ECDHEKAGenerator.class */
    private static final class ECDHEKAGenerator implements SSLKeyAgreementGenerator {
        private ECDHEKAGenerator() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLKeyAgreementGenerator
        public SSLKeyDerivation createKeyDerivation(HandshakeContext context) throws IOException {
            ECDHEPossession ecdhePossession = null;
            ECDHECredentials ecdheCredentials = null;
            Iterator<SSLPossession> it = context.handshakePossessions.iterator();
            while (true) {
                if (!it.hasNext()) {
                    break;
                }
                SSLPossession poss = it.next();
                if (poss instanceof ECDHEPossession) {
                    SupportedGroupsExtension.NamedGroup ng = ((ECDHEPossession) poss).namedGroup;
                    Iterator<SSLCredentials> it2 = context.handshakeCredentials.iterator();
                    while (true) {
                        if (!it2.hasNext()) {
                            break;
                        }
                        SSLCredentials cred = it2.next();
                        if ((cred instanceof ECDHECredentials) && ng.equals(((ECDHECredentials) cred).namedGroup)) {
                            ecdheCredentials = (ECDHECredentials) cred;
                            break;
                        }
                    }
                    if (ecdheCredentials != null) {
                        ecdhePossession = (ECDHEPossession) poss;
                        break;
                    }
                }
            }
            if (ecdhePossession == null || ecdheCredentials == null) {
                throw context.conContext.fatal(Alert.HANDSHAKE_FAILURE, "No sufficient ECDHE key agreement parameters negotiated");
            }
            return new ECDHEKAKeyDerivation(context, ecdhePossession.privateKey, ecdheCredentials.popPublicKey);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/ECDHKeyExchange$ECDHEKAKeyDerivation.class */
    public static final class ECDHEKAKeyDerivation implements SSLKeyDerivation {
        private final HandshakeContext context;
        private final PrivateKey localPrivateKey;
        private final PublicKey peerPublicKey;

        ECDHEKAKeyDerivation(HandshakeContext context, PrivateKey localPrivateKey, PublicKey peerPublicKey) {
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
                KeyAgreement ka = JsseJce.getKeyAgreement("ECDH");
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
                KeyAgreement ka = JsseJce.getKeyAgreement("ECDH");
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