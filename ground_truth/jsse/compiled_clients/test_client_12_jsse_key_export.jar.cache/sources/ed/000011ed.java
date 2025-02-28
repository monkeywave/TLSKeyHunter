package org.openjsse.sun.security.ssl;

import java.security.AlgorithmConstraints;
import java.security.CryptoPrimitive;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.bouncycastle.pqc.crypto.rainbow.util.GF2Field;
import org.bouncycastle.pqc.jcajce.spec.McElieceCCA2KeyGenParameterSpec;
import org.openjsse.sun.security.ssl.SupportedGroupsExtension;
import org.openjsse.sun.security.ssl.X509Authentication;
import sun.security.util.KeyUtil;
import sun.security.util.SignatureUtil;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SignatureScheme.class */
public enum SignatureScheme {
    ED25519(2055, "ed25519", "ed25519", "ed25519", ProtocolVersion.PROTOCOLS_OF_13),
    ED448(2056, "ed448", "ed448", "ed448", ProtocolVersion.PROTOCOLS_OF_13),
    ECDSA_SECP256R1_SHA256(1027, "ecdsa_secp256r1_sha256", "SHA256withECDSA", "EC", SupportedGroupsExtension.NamedGroup.SECP256_R1, ProtocolVersion.PROTOCOLS_TO_13),
    ECDSA_SECP384R1_SHA384(1283, "ecdsa_secp384r1_sha384", "SHA384withECDSA", "EC", SupportedGroupsExtension.NamedGroup.SECP384_R1, ProtocolVersion.PROTOCOLS_TO_13),
    ECDSA_SECP512R1_SHA512(1539, "ecdsa_secp521r1_sha512", "SHA512withECDSA", "EC", SupportedGroupsExtension.NamedGroup.SECP521_R1, ProtocolVersion.PROTOCOLS_TO_13),
    RSA_PSS_RSAE_SHA256(2052, "rsa_pss_rsae_sha256", "RSASSA-PSS", "RSA", SigAlgParamSpec.RSA_PSS_SHA256, 528, ProtocolVersion.PROTOCOLS_12_13),
    RSA_PSS_RSAE_SHA384(2053, "rsa_pss_rsae_sha384", "RSASSA-PSS", "RSA", SigAlgParamSpec.RSA_PSS_SHA384, 784, ProtocolVersion.PROTOCOLS_12_13),
    RSA_PSS_RSAE_SHA512(2054, "rsa_pss_rsae_sha512", "RSASSA-PSS", "RSA", SigAlgParamSpec.RSA_PSS_SHA512, 1040, ProtocolVersion.PROTOCOLS_12_13),
    RSA_PSS_PSS_SHA256(2057, "rsa_pss_pss_sha256", "RSASSA-PSS", "RSASSA-PSS", SigAlgParamSpec.RSA_PSS_SHA256, 528, ProtocolVersion.PROTOCOLS_12_13),
    RSA_PSS_PSS_SHA384(2058, "rsa_pss_pss_sha384", "RSASSA-PSS", "RSASSA-PSS", SigAlgParamSpec.RSA_PSS_SHA384, 784, ProtocolVersion.PROTOCOLS_12_13),
    RSA_PSS_PSS_SHA512(2059, "rsa_pss_pss_sha512", "RSASSA-PSS", "RSASSA-PSS", SigAlgParamSpec.RSA_PSS_SHA512, 1040, ProtocolVersion.PROTOCOLS_12_13),
    RSA_PKCS1_SHA256(1025, "rsa_pkcs1_sha256", "SHA256withRSA", "RSA", null, null, 511, ProtocolVersion.PROTOCOLS_TO_13, ProtocolVersion.PROTOCOLS_TO_12),
    RSA_PKCS1_SHA384(1281, "rsa_pkcs1_sha384", "SHA384withRSA", "RSA", null, null, 768, ProtocolVersion.PROTOCOLS_TO_13, ProtocolVersion.PROTOCOLS_TO_12),
    RSA_PKCS1_SHA512(1537, "rsa_pkcs1_sha512", "SHA512withRSA", "RSA", null, null, 768, ProtocolVersion.PROTOCOLS_TO_13, ProtocolVersion.PROTOCOLS_TO_12),
    DSA_SHA256(1026, "dsa_sha256", "SHA256withDSA", "DSA", ProtocolVersion.PROTOCOLS_TO_12),
    ECDSA_SHA224(771, "ecdsa_sha224", "SHA224withECDSA", "EC", ProtocolVersion.PROTOCOLS_TO_12),
    RSA_SHA224(769, "rsa_sha224", "SHA224withRSA", "RSA", 511, ProtocolVersion.PROTOCOLS_TO_12),
    DSA_SHA224(770, "dsa_sha224", "SHA224withDSA", "DSA", ProtocolVersion.PROTOCOLS_TO_12),
    ECDSA_SHA1(515, "ecdsa_sha1", "SHA1withECDSA", "EC", ProtocolVersion.PROTOCOLS_TO_13),
    RSA_PKCS1_SHA1(513, "rsa_pkcs1_sha1", "SHA1withRSA", "RSA", null, null, 511, ProtocolVersion.PROTOCOLS_TO_13, ProtocolVersion.PROTOCOLS_TO_12),
    DSA_SHA1(514, "dsa_sha1", "SHA1withDSA", "DSA", ProtocolVersion.PROTOCOLS_TO_12),
    RSA_MD5(257, "rsa_md5", "MD5withRSA", "RSA", 511, ProtocolVersion.PROTOCOLS_TO_12);
    

    /* renamed from: id */
    final int f1007id;
    final String name;
    private final String algorithm;
    final String keyAlgorithm;
    private final SigAlgParamSpec signAlgParams;
    private final SupportedGroupsExtension.NamedGroup namedGroup;
    final int minimalKeySize;
    final List<ProtocolVersion> supportedProtocols;
    final List<ProtocolVersion> handshakeSupportedProtocols;
    final boolean isAvailable;
    private static final String[] hashAlgorithms = {"none", "md5", "sha1", "sha224", "sha256", "sha384", "sha512"};
    private static final String[] signatureAlgorithms = {"anonymous", "rsa", "dsa", "ecdsa"};
    private static final Set<CryptoPrimitive> SIGNATURE_PRIMITIVE_SET = Collections.unmodifiableSet(EnumSet.of(CryptoPrimitive.SIGNATURE));

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SignatureScheme$SigAlgParamSpec.class */
    public enum SigAlgParamSpec {
        RSA_PSS_SHA256("SHA-256", 32),
        RSA_PSS_SHA384(McElieceCCA2KeyGenParameterSpec.SHA384, 48),
        RSA_PSS_SHA512("SHA-512", 64);
        
        private final AlgorithmParameterSpec parameterSpec;
        private final boolean isAvailable;

        SigAlgParamSpec(String hash, int saltLength) {
            PSSParameterSpec pssParamSpec = new PSSParameterSpec(hash, "MGF1", new MGF1ParameterSpec(hash), saltLength, 1);
            boolean mediator = true;
            try {
                Signature signer = Signature.getInstance("RSASSA-PSS");
                signer.setParameter(pssParamSpec);
            } catch (RuntimeException | InvalidAlgorithmParameterException | NoSuchAlgorithmException exp) {
                mediator = false;
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.warning("RSASSA-PSS signature with " + hash + " is not supported by the underlying providers", exp);
                }
            }
            this.isAvailable = mediator;
            this.parameterSpec = mediator ? pssParamSpec : null;
        }

        AlgorithmParameterSpec getParameterSpec() {
            return this.parameterSpec;
        }
    }

    SignatureScheme(int id, String name, String algorithm, String keyAlgorithm, ProtocolVersion[] supportedProtocols) {
        this(id, name, algorithm, keyAlgorithm, -1, supportedProtocols);
    }

    SignatureScheme(int id, String name, String algorithm, String keyAlgorithm, int minimalKeySize, ProtocolVersion[] supportedProtocols) {
        this(id, name, algorithm, keyAlgorithm, null, minimalKeySize, supportedProtocols);
    }

    SignatureScheme(int id, String name, String algorithm, String keyAlgorithm, SigAlgParamSpec signAlgParamSpec, int minimalKeySize, ProtocolVersion[] supportedProtocols) {
        this(id, name, algorithm, keyAlgorithm, signAlgParamSpec, null, minimalKeySize, supportedProtocols, supportedProtocols);
    }

    SignatureScheme(int id, String name, String algorithm, String keyAlgorithm, SupportedGroupsExtension.NamedGroup namedGroup, ProtocolVersion[] supportedProtocols) {
        this(id, name, algorithm, keyAlgorithm, null, namedGroup, -1, supportedProtocols, supportedProtocols);
    }

    SignatureScheme(int id, String name, String algorithm, String keyAlgorithm, SigAlgParamSpec signAlgParamSpec, SupportedGroupsExtension.NamedGroup namedGroup, int minimalKeySize, ProtocolVersion[] supportedProtocols, ProtocolVersion[] handshakeSupportedProtocols) {
        this.f1007id = id;
        this.name = name;
        this.algorithm = algorithm;
        this.keyAlgorithm = keyAlgorithm;
        this.signAlgParams = signAlgParamSpec;
        this.namedGroup = namedGroup;
        this.minimalKeySize = minimalKeySize;
        this.supportedProtocols = Arrays.asList(supportedProtocols);
        this.handshakeSupportedProtocols = Arrays.asList(handshakeSupportedProtocols);
        boolean mediator = true;
        mediator = "EC".equals(keyAlgorithm) ? JsseJce.isEcAvailable() : mediator;
        if (mediator) {
            if (signAlgParamSpec != null) {
                mediator = signAlgParamSpec.isAvailable;
            } else {
                try {
                    JsseJce.getSignature(algorithm);
                } catch (Exception e) {
                    mediator = false;
                    if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                        SSLLogger.warning("Signature algorithm, " + algorithm + ", is not supported by the underlying providers", new Object[0]);
                    }
                }
            }
        }
        if (mediator && ((id >> 8) & GF2Field.MASK) == 3 && Security.getProvider("SunMSCAPI") != null) {
            mediator = false;
        }
        this.isAvailable = mediator;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static SignatureScheme valueOf(int id) {
        SignatureScheme[] values;
        for (SignatureScheme ss : values()) {
            if (ss.f1007id == id) {
                return ss;
            }
        }
        return null;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static String nameOf(int id) {
        SignatureScheme[] values;
        for (SignatureScheme ss : values()) {
            if (ss.f1007id == id) {
                return ss.name;
            }
        }
        int hashId = (id >> 8) & GF2Field.MASK;
        int signId = id & GF2Field.MASK;
        String hashName = hashId >= hashAlgorithms.length ? "UNDEFINED-HASH(" + hashId + ")" : hashAlgorithms[hashId];
        String signName = signId >= signatureAlgorithms.length ? "UNDEFINED-SIGNATURE(" + signId + ")" : signatureAlgorithms[signId];
        return signName + "_" + hashName;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static SignatureScheme nameOf(String signatureSchemeName) {
        SignatureScheme[] values;
        for (SignatureScheme ss : values()) {
            if (ss.name.equalsIgnoreCase(signatureSchemeName)) {
                return ss;
            }
        }
        return null;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static int sizeInRecord() {
        return 2;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static List<SignatureScheme> getSupportedAlgorithms(SSLConfiguration config, AlgorithmConstraints constraints, List<ProtocolVersion> activeProtocols) {
        SignatureScheme[] values;
        List<SignatureScheme> supported = new LinkedList<>();
        for (SignatureScheme ss : values()) {
            if (!ss.isAvailable || (!config.signatureSchemes.isEmpty() && !config.signatureSchemes.contains(ss))) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake,verbose")) {
                    SSLLogger.finest("Ignore unsupported signature scheme: " + ss.name, new Object[0]);
                }
            } else {
                boolean isMatch = false;
                Iterator<ProtocolVersion> it = activeProtocols.iterator();
                while (true) {
                    if (!it.hasNext()) {
                        break;
                    }
                    ProtocolVersion pv = it.next();
                    if (ss.supportedProtocols.contains(pv)) {
                        isMatch = true;
                        break;
                    }
                }
                if (isMatch) {
                    if (constraints.permits(SIGNATURE_PRIMITIVE_SET, ss.algorithm, null)) {
                        supported.add(ss);
                    } else if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake,verbose")) {
                        SSLLogger.finest("Ignore disabled signature scheme: " + ss.name, new Object[0]);
                    }
                } else if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake,verbose")) {
                    SSLLogger.finest("Ignore inactive signature scheme: " + ss.name, new Object[0]);
                }
            }
        }
        return supported;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static List<SignatureScheme> getSupportedAlgorithms(SSLConfiguration config, AlgorithmConstraints constraints, ProtocolVersion protocolVersion, int[] algorithmIds) {
        List<SignatureScheme> supported = new LinkedList<>();
        for (int ssid : algorithmIds) {
            SignatureScheme ss = valueOf(ssid);
            if (ss == null) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.warning("Unsupported signature scheme: " + nameOf(ssid), new Object[0]);
                }
            } else if (ss.isAvailable && ss.supportedProtocols.contains(protocolVersion) && ((config.signatureSchemes.isEmpty() || config.signatureSchemes.contains(ss)) && constraints.permits(SIGNATURE_PRIMITIVE_SET, ss.algorithm, null))) {
                supported.add(ss);
            } else if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.warning("Unsupported signature scheme: " + ss.name, new Object[0]);
            }
        }
        return supported;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static SignatureScheme getPreferableAlgorithm(List<SignatureScheme> schemes, SignatureScheme certScheme, ProtocolVersion version) {
        for (SignatureScheme ss : schemes) {
            if (ss.isAvailable && ss.handshakeSupportedProtocols.contains(version) && certScheme.keyAlgorithm.equalsIgnoreCase(ss.keyAlgorithm)) {
                return ss;
            }
        }
        return null;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static Map.Entry<SignatureScheme, Signature> getSignerOfPreferableAlgorithm(List<SignatureScheme> schemes, X509Authentication.X509Possession x509Possession, ProtocolVersion version) {
        int keySize;
        Signature signer;
        PrivateKey signingKey = x509Possession.popPrivateKey;
        String keyAlgorithm = signingKey.getAlgorithm();
        if (keyAlgorithm.equalsIgnoreCase("RSA") || keyAlgorithm.equalsIgnoreCase("RSASSA-PSS")) {
            keySize = KeyUtil.getKeySize(signingKey);
        } else {
            keySize = Integer.MAX_VALUE;
        }
        for (SignatureScheme ss : schemes) {
            if (ss.isAvailable && keySize >= ss.minimalKeySize && ss.handshakeSupportedProtocols.contains(version) && keyAlgorithm.equalsIgnoreCase(ss.keyAlgorithm)) {
                if (ss.namedGroup != null && ss.namedGroup.type == SupportedGroupsExtension.NamedGroupType.NAMED_GROUP_ECDHE) {
                    ECParameterSpec params = x509Possession.getECParameterSpec();
                    if (params != null && ss.namedGroup == SupportedGroupsExtension.NamedGroup.valueOf(params) && (signer = ss.getSigner(signingKey)) != null) {
                        return new AbstractMap.SimpleImmutableEntry(ss, signer);
                    }
                } else {
                    Signature signer2 = ss.getSigner(signingKey);
                    if (signer2 != null) {
                        return new AbstractMap.SimpleImmutableEntry(ss, signer2);
                    }
                }
            }
        }
        return null;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static String[] getAlgorithmNames(Collection<SignatureScheme> schemes) {
        if (schemes != null) {
            ArrayList<String> names = new ArrayList<>(schemes.size());
            for (SignatureScheme scheme : schemes) {
                names.add(scheme.algorithm);
            }
            return (String[]) names.toArray(new String[0]);
        }
        return new String[0];
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public Signature getVerifier(PublicKey publicKey) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
        if (!this.isAvailable) {
            return null;
        }
        Signature verifier = Signature.getInstance(this.algorithm);
        SignatureUtil.initVerifyWithParam(verifier, publicKey, this.signAlgParams != null ? this.signAlgParams.parameterSpec : null);
        return verifier;
    }

    private Signature getSigner(PrivateKey privateKey) {
        if (!this.isAvailable) {
            return null;
        }
        try {
            Signature signer = Signature.getInstance(this.algorithm);
            SignatureUtil.initSignWithParam(signer, privateKey, this.signAlgParams != null ? this.signAlgParams.parameterSpec : null, (SecureRandom) null);
            return signer;
        } catch (InvalidAlgorithmParameterException | InvalidKeyException | NoSuchAlgorithmException nsae) {
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake,verbose")) {
                SSLLogger.finest("Ignore unsupported signature algorithm (" + this.name + ")", nsae);
                return null;
            }
            return null;
        }
    }
}