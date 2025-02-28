package org.bouncycastle.jsse.provider;

import java.security.AlgorithmParameters;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.Vector;
import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.Logger;
import org.bouncycastle.jcajce.spec.EdDSAParameterSpec;
import org.bouncycastle.jsse.java.security.BCAlgorithmConstraints;
import org.bouncycastle.jsse.java.security.BCCryptoPrimitive;
import org.bouncycastle.jsse.provider.NamedGroupInfo;
import org.bouncycastle.tls.NamedGroup;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.SignatureScheme;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Integers;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes2.dex */
public class SignatureSchemeInfo {
    private static final String PROPERTY_CLIENT_SIGNATURE_SCHEMES = "jdk.tls.client.SignatureSchemes";
    private static final String PROPERTY_CLIENT_SIGNATURE_SCHEMES_CERT = "org.bouncycastle.jsse.client.SignatureSchemesCert";
    private static final String PROPERTY_SERVER_SIGNATURE_SCHEMES = "jdk.tls.server.SignatureSchemes";
    private static final String PROPERTY_SERVER_SIGNATURE_SCHEMES_CERT = "org.bouncycastle.jsse.server.SignatureSchemesCert";
    static final int historical_dsa_sha1 = 514;
    static final int historical_dsa_sha224 = 770;
    static final int historical_dsa_sha256 = 1026;
    static final int historical_ecdsa_sha224 = 771;
    static final int historical_rsa_md5 = 257;
    static final int historical_rsa_sha224 = 769;
    private final AlgorithmParameters algorithmParameters;
    private final All all;
    private final boolean disabled13;
    private final boolean enabled;
    private final NamedGroupInfo namedGroupInfo;
    private static final Logger LOG = Logger.getLogger(SignatureSchemeInfo.class.getName());
    private static final int[] CANDIDATES_DEFAULT = createCandidatesDefault();

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes2.dex */
    public enum All {
        ed25519(SignatureScheme.ed25519, EdDSAParameterSpec.Ed25519, EdDSAParameterSpec.Ed25519),
        ed448(SignatureScheme.ed448, EdDSAParameterSpec.Ed448, EdDSAParameterSpec.Ed448),
        ecdsa_secp256r1_sha256(SignatureScheme.ecdsa_secp256r1_sha256, "SHA256withECDSA", "EC"),
        ecdsa_secp384r1_sha384(SignatureScheme.ecdsa_secp384r1_sha384, "SHA384withECDSA", "EC"),
        ecdsa_secp521r1_sha512(SignatureScheme.ecdsa_secp521r1_sha512, "SHA512withECDSA", "EC"),
        ecdsa_brainpoolP256r1tls13_sha256(SignatureScheme.ecdsa_brainpoolP256r1tls13_sha256, "SHA256withECDSA", "EC"),
        ecdsa_brainpoolP384r1tls13_sha384(SignatureScheme.ecdsa_brainpoolP384r1tls13_sha384, "SHA384withECDSA", "EC"),
        ecdsa_brainpoolP512r1tls13_sha512(SignatureScheme.ecdsa_brainpoolP512r1tls13_sha512, "SHA512withECDSA", "EC"),
        rsa_pss_pss_sha256(SignatureScheme.rsa_pss_pss_sha256, "SHA256withRSAandMGF1", "RSASSA-PSS"),
        rsa_pss_pss_sha384(SignatureScheme.rsa_pss_pss_sha384, "SHA384withRSAandMGF1", "RSASSA-PSS"),
        rsa_pss_pss_sha512(SignatureScheme.rsa_pss_pss_sha512, "SHA512withRSAandMGF1", "RSASSA-PSS"),
        rsa_pss_rsae_sha256(SignatureScheme.rsa_pss_rsae_sha256, "SHA256withRSAandMGF1", "RSA"),
        rsa_pss_rsae_sha384(SignatureScheme.rsa_pss_rsae_sha384, "SHA384withRSAandMGF1", "RSA"),
        rsa_pss_rsae_sha512(SignatureScheme.rsa_pss_rsae_sha512, "SHA512withRSAandMGF1", "RSA"),
        rsa_pkcs1_sha256(1025, "SHA256withRSA", "RSA", true),
        rsa_pkcs1_sha384((int) SignatureScheme.rsa_pkcs1_sha384, "SHA384withRSA", "RSA", true),
        rsa_pkcs1_sha512((int) SignatureScheme.rsa_pkcs1_sha512, "SHA512withRSA", "RSA", true),
        sm2sig_sm3(SignatureScheme.sm2sig_sm3, "SM3withSM2", "EC"),
        dsa_sha256((int) SignatureSchemeInfo.historical_dsa_sha256, "dsa_sha256", "SHA256withDSA", "DSA"),
        ecdsa_sha224((int) SignatureSchemeInfo.historical_ecdsa_sha224, "ecdsa_sha224", "SHA224withECDSA", "EC"),
        rsa_sha224((int) SignatureSchemeInfo.historical_rsa_sha224, "rsa_sha224", "SHA224withRSA", "RSA"),
        dsa_sha224((int) SignatureSchemeInfo.historical_dsa_sha224, "dsa_sha224", "SHA224withDSA", "DSA"),
        ecdsa_sha1((int) SignatureScheme.ecdsa_sha1, "SHA1withECDSA", "EC", true),
        rsa_pkcs1_sha1(513, "SHA1withRSA", "RSA", true),
        dsa_sha1((int) SignatureSchemeInfo.historical_dsa_sha1, "dsa_sha1", "SHA1withDSA", "DSA"),
        rsa_md5(257, "rsa_md5", "MD5withRSA", "RSA");
        
        private final String jcaSignatureAlgorithm;
        private final String jcaSignatureAlgorithmBC;
        private final String keyAlgorithm;
        private final String keyType13;
        private final String name;
        private final int namedGroup13;
        private final int signatureScheme;
        private final boolean supportedCerts13;
        private final boolean supportedPost13;
        private final boolean supportedPre13;
        private final String text;

        All(int i, String str, String str2) {
            this(i, str, str2, true, true, SignatureScheme.getNamedGroup(i));
        }

        All(int i, String str, String str2, String str3) {
            this(i, str, str2, str3, false, false, -1);
        }

        All(int i, String str, String str2, String str3, boolean z, boolean z2, int i2) {
            String keyType13 = JsseUtils.getKeyType13(str3, i2);
            String jcaSignatureAlgorithmBC = JsseUtils.getJcaSignatureAlgorithmBC(str2, str3);
            this.signatureScheme = i;
            this.name = str;
            this.text = str + "(0x" + Integer.toHexString(i) + ")";
            this.jcaSignatureAlgorithm = str2;
            this.jcaSignatureAlgorithmBC = jcaSignatureAlgorithmBC;
            this.keyAlgorithm = str3;
            this.keyType13 = keyType13;
            this.supportedPost13 = z;
            this.supportedPre13 = i2 < 0 || NamedGroup.canBeNegotiated(i2, ProtocolVersion.TLSv12);
            this.supportedCerts13 = z2;
            this.namedGroup13 = i2;
        }

        All(int i, String str, String str2, boolean z) {
            this(i, str, str2, false, z, -1);
        }

        All(int i, String str, String str2, boolean z, boolean z2, int i2) {
            this(i, SignatureScheme.getName(i), str, str2, z, z2, i2);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes2.dex */
    public static class PerConnection {
        private final List<SignatureSchemeInfo> localSigSchemes;
        private final List<SignatureSchemeInfo> localSigSchemesCert;
        private final AtomicReference<List<SignatureSchemeInfo>> peerSigSchemes = new AtomicReference<>();
        private final AtomicReference<List<SignatureSchemeInfo>> peerSigSchemesCert = new AtomicReference<>();

        PerConnection(List<SignatureSchemeInfo> list, List<SignatureSchemeInfo> list2) {
            this.localSigSchemes = list;
            this.localSigSchemesCert = list2;
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public String[] getLocalJcaSignatureAlgorithms() {
            return SignatureSchemeInfo.getJcaSignatureAlgorithms(getLocalSigSchemesCert());
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public String[] getLocalJcaSignatureAlgorithmsBC() {
            return SignatureSchemeInfo.getJcaSignatureAlgorithmsBC(getLocalSigSchemesCert());
        }

        List<SignatureSchemeInfo> getLocalSigSchemes() {
            return this.localSigSchemes;
        }

        List<SignatureSchemeInfo> getLocalSigSchemesCert() {
            List<SignatureSchemeInfo> list = this.localSigSchemesCert;
            return list != null ? list : getLocalSigSchemes();
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public Vector<SignatureAndHashAlgorithm> getLocalSignatureAndHashAlgorithms() {
            return SignatureSchemeInfo.getSignatureAndHashAlgorithms(this.localSigSchemes);
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public Vector<SignatureAndHashAlgorithm> getLocalSignatureAndHashAlgorithmsCert() {
            return SignatureSchemeInfo.getSignatureAndHashAlgorithms(this.localSigSchemesCert);
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public String[] getPeerJcaSignatureAlgorithms() {
            return SignatureSchemeInfo.getJcaSignatureAlgorithms(getPeerSigSchemesCert());
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public String[] getPeerJcaSignatureAlgorithmsBC() {
            return SignatureSchemeInfo.getJcaSignatureAlgorithmsBC(getPeerSigSchemesCert());
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public List<SignatureSchemeInfo> getPeerSigSchemes() {
            return this.peerSigSchemes.get();
        }

        List<SignatureSchemeInfo> getPeerSigSchemesCert() {
            List<SignatureSchemeInfo> list = this.peerSigSchemesCert.get();
            return list != null ? list : getPeerSigSchemes();
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public boolean hasLocalSignatureScheme(SignatureSchemeInfo signatureSchemeInfo) {
            return this.localSigSchemes.contains(signatureSchemeInfo);
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public void notifyPeerData(List<SignatureSchemeInfo> list, List<SignatureSchemeInfo> list2) {
            this.peerSigSchemes.set(list);
            this.peerSigSchemesCert.set(list2);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes2.dex */
    public static class PerContext {
        private final int[] candidatesCertClient;
        private final int[] candidatesCertServer;
        private final int[] candidatesClient;
        private final int[] candidatesServer;
        private final Map<Integer, SignatureSchemeInfo> index;

        PerContext(Map<Integer, SignatureSchemeInfo> map, int[] iArr, int[] iArr2, int[] iArr3, int[] iArr4) {
            this.index = map;
            this.candidatesClient = iArr;
            this.candidatesServer = iArr2;
            this.candidatesCertClient = iArr3;
            this.candidatesCertServer = iArr4;
        }
    }

    SignatureSchemeInfo(All all, AlgorithmParameters algorithmParameters, NamedGroupInfo namedGroupInfo, boolean z, boolean z2) {
        this.all = all;
        this.algorithmParameters = algorithmParameters;
        this.namedGroupInfo = namedGroupInfo;
        this.enabled = z;
        this.disabled13 = z2;
    }

    private static void addSignatureScheme(boolean z, JcaTlsCrypto jcaTlsCrypto, NamedGroupInfo.PerContext perContext, Map<Integer, SignatureSchemeInfo> map, All all) {
        boolean z2;
        NamedGroupInfo namedGroupInfo;
        boolean z3;
        int i = all.signatureScheme;
        if (!z || FipsUtils.isFipsSignatureScheme(i)) {
            int i2 = all.namedGroup13;
            AlgorithmParameters algorithmParameters = null;
            if (i2 >= 0) {
                NamedGroupInfo namedGroup = NamedGroupInfo.getNamedGroup(perContext, i2);
                if (namedGroup != null && namedGroup.isEnabled() && namedGroup.isSupportedPost13()) {
                    namedGroupInfo = namedGroup;
                    z2 = false;
                } else {
                    namedGroupInfo = namedGroup;
                    z2 = true;
                }
            } else {
                z2 = false;
                namedGroupInfo = null;
            }
            boolean hasSignatureScheme = jcaTlsCrypto.hasSignatureScheme(i);
            if (hasSignatureScheme) {
                try {
                    algorithmParameters = jcaTlsCrypto.getSignatureSchemeAlgorithmParameters(i);
                } catch (Exception unused) {
                    z3 = false;
                }
            }
            z3 = hasSignatureScheme;
            if (map.put(Integer.valueOf(i), new SignatureSchemeInfo(all, algorithmParameters, namedGroupInfo, z3, z2)) != null) {
                throw new IllegalStateException("Duplicate entries for SignatureSchemeInfo");
            }
        }
    }

    private static int[] createCandidates(Map<Integer, SignatureSchemeInfo> map, String[] strArr, String str) {
        Logger logger;
        StringBuilder append;
        String str2;
        int length = strArr.length;
        int[] iArr = new int[length];
        int i = 0;
        for (String str3 : strArr) {
            int signatureSchemeByName = getSignatureSchemeByName(str3);
            if (signatureSchemeByName < 0) {
                logger = LOG;
                append = new StringBuilder("'").append(str);
                str2 = "' contains unrecognised SignatureScheme: ";
            } else {
                SignatureSchemeInfo signatureSchemeInfo = map.get(Integer.valueOf(signatureSchemeByName));
                if (signatureSchemeInfo == null) {
                    logger = LOG;
                    append = new StringBuilder("'").append(str);
                    str2 = "' contains unsupported SignatureScheme: ";
                } else if (signatureSchemeInfo.isEnabled()) {
                    iArr[i] = signatureSchemeByName;
                    i++;
                } else {
                    logger = LOG;
                    append = new StringBuilder("'").append(str);
                    str2 = "' contains disabled SignatureScheme: ";
                }
            }
            logger.warning(append.append(str2).append(str3).toString());
        }
        if (i < length) {
            iArr = Arrays.copyOf(iArr, i);
        }
        if (iArr.length < 1) {
            LOG.severe("'" + str + "' contained no usable SignatureScheme values");
        }
        return iArr;
    }

    private static int[] createCandidatesDefault() {
        All[] values = All.values();
        int[] iArr = new int[values.length];
        for (int i = 0; i < values.length; i++) {
            iArr[i] = values[i].signatureScheme;
        }
        return iArr;
    }

    private static int[] createCandidatesFromProperty(Map<Integer, SignatureSchemeInfo> map, String str) {
        String[] stringArraySystemProperty = PropertyUtils.getStringArraySystemProperty(str);
        if (stringArraySystemProperty == null) {
            return null;
        }
        return createCandidates(map, stringArraySystemProperty, str);
    }

    private static Map<Integer, SignatureSchemeInfo> createIndex(boolean z, JcaTlsCrypto jcaTlsCrypto, NamedGroupInfo.PerContext perContext) {
        TreeMap treeMap = new TreeMap();
        for (All all : All.values()) {
            addSignatureScheme(z, jcaTlsCrypto, perContext, treeMap, all);
        }
        return treeMap;
    }

    private static PerConnection createPerConnection(PerContext perContext, boolean z, ProvSSLParameters provSSLParameters, ProtocolVersion protocolVersion, ProtocolVersion protocolVersion2, NamedGroupInfo.PerConnection perConnection) {
        int[] createCandidates;
        ArrayList arrayList;
        String[] signatureSchemes = provSSLParameters.getSignatureSchemes();
        if (signatureSchemes == null) {
            createCandidates = z ? perContext.candidatesServer : perContext.candidatesClient;
            if (createCandidates == null) {
                createCandidates = CANDIDATES_DEFAULT;
            }
        } else {
            createCandidates = createCandidates(perContext.index, signatureSchemes, "SSLParameters.signatureSchemes");
        }
        String[] signatureSchemesCert = provSSLParameters.getSignatureSchemesCert();
        int[] createCandidates2 = signatureSchemesCert == null ? z ? perContext.candidatesCertServer : perContext.candidatesCertClient : createCandidates(perContext.index, signatureSchemesCert, "SSLParameters.signatureSchemesCert");
        BCAlgorithmConstraints algorithmConstraints = provSSLParameters.getAlgorithmConstraints();
        boolean isTLSv13 = TlsUtils.isTLSv13(protocolVersion2);
        boolean z2 = !TlsUtils.isTLSv13(protocolVersion);
        ArrayList arrayList2 = new ArrayList(createCandidates.length);
        for (int i : createCandidates) {
            SignatureSchemeInfo signatureSchemeInfo = (SignatureSchemeInfo) perContext.index.get(Integers.valueOf(i));
            if (signatureSchemeInfo != null && signatureSchemeInfo.isActiveCerts(algorithmConstraints, isTLSv13, z2, perConnection)) {
                arrayList2.add(signatureSchemeInfo);
            }
        }
        arrayList2.trimToSize();
        if (createCandidates2 != null) {
            arrayList = new ArrayList(createCandidates2.length);
            for (int i2 : createCandidates2) {
                SignatureSchemeInfo signatureSchemeInfo2 = (SignatureSchemeInfo) perContext.index.get(Integers.valueOf(i2));
                if (signatureSchemeInfo2 != null && signatureSchemeInfo2.isActiveCerts(algorithmConstraints, isTLSv13, z2, perConnection)) {
                    arrayList.add(signatureSchemeInfo2);
                }
            }
            arrayList.trimToSize();
        } else {
            arrayList = null;
        }
        return new PerConnection(arrayList2, arrayList);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static PerConnection createPerConnectionClient(PerContext perContext, ProvSSLParameters provSSLParameters, ProtocolVersion[] protocolVersionArr, NamedGroupInfo.PerConnection perConnection) {
        ProtocolVersion latestTLS = ProtocolVersion.getLatestTLS(protocolVersionArr);
        return !TlsUtils.isSignatureAlgorithmsExtensionAllowed(latestTLS) ? new PerConnection(null, null) : createPerConnection(perContext, false, provSSLParameters, ProtocolVersion.getEarliestTLS(protocolVersionArr), latestTLS, perConnection);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static PerConnection createPerConnectionServer(PerContext perContext, ProvSSLParameters provSSLParameters, ProtocolVersion protocolVersion, NamedGroupInfo.PerConnection perConnection) {
        return !TlsUtils.isSignatureAlgorithmsExtensionAllowed(protocolVersion) ? new PerConnection(null, null) : createPerConnection(perContext, true, provSSLParameters, protocolVersion, protocolVersion, perConnection);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static PerContext createPerContext(boolean z, JcaTlsCrypto jcaTlsCrypto, NamedGroupInfo.PerContext perContext) {
        Map<Integer, SignatureSchemeInfo> createIndex = createIndex(z, jcaTlsCrypto, perContext);
        return new PerContext(createIndex, createCandidatesFromProperty(createIndex, PROPERTY_CLIENT_SIGNATURE_SCHEMES), createCandidatesFromProperty(createIndex, PROPERTY_SERVER_SIGNATURE_SCHEMES), createCandidatesFromProperty(createIndex, PROPERTY_CLIENT_SIGNATURE_SCHEMES_CERT), createCandidatesFromProperty(createIndex, PROPERTY_SERVER_SIGNATURE_SCHEMES_CERT));
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static String[] getJcaSignatureAlgorithms(Collection<SignatureSchemeInfo> collection) {
        if (collection == null) {
            return TlsUtils.EMPTY_STRINGS;
        }
        String[] strArr = new String[collection.size()];
        int i = 0;
        for (SignatureSchemeInfo signatureSchemeInfo : collection) {
            strArr[i] = signatureSchemeInfo.getJcaSignatureAlgorithm();
            i++;
        }
        return strArr;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static String[] getJcaSignatureAlgorithmsBC(Collection<SignatureSchemeInfo> collection) {
        if (collection == null) {
            return TlsUtils.EMPTY_STRINGS;
        }
        String[] strArr = new String[collection.size()];
        int i = 0;
        for (SignatureSchemeInfo signatureSchemeInfo : collection) {
            strArr[i] = signatureSchemeInfo.getJcaSignatureAlgorithmBC();
            i++;
        }
        return strArr;
    }

    static SignatureAndHashAlgorithm getSignatureAndHashAlgorithm(int i) {
        if (TlsUtils.isValidUint16(i)) {
            return SignatureScheme.getSignatureAndHashAlgorithm(i);
        }
        throw new IllegalArgumentException();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static Vector<SignatureAndHashAlgorithm> getSignatureAndHashAlgorithms(Collection<SignatureSchemeInfo> collection) {
        if (collection == null || collection.isEmpty()) {
            return null;
        }
        Vector<SignatureAndHashAlgorithm> vector = new Vector<>(collection.size());
        for (SignatureSchemeInfo signatureSchemeInfo : collection) {
            if (signatureSchemeInfo != null) {
                vector.add(signatureSchemeInfo.getSignatureAndHashAlgorithm());
            }
        }
        if (vector.isEmpty()) {
            return null;
        }
        vector.trimToSize();
        return vector;
    }

    private static int getSignatureSchemeByName(String str) {
        All[] values;
        for (All all : All.values()) {
            if (all.name.equalsIgnoreCase(str)) {
                return all.signatureScheme;
            }
        }
        return -1;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static List<SignatureSchemeInfo> getSignatureSchemes(PerContext perContext, Vector<SignatureAndHashAlgorithm> vector) {
        if (vector == null || vector.isEmpty()) {
            return null;
        }
        int size = vector.size();
        ArrayList arrayList = new ArrayList(size);
        for (int i = 0; i < size; i++) {
            SignatureAndHashAlgorithm elementAt = vector.elementAt(i);
            if (elementAt != null) {
                SignatureSchemeInfo signatureSchemeInfo = (SignatureSchemeInfo) perContext.index.get(Integer.valueOf(SignatureScheme.from(elementAt)));
                if (signatureSchemeInfo != null) {
                    arrayList.add(signatureSchemeInfo);
                }
            }
        }
        if (arrayList.isEmpty()) {
            return null;
        }
        arrayList.trimToSize();
        return Collections.unmodifiableList(arrayList);
    }

    private boolean isActiveCerts(BCAlgorithmConstraints bCAlgorithmConstraints, boolean z, boolean z2, NamedGroupInfo.PerConnection perConnection) {
        if (this.enabled) {
            return isNamedGroupOK(z && isSupportedCerts13(), z2 && isSupportedPre13(), perConnection) && isPermittedBy(bCAlgorithmConstraints);
        }
        return false;
    }

    private static boolean isECDSA(int i) {
        if (i == 515 || i == historical_ecdsa_sha224 || i == 1027 || i == 1283 || i == 1539) {
            return true;
        }
        switch (i) {
            case SignatureScheme.ecdsa_brainpoolP256r1tls13_sha256 /* 2074 */:
            case SignatureScheme.ecdsa_brainpoolP384r1tls13_sha384 /* 2075 */:
            case SignatureScheme.ecdsa_brainpoolP512r1tls13_sha512 /* 2076 */:
                return true;
            default:
                return false;
        }
    }

    private boolean isNamedGroupOK(boolean z, boolean z2, NamedGroupInfo.PerConnection perConnection) {
        NamedGroupInfo namedGroupInfo = this.namedGroupInfo;
        if (namedGroupInfo != null) {
            return (z && NamedGroupInfo.hasLocal(perConnection, namedGroupInfo.getNamedGroup())) || (z2 && NamedGroupInfo.hasAnyECDSALocal(perConnection));
        } else if (z || z2) {
            return !isECDSA(this.all.signatureScheme) || NamedGroupInfo.hasAnyECDSALocal(perConnection);
        } else {
            return false;
        }
    }

    private boolean isPermittedBy(BCAlgorithmConstraints bCAlgorithmConstraints) {
        Set<BCCryptoPrimitive> set = JsseUtils.SIGNATURE_CRYPTO_PRIMITIVES_BC;
        return bCAlgorithmConstraints.permits(set, this.all.name, null) && bCAlgorithmConstraints.permits(set, this.all.keyAlgorithm, null) && bCAlgorithmConstraints.permits(set, this.all.jcaSignatureAlgorithm, this.algorithmParameters);
    }

    short getHashAlgorithm() {
        return SignatureScheme.getHashAlgorithm(this.all.signatureScheme);
    }

    String getJcaSignatureAlgorithm() {
        return this.all.jcaSignatureAlgorithm;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public String getJcaSignatureAlgorithmBC() {
        return this.all.jcaSignatureAlgorithmBC;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public String getKeyType() {
        return this.all.keyAlgorithm;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public String getKeyType13() {
        return this.all.keyType13;
    }

    String getName() {
        return this.all.name;
    }

    NamedGroupInfo getNamedGroupInfo() {
        return this.namedGroupInfo;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public short getSignatureAlgorithm() {
        return SignatureScheme.getSignatureAlgorithm(this.all.signatureScheme);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public SignatureAndHashAlgorithm getSignatureAndHashAlgorithm() {
        return getSignatureAndHashAlgorithm(this.all.signatureScheme);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getSignatureScheme() {
        return this.all.signatureScheme;
    }

    boolean isEnabled() {
        return this.enabled;
    }

    boolean isSupportedCerts13() {
        return !this.disabled13 && this.all.supportedCerts13;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean isSupportedPost13() {
        return !this.disabled13 && this.all.supportedPost13;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean isSupportedPre13() {
        return this.all.supportedPre13;
    }

    public String toString() {
        return this.all.text;
    }
}