package org.bouncycastle.jsse.provider;

import java.security.AlgorithmParameters;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.Vector;
import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.Logger;
import org.bouncycastle.jsse.java.security.BCAlgorithmConstraints;
import org.bouncycastle.jsse.java.security.BCCryptoPrimitive;
import org.bouncycastle.tls.NamedGroup;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.Properties;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes2.dex */
public class NamedGroupInfo {
    private static final String PROPERTY_NAMED_GROUPS = "jdk.tls.namedGroups";
    private final AlgorithmParameters algorithmParameters;
    private final All all;
    private final boolean enabled;
    private static final Logger LOG = Logger.getLogger(NamedGroupInfo.class.getName());
    private static final int[] CANDIDATES_DEFAULT = {29, 30, 23, 24, 25, 31, 32, 33, 256, 257, NamedGroup.ffdhe4096};

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes2.dex */
    public enum All {
        sect163k1(1, "EC"),
        sect163r1(2, "EC"),
        sect163r2(3, "EC"),
        sect193r1(4, "EC"),
        sect193r2(5, "EC"),
        sect233k1(6, "EC"),
        sect233r1(7, "EC"),
        sect239k1(8, "EC"),
        sect283k1(9, "EC"),
        sect283r1(10, "EC"),
        sect409k1(11, "EC"),
        sect409r1(12, "EC"),
        sect571k1(13, "EC"),
        sect571r1(14, "EC"),
        secp160k1(15, "EC"),
        secp160r1(16, "EC"),
        secp160r2(17, "EC"),
        secp192k1(18, "EC"),
        secp192r1(19, "EC"),
        secp224k1(20, "EC"),
        secp224r1(21, "EC"),
        secp256k1(22, "EC"),
        secp256r1(23, "EC"),
        secp384r1(24, "EC"),
        secp521r1(25, "EC"),
        brainpoolP256r1(26, "EC"),
        brainpoolP384r1(27, "EC"),
        brainpoolP512r1(28, "EC"),
        x25519(29, "XDH"),
        x448(30, "XDH"),
        brainpoolP256r1tls13(31, "EC"),
        brainpoolP384r1tls13(32, "EC"),
        brainpoolP512r1tls13(33, "EC"),
        curveSM2(41, "EC"),
        ffdhe2048(256, "DiffieHellman"),
        ffdhe3072(257, "DiffieHellman"),
        ffdhe4096(NamedGroup.ffdhe4096, "DiffieHellman"),
        ffdhe6144(NamedGroup.ffdhe6144, "DiffieHellman"),
        ffdhe8192(NamedGroup.ffdhe8192, "DiffieHellman"),
        OQS_mlkem512(NamedGroup.OQS_mlkem512, "ML-KEM"),
        OQS_mlkem768(NamedGroup.OQS_mlkem768, "ML-KEM"),
        OQS_mlkem1024(NamedGroup.OQS_mlkem1024, "ML-KEM"),
        DRAFT_mlkem768(NamedGroup.DRAFT_mlkem768, "ML-KEM"),
        DRAFT_mlkem1024(NamedGroup.DRAFT_mlkem1024, "ML-KEM");
        
        private final int bitsECDH;
        private final int bitsFFDHE;
        private final boolean char2;
        private final String jcaAlgorithm;
        private final String jcaGroup;
        private final String name;
        private final int namedGroup;
        private final boolean supportedPost13;
        private final boolean supportedPre13;
        private final String text;

        All(int i, String str) {
            this.namedGroup = i;
            this.name = NamedGroup.getName(i);
            this.text = NamedGroup.getText(i);
            this.jcaAlgorithm = str;
            this.jcaGroup = NamedGroup.getStandardName(i);
            this.supportedPost13 = NamedGroup.canBeNegotiated(i, ProtocolVersion.TLSv13);
            this.supportedPre13 = NamedGroup.canBeNegotiated(i, ProtocolVersion.TLSv12);
            this.char2 = NamedGroup.isChar2Curve(i);
            this.bitsECDH = NamedGroup.getCurveBits(i);
            this.bitsFFDHE = NamedGroup.getFiniteFieldBits(i);
        }
    }

    /* loaded from: classes2.dex */
    static class DefaultedResult {
        private final boolean defaulted;
        private final int result;

        DefaultedResult(int i, boolean z) {
            this.result = i;
            this.defaulted = z;
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public int getResult() {
            return this.result;
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public boolean isDefaulted() {
            return this.defaulted;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes2.dex */
    public static class PerConnection {
        private final LinkedHashMap<Integer, NamedGroupInfo> local;
        private final boolean localECDSA;
        private final AtomicReference<List<NamedGroupInfo>> peer;

        PerConnection(LinkedHashMap<Integer, NamedGroupInfo> linkedHashMap, boolean z) {
            if (linkedHashMap == null) {
                throw new NullPointerException("local");
            }
            this.local = linkedHashMap;
            this.localECDSA = z;
            this.peer = new AtomicReference<>();
        }

        List<NamedGroupInfo> getPeer() {
            return this.peer.get();
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public void notifyPeerData(int[] iArr) {
            this.peer.set(NamedGroupInfo.getNamedGroupInfos(this.local, iArr));
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes2.dex */
    public static class PerContext {
        private final int[] candidates;
        private final Map<Integer, NamedGroupInfo> index;

        PerContext(Map<Integer, NamedGroupInfo> map, int[] iArr) {
            this.index = map;
            this.candidates = iArr;
        }
    }

    NamedGroupInfo(All all, AlgorithmParameters algorithmParameters, boolean z) {
        this.all = all;
        this.algorithmParameters = algorithmParameters;
        this.enabled = z;
    }

    private static void addNamedGroup(boolean z, JcaTlsCrypto jcaTlsCrypto, boolean z2, boolean z3, Map<Integer, NamedGroupInfo> map, All all) {
        int i = all.namedGroup;
        if (!z || FipsUtils.isFipsNamedGroup(i)) {
            boolean z4 = false;
            boolean z5 = !(z2 && all.char2) && (!z3 || all.bitsFFDHE <= 0) && all.jcaGroup != null && jcaTlsCrypto.hasNamedGroup(i);
            AlgorithmParameters algorithmParameters = null;
            if (z5) {
                try {
                    algorithmParameters = jcaTlsCrypto.getNamedGroupAlgorithmParameters(i);
                } catch (Exception unused) {
                }
            }
            z4 = z5;
            if (map.put(Integer.valueOf(i), new NamedGroupInfo(all, algorithmParameters, z4)) != null) {
                throw new IllegalStateException("Duplicate entries for NamedGroupInfo");
            }
        }
    }

    private static int[] createCandidates(Map<Integer, NamedGroupInfo> map, String[] strArr, String str) {
        Logger logger;
        StringBuilder append;
        String str2;
        int length = strArr.length;
        int[] iArr = new int[length];
        int i = 0;
        for (String str3 : strArr) {
            int namedGroupByName = getNamedGroupByName(str3);
            if (namedGroupByName < 0) {
                logger = LOG;
                append = new StringBuilder("'").append(str);
                str2 = "' contains unrecognised NamedGroup: ";
            } else {
                NamedGroupInfo namedGroupInfo = map.get(Integer.valueOf(namedGroupByName));
                if (namedGroupInfo == null) {
                    logger = LOG;
                    append = new StringBuilder("'").append(str);
                    str2 = "' contains unsupported NamedGroup: ";
                } else if (namedGroupInfo.isEnabled()) {
                    iArr[i] = namedGroupByName;
                    i++;
                } else {
                    logger = LOG;
                    append = new StringBuilder("'").append(str);
                    str2 = "' contains disabled NamedGroup: ";
                }
            }
            logger.warning(append.append(str2).append(str3).toString());
        }
        if (i < length) {
            iArr = Arrays.copyOf(iArr, i);
        }
        if (iArr.length < 1) {
            LOG.severe("'" + str + "' contained no usable NamedGroup values");
        }
        return iArr;
    }

    private static int[] createCandidatesFromProperty(Map<Integer, NamedGroupInfo> map, String str) {
        String[] stringArraySystemProperty = PropertyUtils.getStringArraySystemProperty(str);
        return stringArraySystemProperty == null ? CANDIDATES_DEFAULT : createCandidates(map, stringArraySystemProperty, str);
    }

    private static Map<Integer, NamedGroupInfo> createIndex(boolean z, JcaTlsCrypto jcaTlsCrypto) {
        TreeMap treeMap = new TreeMap();
        boolean z2 = PropertyUtils.getBooleanSystemProperty("org.bouncycastle.jsse.ec.disableChar2", false) || Properties.isOverrideSet("org.bouncycastle.ec.disable_f2m");
        boolean z3 = !PropertyUtils.getBooleanSystemProperty("jsse.enableFFDHE", true);
        for (All all : All.values()) {
            addNamedGroup(z, jcaTlsCrypto, z2, z3, treeMap, all);
        }
        return treeMap;
    }

    private static PerConnection createPerConnection(PerContext perContext, ProvSSLParameters provSSLParameters, ProtocolVersion protocolVersion, ProtocolVersion protocolVersion2) {
        String[] namedGroups = provSSLParameters.getNamedGroups();
        int[] createCandidates = namedGroups == null ? perContext.candidates : createCandidates(perContext.index, namedGroups, "SSLParameters.namedGroups");
        BCAlgorithmConstraints algorithmConstraints = provSSLParameters.getAlgorithmConstraints();
        boolean isTLSv13 = TlsUtils.isTLSv13(protocolVersion2);
        boolean z = !TlsUtils.isTLSv13(protocolVersion);
        LinkedHashMap linkedHashMap = new LinkedHashMap(createCandidates.length);
        for (int i : createCandidates) {
            Integer valueOf = Integers.valueOf(i);
            NamedGroupInfo namedGroupInfo = (NamedGroupInfo) perContext.index.get(valueOf);
            if (namedGroupInfo != null && namedGroupInfo.isActive(algorithmConstraints, isTLSv13, z)) {
                linkedHashMap.put(valueOf, namedGroupInfo);
            }
        }
        return new PerConnection(linkedHashMap, hasAnyECDSA(linkedHashMap));
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static PerConnection createPerConnectionClient(PerContext perContext, ProvSSLParameters provSSLParameters, ProtocolVersion[] protocolVersionArr) {
        return createPerConnection(perContext, provSSLParameters, ProtocolVersion.getEarliestTLS(protocolVersionArr), ProtocolVersion.getLatestTLS(protocolVersionArr));
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static PerConnection createPerConnectionServer(PerContext perContext, ProvSSLParameters provSSLParameters, ProtocolVersion protocolVersion) {
        return createPerConnection(perContext, provSSLParameters, protocolVersion, protocolVersion);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static PerContext createPerContext(boolean z, JcaTlsCrypto jcaTlsCrypto) {
        Map<Integer, NamedGroupInfo> createIndex = createIndex(z, jcaTlsCrypto);
        return new PerContext(createIndex, createCandidatesFromProperty(createIndex, PROPERTY_NAMED_GROUPS));
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static DefaultedResult getMaximumBitsServerECDH(PerConnection perConnection) {
        int i;
        List<NamedGroupInfo> peer = perConnection.getPeer();
        if (peer != null) {
            i = 0;
            for (NamedGroupInfo namedGroupInfo : peer) {
                int bitsECDH = namedGroupInfo.getBitsECDH();
                if (bitsECDH > i && perConnection.local.containsKey(Integer.valueOf(namedGroupInfo.getNamedGroup()))) {
                    i = bitsECDH;
                }
            }
        } else {
            i = 0;
            for (NamedGroupInfo namedGroupInfo2 : perConnection.local.values()) {
                i = Math.max(i, namedGroupInfo2.getBitsECDH());
            }
        }
        return new DefaultedResult(i, peer == null);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static DefaultedResult getMaximumBitsServerFFDHE(PerConnection perConnection) {
        int i;
        List<NamedGroupInfo> peer = perConnection.getPeer();
        boolean z = false;
        if (peer != null) {
            i = 0;
            for (NamedGroupInfo namedGroupInfo : peer) {
                int namedGroup = namedGroupInfo.getNamedGroup();
                z |= NamedGroup.isFiniteField(namedGroup);
                int bitsFFDHE = namedGroupInfo.getBitsFFDHE();
                if (bitsFFDHE > i && perConnection.local.containsKey(Integer.valueOf(namedGroup))) {
                    i = bitsFFDHE;
                }
            }
        } else {
            i = 0;
        }
        if (!z) {
            for (NamedGroupInfo namedGroupInfo2 : perConnection.local.values()) {
                i = Math.max(i, namedGroupInfo2.getBitsFFDHE());
            }
        }
        return new DefaultedResult(i, !z);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static NamedGroupInfo getNamedGroup(PerContext perContext, int i) {
        return (NamedGroupInfo) perContext.index.get(Integer.valueOf(i));
    }

    private static int getNamedGroupByName(String str) {
        All[] values;
        for (All all : All.values()) {
            if (all.name.equalsIgnoreCase(str)) {
                return all.namedGroup;
            }
        }
        return -1;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static List<NamedGroupInfo> getNamedGroupInfos(Map<Integer, NamedGroupInfo> map, int[] iArr) {
        if (iArr == null) {
            return null;
        }
        if (iArr.length < 1) {
            return Collections.emptyList();
        }
        ArrayList arrayList = new ArrayList(iArr.length);
        for (int i : iArr) {
            NamedGroupInfo namedGroupInfo = map.get(Integer.valueOf(i));
            if (namedGroupInfo != null) {
                arrayList.add(namedGroupInfo);
            }
        }
        if (arrayList.isEmpty()) {
            return Collections.emptyList();
        }
        arrayList.trimToSize();
        return arrayList;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static Vector<Integer> getSupportedGroupsLocalClient(PerConnection perConnection) {
        return new Vector<>(perConnection.local.keySet());
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static int[] getSupportedGroupsLocalServer(PerConnection perConnection) {
        Set<Integer> keySet = perConnection.local.keySet();
        int[] iArr = new int[keySet.size()];
        int i = 0;
        for (Integer num : keySet) {
            iArr[i] = num.intValue();
            i++;
        }
        return iArr;
    }

    private static boolean hasAnyECDSA(Map<Integer, NamedGroupInfo> map) {
        for (NamedGroupInfo namedGroupInfo : map.values()) {
            if (NamedGroup.refersToAnECDSACurve(namedGroupInfo.getNamedGroup())) {
                return true;
            }
        }
        return false;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static boolean hasAnyECDSALocal(PerConnection perConnection) {
        return perConnection.localECDSA;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static boolean hasLocal(PerConnection perConnection, int i) {
        return perConnection.local.containsKey(Integer.valueOf(i));
    }

    private boolean isPermittedBy(BCAlgorithmConstraints bCAlgorithmConstraints) {
        Set<BCCryptoPrimitive> set = JsseUtils.KEY_AGREEMENT_CRYPTO_PRIMITIVES_BC;
        return bCAlgorithmConstraints.permits(set, getJcaGroup(), null) && bCAlgorithmConstraints.permits(set, getJcaAlgorithm(), this.algorithmParameters);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static DefaultedResult selectServerECDH(PerConnection perConnection, int i) {
        List<NamedGroupInfo> peer = perConnection.getPeer();
        if (peer != null) {
            for (NamedGroupInfo namedGroupInfo : peer) {
                if (namedGroupInfo.getBitsECDH() >= i) {
                    int namedGroup = namedGroupInfo.getNamedGroup();
                    if (perConnection.local.containsKey(Integer.valueOf(namedGroup))) {
                        return new DefaultedResult(namedGroup, false);
                    }
                }
            }
        } else {
            for (NamedGroupInfo namedGroupInfo2 : perConnection.local.values()) {
                if (namedGroupInfo2.getBitsECDH() >= i) {
                    return new DefaultedResult(namedGroupInfo2.getNamedGroup(), true);
                }
            }
        }
        return new DefaultedResult(-1, peer == null);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static DefaultedResult selectServerFFDHE(PerConnection perConnection, int i) {
        List<NamedGroupInfo> peer = perConnection.getPeer();
        boolean z = false;
        if (peer != null) {
            boolean z2 = false;
            for (NamedGroupInfo namedGroupInfo : peer) {
                int namedGroup = namedGroupInfo.getNamedGroup();
                z2 |= NamedGroup.isFiniteField(namedGroup);
                if (namedGroupInfo.getBitsFFDHE() >= i && perConnection.local.containsKey(Integer.valueOf(namedGroup))) {
                    return new DefaultedResult(namedGroup, false);
                }
            }
            z = z2;
        }
        if (!z) {
            for (NamedGroupInfo namedGroupInfo2 : perConnection.local.values()) {
                if (namedGroupInfo2.getBitsFFDHE() >= i) {
                    return new DefaultedResult(namedGroupInfo2.getNamedGroup(), true);
                }
            }
        }
        return new DefaultedResult(-1, !z);
    }

    int getBitsECDH() {
        return this.all.bitsECDH;
    }

    int getBitsFFDHE() {
        return this.all.bitsFFDHE;
    }

    String getJcaAlgorithm() {
        return this.all.jcaAlgorithm;
    }

    String getJcaGroup() {
        return this.all.jcaGroup;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getNamedGroup() {
        return this.all.namedGroup;
    }

    boolean isActive(BCAlgorithmConstraints bCAlgorithmConstraints, boolean z, boolean z2) {
        return this.enabled && ((z && isSupportedPost13()) || (z2 && isSupportedPre13())) && isPermittedBy(bCAlgorithmConstraints);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean isEnabled() {
        return this.enabled;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean isSupportedPost13() {
        return this.all.supportedPost13;
    }

    boolean isSupportedPre13() {
        return this.all.supportedPre13;
    }

    public String toString() {
        return this.all.text;
    }
}