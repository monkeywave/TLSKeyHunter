package org.openjsse.sun.security.ssl;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.AlgorithmConstraints;
import java.security.AlgorithmParameters;
import java.security.CryptoPrimitive;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import javassist.bytecode.AccessFlag;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;
import javax.net.ssl.SSLProtocolException;
import org.bouncycastle.jcajce.spec.XDHParameterSpec;
import org.openjsse.sun.security.ssl.SSLExtension;
import org.openjsse.sun.security.ssl.SSLHandshake;
import org.openjsse.sun.security.util.CurveDB;
import sun.security.action.GetPropertyAction;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SupportedGroupsExtension.class */
final class SupportedGroupsExtension {
    static final HandshakeProducer chNetworkProducer = new CHSupportedGroupsProducer();
    static final SSLExtension.ExtensionConsumer chOnLoadConsumer = new CHSupportedGroupsConsumer();
    static final HandshakeAbsence chOnTradAbsence = new CHSupportedGroupsOnTradeAbsence();
    static final SSLStringizer sgsStringizer = new SupportedGroupsStringizer();
    static final HandshakeProducer eeNetworkProducer = new EESupportedGroupsProducer();
    static final SSLExtension.ExtensionConsumer eeOnLoadConsumer = new EESupportedGroupsConsumer();

    SupportedGroupsExtension() {
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SupportedGroupsExtension$SupportedGroupsSpec.class */
    static final class SupportedGroupsSpec implements SSLExtension.SSLExtensionSpec {
        final int[] namedGroupsIds;

        private SupportedGroupsSpec(int[] namedGroupsIds) {
            this.namedGroupsIds = namedGroupsIds;
        }

        private SupportedGroupsSpec(List<NamedGroup> namedGroups) {
            this.namedGroupsIds = new int[namedGroups.size()];
            int i = 0;
            for (NamedGroup ng : namedGroups) {
                int i2 = i;
                i++;
                this.namedGroupsIds[i2] = ng.f1009id;
            }
        }

        private SupportedGroupsSpec(ByteBuffer m) throws IOException {
            if (m.remaining() < 2) {
                throw new SSLProtocolException("Invalid supported_groups extension: insufficient data");
            }
            byte[] ngs = Record.getBytes16(m);
            if (m.hasRemaining()) {
                throw new SSLProtocolException("Invalid supported_groups extension: unknown extra data");
            }
            if (ngs == null || ngs.length == 0 || ngs.length % 2 != 0) {
                throw new SSLProtocolException("Invalid supported_groups extension: incomplete data");
            }
            int[] ids = new int[ngs.length / 2];
            int i = 0;
            int j = 0;
            while (i < ngs.length) {
                int i2 = j;
                j++;
                int i3 = i;
                int i4 = i + 1;
                i = i4 + 1;
                ids[i2] = ((ngs[i3] & 255) << 8) | (ngs[i4] & 255);
            }
            this.namedGroupsIds = ids;
        }

        public String toString() {
            int[] iArr;
            MessageFormat messageFormat = new MessageFormat("\"versions\": '['{0}']'", Locale.ENGLISH);
            if (this.namedGroupsIds == null || this.namedGroupsIds.length == 0) {
                Object[] messageFields = {"<no supported named group specified>"};
                return messageFormat.format(messageFields);
            }
            StringBuilder builder = new StringBuilder(512);
            boolean isFirst = true;
            for (int ngid : this.namedGroupsIds) {
                if (isFirst) {
                    isFirst = false;
                } else {
                    builder.append(", ");
                }
                builder.append(NamedGroup.nameOf(ngid));
            }
            Object[] messageFields2 = {builder.toString()};
            return messageFormat.format(messageFields2);
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SupportedGroupsExtension$SupportedGroupsStringizer.class */
    private static final class SupportedGroupsStringizer implements SSLStringizer {
        private SupportedGroupsStringizer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLStringizer
        public String toString(ByteBuffer buffer) {
            try {
                return new SupportedGroupsSpec(buffer).toString();
            } catch (IOException ioe) {
                return ioe.getMessage();
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SupportedGroupsExtension$NamedGroupType.class */
    public enum NamedGroupType {
        NAMED_GROUP_ECDHE("EC"),
        NAMED_GROUP_FFDHE("DiffieHellman"),
        NAMED_GROUP_XDH("XDH"),
        NAMED_GROUP_ARBITRARY("EC"),
        NAMED_GROUP_NONE("");
        
        private final String algorithm;

        NamedGroupType(String algorithm) {
            this.algorithm = algorithm;
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        /* JADX WARN: Removed duplicated region for block: B:5:0x0010  */
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct code enable 'Show inconsistent code' option in preferences
        */
        public boolean isSupported(java.util.List<org.openjsse.sun.security.ssl.CipherSuite> r4) {
            /*
                r3 = this;
                r0 = r4
                java.util.Iterator r0 = r0.iterator()
                r5 = r0
            L7:
                r0 = r5
                boolean r0 = r0.hasNext()
                if (r0 == 0) goto L31
                r0 = r5
                java.lang.Object r0 = r0.next()
                org.openjsse.sun.security.ssl.CipherSuite r0 = (org.openjsse.sun.security.ssl.CipherSuite) r0
                r6 = r0
                r0 = r6
                org.openjsse.sun.security.ssl.CipherSuite$KeyExchange r0 = r0.keyExchange
                if (r0 == 0) goto L2c
                r0 = r6
                org.openjsse.sun.security.ssl.CipherSuite$KeyExchange r0 = r0.keyExchange
                org.openjsse.sun.security.ssl.SupportedGroupsExtension$NamedGroupType r0 = r0.groupType
                r1 = r3
                if (r0 != r1) goto L2e
            L2c:
                r0 = 1
                return r0
            L2e:
                goto L7
            L31:
                r0 = 0
                return r0
            */
            throw new UnsupportedOperationException("Method not decompiled: org.openjsse.sun.security.ssl.SupportedGroupsExtension.NamedGroupType.isSupported(java.util.List):boolean");
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SupportedGroupsExtension$NamedGroup.class */
    public enum NamedGroup {
        SECT163_K1(1, "sect163k1", "1.3.132.0.1", true, ProtocolVersion.PROTOCOLS_TO_12),
        SECT163_R1(2, "sect163r1", "1.3.132.0.2", false, ProtocolVersion.PROTOCOLS_TO_12),
        SECT163_R2(3, "sect163r2", "1.3.132.0.15", true, ProtocolVersion.PROTOCOLS_TO_12),
        SECT193_R1(4, "sect193r1", "1.3.132.0.24", false, ProtocolVersion.PROTOCOLS_TO_12),
        SECT193_R2(5, "sect193r2", "1.3.132.0.25", false, ProtocolVersion.PROTOCOLS_TO_12),
        SECT233_K1(6, "sect233k1", "1.3.132.0.26", true, ProtocolVersion.PROTOCOLS_TO_12),
        SECT233_R1(7, "sect233r1", "1.3.132.0.27", true, ProtocolVersion.PROTOCOLS_TO_12),
        SECT239_K1(8, "sect239k1", "1.3.132.0.3", false, ProtocolVersion.PROTOCOLS_TO_12),
        SECT283_K1(9, "sect283k1", "1.3.132.0.16", true, ProtocolVersion.PROTOCOLS_TO_12),
        SECT283_R1(10, "sect283r1", "1.3.132.0.17", true, ProtocolVersion.PROTOCOLS_TO_12),
        SECT409_K1(11, "sect409k1", "1.3.132.0.36", true, ProtocolVersion.PROTOCOLS_TO_12),
        SECT409_R1(12, "sect409r1", "1.3.132.0.37", true, ProtocolVersion.PROTOCOLS_TO_12),
        SECT571_K1(13, "sect571k1", "1.3.132.0.38", true, ProtocolVersion.PROTOCOLS_TO_12),
        SECT571_R1(14, "sect571r1", "1.3.132.0.39", true, ProtocolVersion.PROTOCOLS_TO_12),
        SECP160_K1(15, "secp160k1", "1.3.132.0.9", false, ProtocolVersion.PROTOCOLS_TO_12),
        SECP160_R1(16, "secp160r1", "1.3.132.0.8", false, ProtocolVersion.PROTOCOLS_TO_12),
        SECP160_R2(17, "secp160r2", "1.3.132.0.30", false, ProtocolVersion.PROTOCOLS_TO_12),
        SECP192_K1(18, "secp192k1", "1.3.132.0.31", false, ProtocolVersion.PROTOCOLS_TO_12),
        SECP192_R1(19, "secp192r1", "1.2.840.10045.3.1.1", true, ProtocolVersion.PROTOCOLS_TO_12),
        SECP224_K1(20, "secp224k1", "1.3.132.0.32", false, ProtocolVersion.PROTOCOLS_TO_12),
        SECP224_R1(21, "secp224r1", "1.3.132.0.33", true, ProtocolVersion.PROTOCOLS_TO_12),
        SECP256_K1(22, "secp256k1", "1.3.132.0.10", false, ProtocolVersion.PROTOCOLS_TO_12),
        SECP256_R1(23, "secp256r1", "1.2.840.10045.3.1.7", true, ProtocolVersion.PROTOCOLS_TO_13),
        SECP384_R1(24, "secp384r1", "1.3.132.0.34", true, ProtocolVersion.PROTOCOLS_TO_13),
        SECP521_R1(25, "secp521r1", "1.3.132.0.35", true, ProtocolVersion.PROTOCOLS_TO_13),
        X25519(29, "x25519", true, "x25519", ProtocolVersion.PROTOCOLS_TO_13, NamedParameterSpec.X25519),
        X448(30, "x448", true, "x448", ProtocolVersion.PROTOCOLS_TO_13, NamedParameterSpec.X448),
        FFDHE_2048(256, "ffdhe2048", true, ProtocolVersion.PROTOCOLS_TO_13, (AlgorithmParameterSpec) PredefinedDHParameterSpecs.ffdheParams.get(2048)),
        FFDHE_3072(257, "ffdhe3072", true, ProtocolVersion.PROTOCOLS_TO_13, (AlgorithmParameterSpec) PredefinedDHParameterSpecs.ffdheParams.get(3072)),
        FFDHE_4096(258, "ffdhe4096", true, ProtocolVersion.PROTOCOLS_TO_13, (AlgorithmParameterSpec) PredefinedDHParameterSpecs.ffdheParams.get(Integer.valueOf((int) AccessFlag.SYNTHETIC))),
        FFDHE_6144(259, "ffdhe6144", true, ProtocolVersion.PROTOCOLS_TO_13, (AlgorithmParameterSpec) PredefinedDHParameterSpecs.ffdheParams.get(6144)),
        FFDHE_8192(260, "ffdhe8192", true, ProtocolVersion.PROTOCOLS_TO_13, (AlgorithmParameterSpec) PredefinedDHParameterSpecs.ffdheParams.get(8192)),
        ARBITRARY_PRIME(65281, "arbitrary_explicit_prime_curves", ProtocolVersion.PROTOCOLS_TO_12),
        ARBITRARY_CHAR2(65282, "arbitrary_explicit_char2_curves", ProtocolVersion.PROTOCOLS_TO_12);
        

        /* renamed from: id */
        final int f1009id;
        final NamedGroupType type;
        final String name;
        final String oid;
        final String algorithm;
        final boolean isFips;
        final ProtocolVersion[] supportedProtocols;
        final AlgorithmParameterSpec keAlgParamSpec;
        AlgorithmParameters keAlgParams;
        boolean isAvailable;

        NamedGroup(int id, NamedGroupType type, String name, String oid, String algorithm, boolean isFips, ProtocolVersion[] supportedProtocols, AlgorithmParameterSpec keAlgParamSpec) {
            this.f1009id = id;
            this.type = type;
            this.name = name;
            this.oid = oid;
            this.algorithm = algorithm;
            this.isFips = isFips;
            this.supportedProtocols = supportedProtocols;
            this.keAlgParamSpec = keAlgParamSpec;
            boolean mediator = keAlgParamSpec != null;
            if (mediator && type == NamedGroupType.NAMED_GROUP_ECDHE) {
                mediator = JsseJce.isEcAvailable();
            }
            if (mediator) {
                try {
                    AlgorithmParameters algParams = AlgorithmParameters.getInstance(type.algorithm);
                    algParams.init(keAlgParamSpec);
                } catch (NoSuchAlgorithmException | InvalidParameterSpecException exp) {
                    if (type != NamedGroupType.NAMED_GROUP_XDH) {
                        mediator = false;
                        if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                            SSLLogger.warning("No AlgorithmParameters for " + name, exp);
                        }
                    } else {
                        try {
                            KeyAgreement.getInstance(name);
                        } catch (NoSuchAlgorithmException nsae) {
                            mediator = false;
                            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                                SSLLogger.warning("No AlgorithmParameters for " + name, nsae);
                            }
                        }
                    }
                }
            }
            this.isAvailable = mediator;
        }

        NamedGroup(int id, String name, String oid, boolean isFips, ProtocolVersion[] supportedProtocols) {
            this(id, NamedGroupType.NAMED_GROUP_ECDHE, name, oid, "EC", isFips, supportedProtocols, CurveDB.lookup(name));
        }

        NamedGroup(int id, String name, boolean isFips, String algorithm, ProtocolVersion[] supportedProtocols, AlgorithmParameterSpec keAlgParamSpec) {
            this(id, NamedGroupType.NAMED_GROUP_XDH, name, null, algorithm, isFips, supportedProtocols, keAlgParamSpec);
        }

        NamedGroup(int id, String name, boolean isFips, ProtocolVersion[] supportedProtocols, AlgorithmParameterSpec keAlgParamSpec) {
            this(id, NamedGroupType.NAMED_GROUP_FFDHE, name, null, "DiffieHellman", isFips, supportedProtocols, keAlgParamSpec);
        }

        NamedGroup(int id, String name, ProtocolVersion[] supportedProtocols) {
            this(id, NamedGroupType.NAMED_GROUP_ARBITRARY, name, null, "EC", false, supportedProtocols, null);
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public static NamedGroup valueOf(int id) {
            NamedGroup[] values;
            for (NamedGroup group : values()) {
                if (group.f1009id == id) {
                    return group;
                }
            }
            return null;
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public static NamedGroup valueOf(ECParameterSpec params) {
            NamedGroup[] values;
            for (NamedGroup ng : values()) {
                if (ng.type == NamedGroupType.NAMED_GROUP_ECDHE && (params == ng.keAlgParamSpec || ng.keAlgParamSpec == CurveDB.lookup(params))) {
                    return ng;
                }
            }
            return null;
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public static NamedGroup valueOf(DHParameterSpec params) {
            NamedGroup[] values;
            for (NamedGroup ng : values()) {
                if (ng.type == NamedGroupType.NAMED_GROUP_FFDHE) {
                    DHParameterSpec ngParams = (DHParameterSpec) ng.keAlgParamSpec;
                    if (ngParams.getP().equals(params.getP()) && ngParams.getG().equals(params.getG())) {
                        return ng;
                    }
                }
            }
            return null;
        }

        static NamedGroup nameOf(String name) {
            NamedGroup[] values;
            for (NamedGroup group : values()) {
                if (group.name.equals(name)) {
                    return group;
                }
            }
            return null;
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public static String nameOf(int id) {
            NamedGroup[] values;
            for (NamedGroup group : values()) {
                if (group.f1009id == id) {
                    return group.name;
                }
            }
            return "UNDEFINED-NAMED-GROUP(" + id + ")";
        }

        boolean isAvailable(List<ProtocolVersion> protocolVersions) {
            ProtocolVersion[] protocolVersionArr;
            if (this.isAvailable) {
                for (ProtocolVersion pv : this.supportedProtocols) {
                    if (protocolVersions.contains(pv)) {
                        return true;
                    }
                }
                return false;
            }
            return false;
        }

        boolean isAvailable(ProtocolVersion protocolVersion) {
            ProtocolVersion[] protocolVersionArr;
            if (this.isAvailable) {
                for (ProtocolVersion pv : this.supportedProtocols) {
                    if (protocolVersion == pv) {
                        return true;
                    }
                }
                return false;
            }
            return false;
        }

        boolean isSupported(List<CipherSuite> cipherSuites) {
            for (CipherSuite cs : cipherSuites) {
                boolean isMatch = isAvailable(cs.supportedProtocols);
                if (isMatch && (cs.keyExchange == null || cs.keyExchange.groupType == this.type)) {
                    return true;
                }
            }
            return false;
        }

        AlgorithmParameters getParameters() {
            return SupportedGroups.namedGroupParams.get(this);
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public AlgorithmParameterSpec getParameterSpec() {
            if (this.type == NamedGroupType.NAMED_GROUP_ECDHE) {
                return SupportedGroups.getECGenParamSpec(this);
            }
            if (this.type == NamedGroupType.NAMED_GROUP_FFDHE) {
                return SupportedGroups.getDHParameterSpec(this);
            }
            return null;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SupportedGroupsExtension$SupportedGroups.class */
    public static class SupportedGroups {
        static final boolean enableFFDHE = Utilities.getBooleanProperty("jsse.enableFFDHE", true);
        static final Map<NamedGroup, AlgorithmParameters> namedGroupParams = new HashMap();
        static final NamedGroup[] supportedNamedGroups;

        SupportedGroups() {
        }

        static {
            ArrayList<NamedGroup> groupList;
            NamedGroup[] namedGroupArr;
            NamedGroup namedGroup;
            boolean requireFips = OpenJSSE.isFIPS();
            String property = GetPropertyAction.privilegedGetProperty("jdk.tls.namedGroups");
            if (property != null && property.length() != 0 && property.length() > 1 && property.charAt(0) == '\"' && property.charAt(property.length() - 1) == '\"') {
                property = property.substring(1, property.length() - 1);
            }
            if (property != null && property.length() != 0) {
                String[] groups = property.split(",");
                groupList = new ArrayList<>(groups.length);
                for (String group : groups) {
                    String group2 = group.trim();
                    if (!group2.isEmpty() && (namedGroup = NamedGroup.nameOf(group2)) != null && ((!requireFips || namedGroup.isFips) && isAvailableGroup(namedGroup))) {
                        groupList.add(namedGroup);
                    }
                }
                if (groupList.isEmpty()) {
                    throw new IllegalArgumentException("System property jdk.tls.namedGroups(" + property + ") contains no supported named groups");
                }
            } else {
                NamedGroup[] groups2 = requireFips ? new NamedGroup[]{NamedGroup.SECP256_R1, NamedGroup.SECP384_R1, NamedGroup.SECP521_R1, NamedGroup.FFDHE_2048, NamedGroup.FFDHE_3072, NamedGroup.FFDHE_4096, NamedGroup.FFDHE_6144, NamedGroup.FFDHE_8192} : new NamedGroup[]{NamedGroup.SECP256_R1, NamedGroup.SECP384_R1, NamedGroup.SECP521_R1, NamedGroup.FFDHE_2048, NamedGroup.FFDHE_3072, NamedGroup.FFDHE_4096, NamedGroup.FFDHE_6144, NamedGroup.FFDHE_8192};
                groupList = new ArrayList<>(groups2.length);
                for (NamedGroup group3 : groups2) {
                    if (isAvailableGroup(group3)) {
                        groupList.add(group3);
                    }
                }
                if (groupList.isEmpty() && SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                    SSLLogger.warning("No default named groups", new Object[0]);
                }
            }
            supportedNamedGroups = new NamedGroup[groupList.size()];
            int i = 0;
            Iterator<NamedGroup> it = groupList.iterator();
            while (it.hasNext()) {
                int i2 = i;
                i++;
                supportedNamedGroups[i2] = it.next();
            }
        }

        private static boolean isAvailableGroup(NamedGroup namedGroup) {
            AlgorithmParameters params = null;
            AlgorithmParameterSpec spec = null;
            if (namedGroup.type == NamedGroupType.NAMED_GROUP_ECDHE) {
                if (namedGroup.oid != null) {
                    try {
                        params = JsseJce.getAlgorithmParameters("EC");
                        spec = new ECGenParameterSpec(namedGroup.oid);
                    } catch (NoSuchAlgorithmException e) {
                        return false;
                    }
                }
            } else if (namedGroup.type == NamedGroupType.NAMED_GROUP_FFDHE) {
                try {
                    params = JsseJce.getAlgorithmParameters("DiffieHellman");
                    spec = getFFDHEDHParameterSpec(namedGroup);
                } catch (NoSuchAlgorithmException e2) {
                    return false;
                }
            }
            if (params != null && spec != null) {
                try {
                    params.init(spec);
                    namedGroupParams.put(namedGroup, params);
                    return true;
                } catch (InvalidParameterSpecException e3) {
                    return false;
                }
            }
            return false;
        }

        private static DHParameterSpec getFFDHEDHParameterSpec(NamedGroup namedGroup) {
            DHParameterSpec spec = null;
            switch (namedGroup) {
                case FFDHE_2048:
                    spec = PredefinedDHParameterSpecs.ffdheParams.get(2048);
                    break;
                case FFDHE_3072:
                    spec = PredefinedDHParameterSpecs.ffdheParams.get(3072);
                    break;
                case FFDHE_4096:
                    spec = PredefinedDHParameterSpecs.ffdheParams.get(Integer.valueOf((int) AccessFlag.SYNTHETIC));
                    break;
                case FFDHE_6144:
                    spec = PredefinedDHParameterSpecs.ffdheParams.get(6144);
                    break;
                case FFDHE_8192:
                    spec = PredefinedDHParameterSpecs.ffdheParams.get(8192);
                    break;
            }
            return spec;
        }

        private static DHParameterSpec getPredefinedDHParameterSpec(NamedGroup namedGroup) {
            DHParameterSpec spec = null;
            switch (namedGroup) {
                case FFDHE_2048:
                    spec = PredefinedDHParameterSpecs.definedParams.get(2048);
                    break;
                case FFDHE_3072:
                    spec = PredefinedDHParameterSpecs.definedParams.get(3072);
                    break;
                case FFDHE_4096:
                    spec = PredefinedDHParameterSpecs.definedParams.get(Integer.valueOf((int) AccessFlag.SYNTHETIC));
                    break;
                case FFDHE_6144:
                    spec = PredefinedDHParameterSpecs.definedParams.get(6144);
                    break;
                case FFDHE_8192:
                    spec = PredefinedDHParameterSpecs.definedParams.get(8192);
                    break;
            }
            return spec;
        }

        static ECGenParameterSpec getECGenParamSpec(NamedGroup namedGroup) {
            if (namedGroup.type != NamedGroupType.NAMED_GROUP_ECDHE) {
                throw new RuntimeException("Not a named EC group: " + namedGroup);
            }
            AlgorithmParameters params = namedGroupParams.get(namedGroup);
            if (params == null) {
                throw new RuntimeException("Not a supported EC named group: " + namedGroup);
            }
            try {
                return (ECGenParameterSpec) params.getParameterSpec(ECGenParameterSpec.class);
            } catch (InvalidParameterSpecException e) {
                return new ECGenParameterSpec(namedGroup.oid);
            }
        }

        static DHParameterSpec getDHParameterSpec(NamedGroup namedGroup) {
            if (namedGroup.type != NamedGroupType.NAMED_GROUP_FFDHE) {
                throw new RuntimeException("Not a named DH group: " + namedGroup);
            }
            AlgorithmParameters params = namedGroupParams.get(namedGroup);
            if (params == null) {
                throw new RuntimeException("Not a supported DH named group: " + namedGroup);
            }
            try {
                return (DHParameterSpec) params.getParameterSpec(DHParameterSpec.class);
            } catch (InvalidParameterSpecException e) {
                return getPredefinedDHParameterSpec(namedGroup);
            }
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public static boolean isActivatable(AlgorithmConstraints constraints, NamedGroupType type) {
            NamedGroup[] namedGroupArr;
            boolean hasFFDHEGroups = false;
            for (NamedGroup namedGroup : supportedNamedGroups) {
                if (namedGroup.type == type) {
                    if (constraints.permits(EnumSet.of(CryptoPrimitive.KEY_AGREEMENT), namedGroup.algorithm, namedGroupParams.get(namedGroup))) {
                        return true;
                    }
                    if (!hasFFDHEGroups && type == NamedGroupType.NAMED_GROUP_FFDHE) {
                        hasFFDHEGroups = true;
                    }
                }
            }
            return !hasFFDHEGroups && type == NamedGroupType.NAMED_GROUP_FFDHE;
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public static boolean isActivatable(AlgorithmConstraints constraints, NamedGroup namedGroup) {
            if (!isSupported(namedGroup)) {
                return false;
            }
            return constraints.permits(EnumSet.of(CryptoPrimitive.KEY_AGREEMENT), namedGroup.algorithm, namedGroupParams.get(namedGroup));
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public static boolean isSupported(NamedGroup namedGroup) {
            NamedGroup[] namedGroupArr;
            for (NamedGroup group : supportedNamedGroups) {
                if (namedGroup.f1009id == group.f1009id) {
                    return true;
                }
            }
            return false;
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public static NamedGroup getPreferredGroup(ProtocolVersion negotiatedProtocol, AlgorithmConstraints constraints, NamedGroupType type, List<NamedGroup> requestedNamedGroups) {
            for (NamedGroup namedGroup : requestedNamedGroups) {
                if (namedGroup.type == type && namedGroup.isAvailable(negotiatedProtocol) && isSupported(namedGroup) && constraints.permits(EnumSet.of(CryptoPrimitive.KEY_AGREEMENT), namedGroup.algorithm, namedGroupParams.get(namedGroup))) {
                    return namedGroup;
                }
            }
            return null;
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public static NamedGroup getPreferredGroup(ProtocolVersion negotiatedProtocol, AlgorithmConstraints constraints, NamedGroupType type) {
            NamedGroup[] namedGroupArr;
            for (NamedGroup namedGroup : supportedNamedGroups) {
                if (namedGroup.type == type && namedGroup.isAvailable(negotiatedProtocol) && constraints.permits(EnumSet.of(CryptoPrimitive.KEY_AGREEMENT), namedGroup.algorithm, namedGroupParams.get(namedGroup))) {
                    return namedGroup;
                }
            }
            return null;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SupportedGroupsExtension$CHSupportedGroupsProducer.class */
    private static final class CHSupportedGroupsProducer extends SupportedGroups implements HandshakeProducer {
        private CHSupportedGroupsProducer() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeProducer
        public byte[] produce(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            NamedGroup[] namedGroupArr;
            ClientHandshakeContext chc = (ClientHandshakeContext) context;
            if (!chc.sslConfig.isAvailable(SSLExtension.CH_SUPPORTED_GROUPS)) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("Ignore unavailable supported_groups extension", new Object[0]);
                    return null;
                }
                return null;
            }
            ArrayList<NamedGroup> namedGroups = new ArrayList<>(SupportedGroups.supportedNamedGroups.length);
            for (NamedGroup ng : SupportedGroups.supportedNamedGroups) {
                if (SupportedGroups.enableFFDHE || ng.type != NamedGroupType.NAMED_GROUP_FFDHE) {
                    if (ng.isAvailable(chc.activeProtocols) && ng.isSupported(chc.activeCipherSuites) && chc.algorithmConstraints.permits(EnumSet.of(CryptoPrimitive.KEY_AGREEMENT), ng.algorithm, namedGroupParams.get(ng))) {
                        namedGroups.add(ng);
                    } else if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                        SSLLogger.fine("Ignore inactive or disabled named group: " + ng.name, new Object[0]);
                    }
                }
            }
            if (namedGroups.isEmpty()) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.warning("no available named group", new Object[0]);
                    return null;
                }
                return null;
            }
            int vectorLen = namedGroups.size() << 1;
            byte[] extData = new byte[vectorLen + 2];
            ByteBuffer m = ByteBuffer.wrap(extData);
            Record.putInt16(m, vectorLen);
            Iterator<NamedGroup> it = namedGroups.iterator();
            while (it.hasNext()) {
                NamedGroup namedGroup = it.next();
                Record.putInt16(m, namedGroup.f1009id);
            }
            chc.clientRequestedNamedGroups = Collections.unmodifiableList(namedGroups);
            chc.handshakeExtensions.put(SSLExtension.CH_SUPPORTED_GROUPS, new SupportedGroupsSpec(namedGroups));
            return extData;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SupportedGroupsExtension$CHSupportedGroupsConsumer.class */
    private static final class CHSupportedGroupsConsumer implements SSLExtension.ExtensionConsumer {
        private CHSupportedGroupsConsumer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLExtension.ExtensionConsumer
        public void consume(ConnectionContext context, SSLHandshake.HandshakeMessage message, ByteBuffer buffer) throws IOException {
            int[] iArr;
            ServerHandshakeContext shc = (ServerHandshakeContext) context;
            if (!shc.sslConfig.isAvailable(SSLExtension.CH_SUPPORTED_GROUPS)) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("Ignore unavailable supported_groups extension", new Object[0]);
                    return;
                }
                return;
            }
            try {
                SupportedGroupsSpec spec = new SupportedGroupsSpec(buffer);
                List<NamedGroup> knownNamedGroups = new LinkedList<>();
                for (int id : spec.namedGroupsIds) {
                    NamedGroup ng = NamedGroup.valueOf(id);
                    if (ng != null) {
                        knownNamedGroups.add(ng);
                    }
                }
                shc.clientRequestedNamedGroups = knownNamedGroups;
                shc.handshakeExtensions.put(SSLExtension.CH_SUPPORTED_GROUPS, spec);
            } catch (IOException ioe) {
                throw shc.conContext.fatal(Alert.UNEXPECTED_MESSAGE, ioe);
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SupportedGroupsExtension$CHSupportedGroupsOnTradeAbsence.class */
    private static final class CHSupportedGroupsOnTradeAbsence implements HandshakeAbsence {
        private CHSupportedGroupsOnTradeAbsence() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeAbsence
        public void absent(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            ServerHandshakeContext shc = (ServerHandshakeContext) context;
            if (shc.negotiatedProtocol.useTLS13PlusSpec() && shc.handshakeExtensions.containsKey(SSLExtension.CH_KEY_SHARE)) {
                throw shc.conContext.fatal(Alert.MISSING_EXTENSION, "No supported_groups extension to work with the key_share extension");
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SupportedGroupsExtension$EESupportedGroupsProducer.class */
    private static final class EESupportedGroupsProducer extends SupportedGroups implements HandshakeProducer {
        private EESupportedGroupsProducer() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeProducer
        public byte[] produce(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            NamedGroup[] namedGroupArr;
            ServerHandshakeContext shc = (ServerHandshakeContext) context;
            if (!shc.sslConfig.isAvailable(SSLExtension.EE_SUPPORTED_GROUPS)) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("Ignore unavailable supported_groups extension", new Object[0]);
                    return null;
                }
                return null;
            }
            ArrayList<NamedGroup> namedGroups = new ArrayList<>(SupportedGroups.supportedNamedGroups.length);
            for (NamedGroup ng : SupportedGroups.supportedNamedGroups) {
                if (SupportedGroups.enableFFDHE || ng.type != NamedGroupType.NAMED_GROUP_FFDHE) {
                    if (ng.isAvailable(shc.activeProtocols) && ng.isSupported(shc.activeCipherSuites) && shc.algorithmConstraints.permits(EnumSet.of(CryptoPrimitive.KEY_AGREEMENT), ng.algorithm, namedGroupParams.get(ng))) {
                        namedGroups.add(ng);
                    } else if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                        SSLLogger.fine("Ignore inactive or disabled named group: " + ng.name, new Object[0]);
                    }
                }
            }
            if (namedGroups.isEmpty()) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.warning("no available named group", new Object[0]);
                    return null;
                }
                return null;
            }
            int vectorLen = namedGroups.size() << 1;
            byte[] extData = new byte[vectorLen + 2];
            ByteBuffer m = ByteBuffer.wrap(extData);
            Record.putInt16(m, vectorLen);
            Iterator<NamedGroup> it = namedGroups.iterator();
            while (it.hasNext()) {
                NamedGroup namedGroup = it.next();
                Record.putInt16(m, namedGroup.f1009id);
            }
            shc.conContext.serverRequestedNamedGroups = Collections.unmodifiableList(namedGroups);
            SupportedGroupsSpec spec = new SupportedGroupsSpec(namedGroups);
            shc.handshakeExtensions.put(SSLExtension.EE_SUPPORTED_GROUPS, spec);
            return extData;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SupportedGroupsExtension$EESupportedGroupsConsumer.class */
    private static final class EESupportedGroupsConsumer implements SSLExtension.ExtensionConsumer {
        private EESupportedGroupsConsumer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLExtension.ExtensionConsumer
        public void consume(ConnectionContext context, SSLHandshake.HandshakeMessage message, ByteBuffer buffer) throws IOException {
            int[] iArr;
            ClientHandshakeContext chc = (ClientHandshakeContext) context;
            if (!chc.sslConfig.isAvailable(SSLExtension.EE_SUPPORTED_GROUPS)) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("Ignore unavailable supported_groups extension", new Object[0]);
                    return;
                }
                return;
            }
            try {
                SupportedGroupsSpec spec = new SupportedGroupsSpec(buffer);
                List<NamedGroup> knownNamedGroups = new ArrayList<>(spec.namedGroupsIds.length);
                for (int id : spec.namedGroupsIds) {
                    NamedGroup ng = NamedGroup.valueOf(id);
                    if (ng != null) {
                        knownNamedGroups.add(ng);
                    }
                }
                chc.conContext.serverRequestedNamedGroups = knownNamedGroups;
                chc.handshakeExtensions.put(SSLExtension.EE_SUPPORTED_GROUPS, spec);
            } catch (IOException ioe) {
                throw chc.conContext.fatal(Alert.UNEXPECTED_MESSAGE, ioe);
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SupportedGroupsExtension$NamedParameterSpec.class */
    static class NamedParameterSpec implements AlgorithmParameterSpec {
        public static final NamedParameterSpec X25519 = new NamedParameterSpec(XDHParameterSpec.X25519);
        public static final NamedParameterSpec X448 = new NamedParameterSpec(XDHParameterSpec.X448);
        private String name;

        public NamedParameterSpec(String stdName) {
            this.name = stdName;
        }

        public String getName() {
            return this.name;
        }
    }
}