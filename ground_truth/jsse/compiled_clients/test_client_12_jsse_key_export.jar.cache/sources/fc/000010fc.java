package org.openjsse.sun.security.ssl;

import java.security.CryptoPrimitive;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import org.bouncycastle.pqc.crypto.rainbow.util.GF2Field;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/ProtocolVersion.class */
public enum ProtocolVersion {
    TLS13(772, "TLSv1.3", false),
    TLS12(771, "TLSv1.2", false),
    TLS11(770, "TLSv1.1", false),
    TLS10(769, "TLSv1", false),
    SSL30(768, "SSLv3", false),
    SSL20Hello(2, "SSLv2Hello", false),
    DTLS12(65277, "DTLSv1.2", true),
    DTLS10(65279, "DTLSv1.0", true),
    NONE(-1, "NONE", false);
    

    /* renamed from: id */
    final int f978id;
    final String name;
    final boolean isDTLS;
    final byte major;
    final byte minor;
    final boolean isAvailable;
    static final int LIMIT_MAX_VALUE = 65535;
    static final int LIMIT_MIN_VALUE = 0;
    static final ProtocolVersion[] PROTOCOLS_TO_10 = {TLS10, SSL30};
    static final ProtocolVersion[] PROTOCOLS_TO_11 = {TLS11, TLS10, SSL30, DTLS10};
    static final ProtocolVersion[] PROTOCOLS_TO_12 = {TLS12, TLS11, TLS10, SSL30, DTLS12, DTLS10};
    static final ProtocolVersion[] PROTOCOLS_TO_13 = {TLS13, TLS12, TLS11, TLS10, SSL30, DTLS12, DTLS10};
    static final ProtocolVersion[] PROTOCOLS_OF_NONE = {NONE};
    static final ProtocolVersion[] PROTOCOLS_OF_30 = {SSL30};
    static final ProtocolVersion[] PROTOCOLS_OF_11 = {TLS11, DTLS10};
    static final ProtocolVersion[] PROTOCOLS_OF_12 = {TLS12, DTLS12};
    static final ProtocolVersion[] PROTOCOLS_OF_13 = {TLS13};
    static final ProtocolVersion[] PROTOCOLS_10_11 = {TLS11, TLS10, DTLS10};
    static final ProtocolVersion[] PROTOCOLS_11_12 = {TLS12, TLS11, DTLS12, DTLS10};
    static final ProtocolVersion[] PROTOCOLS_12_13 = {TLS13, TLS12, DTLS12};
    static final ProtocolVersion[] PROTOCOLS_10_12 = {TLS12, TLS11, TLS10, DTLS12, DTLS10};
    static final ProtocolVersion[] PROTOCOLS_TO_TLS12 = {TLS12, TLS11, TLS10, SSL30};
    static final ProtocolVersion[] PROTOCOLS_TO_TLS11 = {TLS11, TLS10, SSL30};
    static final ProtocolVersion[] PROTOCOLS_TO_TLS10 = {TLS10, SSL30};
    static final ProtocolVersion[] PROTOCOLS_EMPTY = new ProtocolVersion[0];

    ProtocolVersion(int id, String name, boolean isDTLS) {
        this.f978id = id;
        this.name = name;
        this.isDTLS = isDTLS;
        this.major = (byte) ((id >>> 8) & GF2Field.MASK);
        this.minor = (byte) (id & GF2Field.MASK);
        this.isAvailable = SSLAlgorithmConstraints.DEFAULT_SSL_ONLY.permits(EnumSet.of(CryptoPrimitive.KEY_AGREEMENT), name, null);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static ProtocolVersion valueOf(byte major, byte minor) {
        ProtocolVersion[] values;
        for (ProtocolVersion pv : values()) {
            if (pv.major == major && pv.minor == minor) {
                return pv;
            }
        }
        return null;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static ProtocolVersion valueOf(int id) {
        ProtocolVersion[] values;
        for (ProtocolVersion pv : values()) {
            if (pv.f978id == id) {
                return pv;
            }
        }
        return null;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static String nameOf(byte major, byte minor) {
        ProtocolVersion[] values;
        for (ProtocolVersion pv : values()) {
            if (pv.major == major && pv.minor == minor) {
                return pv.name;
            }
        }
        return "(D)TLS-" + ((int) major) + "." + ((int) minor);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static String nameOf(int id) {
        return nameOf((byte) ((id >>> 8) & GF2Field.MASK), (byte) (id & GF2Field.MASK));
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static ProtocolVersion nameOf(String name) {
        ProtocolVersion[] values;
        for (ProtocolVersion pv : values()) {
            if (pv.name.equals(name)) {
                return pv;
            }
        }
        return null;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static boolean isNegotiable(byte major, byte minor, boolean isDTLS, boolean allowSSL20Hello) {
        int v = ((major & 255) << 8) | (minor & 255);
        if (isDTLS) {
            return v <= DTLS10.f978id;
        } else if (v < SSL30.f978id) {
            if (!allowSSL20Hello || v != SSL20Hello.f978id) {
                return false;
            }
            return true;
        } else {
            return true;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static String[] toStringArray(List<ProtocolVersion> protocolVersions) {
        if (protocolVersions != null && !protocolVersions.isEmpty()) {
            String[] protocolNames = new String[protocolVersions.size()];
            int i = 0;
            for (ProtocolVersion pv : protocolVersions) {
                int i2 = i;
                i++;
                protocolNames[i2] = pv.name;
            }
            return protocolNames;
        }
        return new String[0];
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static String[] toStringArray(int[] protocolVersions) {
        if (protocolVersions != null && protocolVersions.length != 0) {
            String[] protocolNames = new String[protocolVersions.length];
            int i = 0;
            for (int pv : protocolVersions) {
                int i2 = i;
                i++;
                protocolNames[i2] = nameOf(pv);
            }
            return protocolNames;
        }
        return new String[0];
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static List<ProtocolVersion> namesOf(String[] protocolNames) {
        if (protocolNames == null || protocolNames.length == 0) {
            return Collections.emptyList();
        }
        List<ProtocolVersion> pvs = new ArrayList<>(protocolNames.length);
        for (String pn : protocolNames) {
            ProtocolVersion pv = nameOf(pn);
            if (pv == null) {
                throw new IllegalArgumentException("Unsupported protocol" + pn);
            }
            pvs.add(pv);
        }
        return Collections.unmodifiableList(pvs);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static boolean useTLS12PlusSpec(String name) {
        ProtocolVersion pv = nameOf(name);
        if (pv == null || pv == NONE) {
            return false;
        }
        return pv.isDTLS ? pv.f978id <= DTLS12.f978id : pv.f978id >= TLS12.f978id;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int compare(ProtocolVersion that) {
        if (this == that) {
            return 0;
        }
        if (this == NONE) {
            return -1;
        }
        if (that == NONE) {
            return 1;
        }
        if (this.isDTLS) {
            return that.f978id - this.f978id;
        }
        return this.f978id - that.f978id;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean useTLS13PlusSpec() {
        return this.isDTLS ? this.f978id < DTLS12.f978id : this.f978id >= TLS13.f978id;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean useTLS12PlusSpec() {
        return this.isDTLS ? this.f978id <= DTLS12.f978id : this.f978id >= TLS12.f978id;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean useTLS11PlusSpec() {
        return this.isDTLS || this.f978id >= TLS11.f978id;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean useTLS10PlusSpec() {
        return this.isDTLS || this.f978id >= TLS10.f978id;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static boolean useTLS10PlusSpec(int id, boolean isDTLS) {
        return isDTLS || id >= TLS10.f978id;
    }

    static boolean useTLS13PlusSpec(int id, boolean isDTLS) {
        return isDTLS ? id < DTLS12.f978id : id >= TLS13.f978id;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static ProtocolVersion selectedFrom(List<ProtocolVersion> listedVersions, int suggestedVersion) {
        ProtocolVersion selectedVersion = NONE;
        for (ProtocolVersion pv : listedVersions) {
            if (pv.f978id == suggestedVersion) {
                return pv;
            }
            if (pv.isDTLS) {
                if (pv.f978id > suggestedVersion && pv.f978id < selectedVersion.f978id) {
                    selectedVersion = pv;
                }
            } else if (pv.f978id < suggestedVersion && pv.f978id > selectedVersion.f978id) {
                selectedVersion = pv;
            }
        }
        return selectedVersion;
    }
}