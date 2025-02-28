package org.bouncycastle.tls;

import com.google.android.material.internal.ViewUtils;
import java.util.Vector;
import org.bouncycastle.util.Strings;

/* loaded from: classes2.dex */
public final class ProtocolVersion {
    static final ProtocolVersion CLIENT_EARLIEST_SUPPORTED_DTLS;
    static final ProtocolVersion CLIENT_EARLIEST_SUPPORTED_TLS;
    static final ProtocolVersion CLIENT_LATEST_SUPPORTED_DTLS;
    static final ProtocolVersion CLIENT_LATEST_SUPPORTED_TLS;
    public static final ProtocolVersion DTLSv10;
    public static final ProtocolVersion DTLSv12;
    public static final ProtocolVersion DTLSv13;
    static final ProtocolVersion SERVER_EARLIEST_SUPPORTED_DTLS;
    static final ProtocolVersion SERVER_EARLIEST_SUPPORTED_TLS;
    static final ProtocolVersion SERVER_LATEST_SUPPORTED_DTLS;
    static final ProtocolVersion SERVER_LATEST_SUPPORTED_TLS;
    public static final ProtocolVersion SSLv3;
    public static final ProtocolVersion TLSv10;
    public static final ProtocolVersion TLSv11;
    public static final ProtocolVersion TLSv12;
    public static final ProtocolVersion TLSv13;
    private String name;
    private int version;

    static {
        ProtocolVersion protocolVersion = new ProtocolVersion(ViewUtils.EDGE_TO_EDGE_FLAGS, "SSL 3.0");
        SSLv3 = protocolVersion;
        TLSv10 = new ProtocolVersion(769, "TLS 1.0");
        TLSv11 = new ProtocolVersion(770, "TLS 1.1");
        TLSv12 = new ProtocolVersion(771, "TLS 1.2");
        ProtocolVersion protocolVersion2 = new ProtocolVersion(772, "TLS 1.3");
        TLSv13 = protocolVersion2;
        ProtocolVersion protocolVersion3 = new ProtocolVersion(65279, "DTLS 1.0");
        DTLSv10 = protocolVersion3;
        ProtocolVersion protocolVersion4 = new ProtocolVersion(65277, "DTLS 1.2");
        DTLSv12 = protocolVersion4;
        DTLSv13 = new ProtocolVersion(65276, "DTLS 1.3");
        CLIENT_EARLIEST_SUPPORTED_DTLS = protocolVersion3;
        CLIENT_EARLIEST_SUPPORTED_TLS = protocolVersion;
        CLIENT_LATEST_SUPPORTED_DTLS = protocolVersion4;
        CLIENT_LATEST_SUPPORTED_TLS = protocolVersion2;
        SERVER_EARLIEST_SUPPORTED_DTLS = protocolVersion3;
        SERVER_EARLIEST_SUPPORTED_TLS = protocolVersion;
        SERVER_LATEST_SUPPORTED_DTLS = protocolVersion4;
        SERVER_LATEST_SUPPORTED_TLS = protocolVersion2;
    }

    private ProtocolVersion(int i, String str) {
        this.version = i & 65535;
        this.name = str;
    }

    private static void checkUint8(int i) {
        if (!TlsUtils.isValidUint8(i)) {
            throw new IllegalArgumentException("'versionOctet' is not a valid octet");
        }
    }

    public static boolean contains(ProtocolVersion[] protocolVersionArr, ProtocolVersion protocolVersion) {
        if (protocolVersionArr != null && protocolVersion != null) {
            for (ProtocolVersion protocolVersion2 : protocolVersionArr) {
                if (protocolVersion.equals(protocolVersion2)) {
                    return true;
                }
            }
        }
        return false;
    }

    public static ProtocolVersion get(int i, int i2) {
        String str;
        if (i != 3) {
            if (i == 254) {
                switch (i2) {
                    case 252:
                        return DTLSv13;
                    case 253:
                        return DTLSv12;
                    case 254:
                        throw new IllegalArgumentException("{0xFE, 0xFE} is a reserved protocol version");
                    case 255:
                        return DTLSv10;
                    default:
                        str = "DTLS";
                        break;
                }
            } else {
                str = "UNKNOWN";
            }
        } else if (i2 == 0) {
            return SSLv3;
        } else {
            if (i2 == 1) {
                return TLSv10;
            }
            if (i2 == 2) {
                return TLSv11;
            }
            if (i2 == 3) {
                return TLSv12;
            }
            if (i2 == 4) {
                return TLSv13;
            }
            str = "TLS";
        }
        return getUnknownVersion(i, i2, str);
    }

    public static ProtocolVersion getEarliestDTLS(ProtocolVersion[] protocolVersionArr) {
        ProtocolVersion protocolVersion = null;
        if (protocolVersionArr != null) {
            for (ProtocolVersion protocolVersion2 : protocolVersionArr) {
                if (protocolVersion2 != null && protocolVersion2.isDTLS() && (protocolVersion == null || protocolVersion2.getMinorVersion() > protocolVersion.getMinorVersion())) {
                    protocolVersion = protocolVersion2;
                }
            }
        }
        return protocolVersion;
    }

    public static ProtocolVersion getEarliestTLS(ProtocolVersion[] protocolVersionArr) {
        ProtocolVersion protocolVersion = null;
        if (protocolVersionArr != null) {
            for (ProtocolVersion protocolVersion2 : protocolVersionArr) {
                if (protocolVersion2 != null && protocolVersion2.isTLS() && (protocolVersion == null || protocolVersion2.getMinorVersion() < protocolVersion.getMinorVersion())) {
                    protocolVersion = protocolVersion2;
                }
            }
        }
        return protocolVersion;
    }

    public static ProtocolVersion getLatestDTLS(ProtocolVersion[] protocolVersionArr) {
        ProtocolVersion protocolVersion = null;
        if (protocolVersionArr != null) {
            for (ProtocolVersion protocolVersion2 : protocolVersionArr) {
                if (protocolVersion2 != null && protocolVersion2.isDTLS() && (protocolVersion == null || protocolVersion2.getMinorVersion() < protocolVersion.getMinorVersion())) {
                    protocolVersion = protocolVersion2;
                }
            }
        }
        return protocolVersion;
    }

    public static ProtocolVersion getLatestTLS(ProtocolVersion[] protocolVersionArr) {
        ProtocolVersion protocolVersion = null;
        if (protocolVersionArr != null) {
            for (ProtocolVersion protocolVersion2 : protocolVersionArr) {
                if (protocolVersion2 != null && protocolVersion2.isTLS() && (protocolVersion == null || protocolVersion2.getMinorVersion() > protocolVersion.getMinorVersion())) {
                    protocolVersion = protocolVersion2;
                }
            }
        }
        return protocolVersion;
    }

    private static ProtocolVersion getUnknownVersion(int i, int i2, String str) {
        checkUint8(i);
        checkUint8(i2);
        int i3 = (i << 8) | i2;
        return new ProtocolVersion(i3, str + " 0x" + Strings.toUpperCase(Integer.toHexString(65536 | i3).substring(1)));
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static boolean isSupportedDTLSVersionClient(ProtocolVersion protocolVersion) {
        return protocolVersion != null && protocolVersion.isEqualOrLaterVersionOf(CLIENT_EARLIEST_SUPPORTED_DTLS) && protocolVersion.isEqualOrEarlierVersionOf(CLIENT_LATEST_SUPPORTED_DTLS);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static boolean isSupportedDTLSVersionServer(ProtocolVersion protocolVersion) {
        return protocolVersion != null && protocolVersion.isEqualOrLaterVersionOf(SERVER_EARLIEST_SUPPORTED_DTLS) && protocolVersion.isEqualOrEarlierVersionOf(SERVER_LATEST_SUPPORTED_DTLS);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static boolean isSupportedTLSVersionClient(ProtocolVersion protocolVersion) {
        int fullVersion;
        return protocolVersion != null && (fullVersion = protocolVersion.getFullVersion()) >= CLIENT_EARLIEST_SUPPORTED_TLS.getFullVersion() && fullVersion <= CLIENT_LATEST_SUPPORTED_TLS.getFullVersion();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static boolean isSupportedTLSVersionServer(ProtocolVersion protocolVersion) {
        int fullVersion;
        return protocolVersion != null && (fullVersion = protocolVersion.getFullVersion()) >= SERVER_EARLIEST_SUPPORTED_TLS.getFullVersion() && fullVersion <= SERVER_LATEST_SUPPORTED_TLS.getFullVersion();
    }

    public ProtocolVersion[] downTo(ProtocolVersion protocolVersion) {
        if (isEqualOrLaterVersionOf(protocolVersion)) {
            Vector vector = new Vector();
            vector.addElement(this);
            ProtocolVersion protocolVersion2 = this;
            while (!protocolVersion2.equals(protocolVersion)) {
                protocolVersion2 = protocolVersion2.getPreviousVersion();
                vector.addElement(protocolVersion2);
            }
            ProtocolVersion[] protocolVersionArr = new ProtocolVersion[vector.size()];
            for (int i = 0; i < vector.size(); i++) {
                protocolVersionArr[i] = (ProtocolVersion) vector.elementAt(i);
            }
            return protocolVersionArr;
        }
        throw new IllegalArgumentException("'min' must be an equal or earlier version of this one");
    }

    public boolean equals(Object obj) {
        return this == obj || ((obj instanceof ProtocolVersion) && equals((ProtocolVersion) obj));
    }

    public boolean equals(ProtocolVersion protocolVersion) {
        return protocolVersion != null && this.version == protocolVersion.version;
    }

    public ProtocolVersion getEquivalentTLSVersion() {
        int majorVersion = getMajorVersion();
        if (majorVersion != 3) {
            if (majorVersion != 254) {
                return null;
            }
            int minorVersion = getMinorVersion();
            if (minorVersion != 252) {
                if (minorVersion != 253) {
                    if (minorVersion != 255) {
                        return null;
                    }
                    return TLSv11;
                }
                return TLSv12;
            }
            return TLSv13;
        }
        return this;
    }

    public int getFullVersion() {
        return this.version;
    }

    public int getMajorVersion() {
        return this.version >> 8;
    }

    public int getMinorVersion() {
        return this.version & 255;
    }

    public String getName() {
        return this.name;
    }

    public ProtocolVersion getNextVersion() {
        int i;
        int majorVersion = getMajorVersion();
        int minorVersion = getMinorVersion();
        if (majorVersion != 3) {
            if (majorVersion != 254 || minorVersion == 0) {
                return null;
            }
            if (minorVersion == 255) {
                return DTLSv12;
            }
            i = minorVersion - 1;
        } else if (minorVersion == 255) {
            return null;
        } else {
            i = minorVersion + 1;
        }
        return get(majorVersion, i);
    }

    public ProtocolVersion getPreviousVersion() {
        int i;
        int majorVersion = getMajorVersion();
        int minorVersion = getMinorVersion();
        if (majorVersion != 3) {
            if (majorVersion != 254) {
                return null;
            }
            if (minorVersion == 253) {
                return DTLSv10;
            }
            if (minorVersion == 255) {
                return null;
            }
            i = minorVersion + 1;
        } else if (minorVersion == 0) {
            return null;
        } else {
            i = minorVersion - 1;
        }
        return get(majorVersion, i);
    }

    public int hashCode() {
        return this.version;
    }

    public boolean isDTLS() {
        return getMajorVersion() == 254;
    }

    public boolean isEarlierVersionOf(ProtocolVersion protocolVersion) {
        if (protocolVersion == null || getMajorVersion() != protocolVersion.getMajorVersion()) {
            return false;
        }
        int minorVersion = getMinorVersion() - protocolVersion.getMinorVersion();
        if (isDTLS()) {
            if (minorVersion <= 0) {
                return false;
            }
        } else if (minorVersion >= 0) {
            return false;
        }
        return true;
    }

    public boolean isEqualOrEarlierVersionOf(ProtocolVersion protocolVersion) {
        if (protocolVersion == null || getMajorVersion() != protocolVersion.getMajorVersion()) {
            return false;
        }
        int minorVersion = getMinorVersion() - protocolVersion.getMinorVersion();
        if (isDTLS()) {
            if (minorVersion < 0) {
                return false;
            }
        } else if (minorVersion > 0) {
            return false;
        }
        return true;
    }

    public boolean isEqualOrLaterVersionOf(ProtocolVersion protocolVersion) {
        if (protocolVersion == null || getMajorVersion() != protocolVersion.getMajorVersion()) {
            return false;
        }
        int minorVersion = getMinorVersion() - protocolVersion.getMinorVersion();
        if (isDTLS()) {
            if (minorVersion > 0) {
                return false;
            }
        } else if (minorVersion < 0) {
            return false;
        }
        return true;
    }

    public boolean isLaterVersionOf(ProtocolVersion protocolVersion) {
        if (protocolVersion == null || getMajorVersion() != protocolVersion.getMajorVersion()) {
            return false;
        }
        int minorVersion = getMinorVersion() - protocolVersion.getMinorVersion();
        if (isDTLS()) {
            if (minorVersion >= 0) {
                return false;
            }
        } else if (minorVersion <= 0) {
            return false;
        }
        return true;
    }

    public boolean isSSL() {
        return this == SSLv3;
    }

    public boolean isTLS() {
        return getMajorVersion() == 3;
    }

    public ProtocolVersion[] only() {
        return new ProtocolVersion[]{this};
    }

    public String toString() {
        return this.name;
    }
}