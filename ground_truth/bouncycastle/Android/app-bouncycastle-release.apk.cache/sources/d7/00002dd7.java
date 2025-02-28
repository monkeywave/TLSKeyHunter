package org.bouncycastle.tls.crypto;

import java.io.IOException;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.tls.HashAlgorithm;
import org.bouncycastle.tls.MACAlgorithm;
import org.bouncycastle.tls.PRFAlgorithm;
import org.bouncycastle.tls.SignatureAlgorithm;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.TlsUtils;

/* loaded from: classes2.dex */
public abstract class TlsCryptoUtils {
    private static final byte[] TLS13_PREFIX = {116, 108, 115, 49, 51, 32};

    public static int getHash(short s) {
        switch (s) {
            case 1:
                return 1;
            case 2:
                return 2;
            case 3:
                return 3;
            case 4:
                return 4;
            case 5:
                return 5;
            case 6:
                return 6;
            default:
                throw new IllegalArgumentException("specified HashAlgorithm invalid: " + HashAlgorithm.getText(s));
        }
    }

    public static int getHashForHMAC(int i) {
        int i2 = 1;
        if (i != 1) {
            i2 = 2;
            if (i != 2) {
                if (i != 3) {
                    if (i != 4) {
                        if (i == 5) {
                            return 6;
                        }
                        throw new IllegalArgumentException("specified MACAlgorithm not an HMAC: " + MACAlgorithm.getText(i));
                    }
                    return 5;
                }
                return 4;
            }
        }
        return i2;
    }

    public static int getHashForPRF(int i) {
        switch (i) {
            case 0:
            case 1:
                throw new IllegalArgumentException("legacy PRF not a valid algorithm");
            case 2:
            case 4:
                return 4;
            case 3:
            case 5:
                return 5;
            case 6:
            default:
                throw new IllegalArgumentException("unknown PRFAlgorithm: " + PRFAlgorithm.getText(i));
            case 7:
                return 7;
            case 8:
                return 8;
        }
    }

    public static int getHashInternalSize(int i) {
        switch (i) {
            case 1:
            case 2:
            case 3:
            case 4:
            case 7:
            case 8:
                return 64;
            case 5:
            case 6:
                return 128;
            default:
                throw new IllegalArgumentException();
        }
    }

    public static int getHashOutputSize(int i) {
        switch (i) {
            case 1:
                return 16;
            case 2:
                return 20;
            case 3:
                return 28;
            case 4:
            case 7:
            case 8:
                return 32;
            case 5:
                return 48;
            case 6:
                return 64;
            default:
                throw new IllegalArgumentException();
        }
    }

    public static ASN1ObjectIdentifier getOIDForHash(int i) {
        switch (i) {
            case 1:
                return PKCSObjectIdentifiers.md5;
            case 2:
                return X509ObjectIdentifiers.id_SHA1;
            case 3:
                return NISTObjectIdentifiers.id_sha224;
            case 4:
                return NISTObjectIdentifiers.id_sha256;
            case 5:
                return NISTObjectIdentifiers.id_sha384;
            case 6:
                return NISTObjectIdentifiers.id_sha512;
            case 7:
            default:
                throw new IllegalArgumentException();
            case 8:
                return RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256;
        }
    }

    public static int getSignature(short s) {
        int i = 64;
        if (s != 64) {
            i = 65;
            if (s != 65) {
                switch (s) {
                    case 1:
                        return 1;
                    case 2:
                        return 2;
                    case 3:
                        return 3;
                    case 4:
                        return 4;
                    case 5:
                        return 5;
                    case 6:
                        return 6;
                    case 7:
                        return 7;
                    case 8:
                        return 8;
                    case 9:
                        return 9;
                    case 10:
                        return 10;
                    case 11:
                        return 11;
                    default:
                        switch (s) {
                            case 26:
                                return 26;
                            case 27:
                                return 27;
                            case 28:
                                return 28;
                            default:
                                throw new IllegalArgumentException("specified SignatureAlgorithm invalid: " + SignatureAlgorithm.getText(s));
                        }
                }
            }
        }
        return i;
    }

    public static TlsSecret hkdfExpandLabel(TlsSecret tlsSecret, int i, String str, byte[] bArr, int i2) throws IOException {
        int length = str.length();
        if (length >= 1) {
            int length2 = bArr.length;
            byte[] bArr2 = TLS13_PREFIX;
            int length3 = bArr2.length + length;
            int i3 = length3 + 3;
            byte[] bArr3 = new byte[length2 + 1 + i3];
            TlsUtils.checkUint16(i2);
            TlsUtils.writeUint16(i2, bArr3, 0);
            TlsUtils.checkUint8(length3);
            TlsUtils.writeUint8(length3, bArr3, 2);
            System.arraycopy(bArr2, 0, bArr3, 3, bArr2.length);
            int length4 = bArr2.length + 3;
            for (int i4 = 0; i4 < length; i4++) {
                bArr3[length4 + i4] = (byte) str.charAt(i4);
            }
            TlsUtils.writeOpaque8(bArr, bArr3, i3);
            return tlsSecret.hkdfExpand(i, bArr3, i2);
        }
        throw new TlsFatalAlert((short) 80);
    }
}