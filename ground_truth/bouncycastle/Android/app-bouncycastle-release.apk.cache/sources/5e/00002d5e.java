package org.bouncycastle.tls;

import androidx.core.view.InputDeviceCompat;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.jcajce.spec.XDHParameterSpec;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMEngine;

/* loaded from: classes2.dex */
public class NamedGroup {
    public static final int DRAFT_mlkem1024 = 4132;
    public static final int DRAFT_mlkem768 = 1896;
    public static final int GC256A = 34;
    public static final int GC256B = 35;
    public static final int GC256C = 36;
    public static final int GC256D = 37;
    public static final int GC512A = 38;
    public static final int GC512B = 39;
    public static final int GC512C = 40;
    public static final int OQS_mlkem1024 = 585;
    public static final int OQS_mlkem512 = 583;
    public static final int OQS_mlkem768 = 584;
    public static final int arbitrary_explicit_char2_curves = 65282;
    public static final int arbitrary_explicit_prime_curves = 65281;
    public static final int brainpoolP256r1 = 26;
    public static final int brainpoolP256r1tls13 = 31;
    public static final int brainpoolP384r1 = 27;
    public static final int brainpoolP384r1tls13 = 32;
    public static final int brainpoolP512r1 = 28;
    public static final int brainpoolP512r1tls13 = 33;
    public static final int curveSM2 = 41;
    public static final int ffdhe2048 = 256;
    public static final int ffdhe3072 = 257;
    public static final int ffdhe4096 = 258;
    public static final int ffdhe6144 = 259;
    public static final int ffdhe8192 = 260;
    public static final int secp160k1 = 15;
    public static final int secp160r1 = 16;
    public static final int secp160r2 = 17;
    public static final int secp192k1 = 18;
    public static final int secp192r1 = 19;
    public static final int secp224k1 = 20;
    public static final int secp224r1 = 21;
    public static final int secp256k1 = 22;
    public static final int secp256r1 = 23;
    public static final int secp384r1 = 24;
    public static final int secp521r1 = 25;
    public static final int sect163k1 = 1;
    public static final int sect163r1 = 2;
    public static final int sect163r2 = 3;
    public static final int sect193r1 = 4;
    public static final int sect193r2 = 5;
    public static final int sect233k1 = 6;
    public static final int sect233r1 = 7;
    public static final int sect239k1 = 8;
    public static final int sect283k1 = 9;
    public static final int sect283r1 = 10;
    public static final int sect409k1 = 11;
    public static final int sect409r1 = 12;
    public static final int sect571k1 = 13;
    public static final int sect571r1 = 14;
    public static final int x25519 = 29;
    public static final int x448 = 30;
    private static final String[] CURVE_NAMES = {"sect163k1", "sect163r1", "sect163r2", "sect193r1", "sect193r2", "sect233k1", "sect233r1", "sect239k1", "sect283k1", "sect283r1", "sect409k1", "sect409r1", "sect571k1", "sect571r1", "secp160k1", "secp160r1", "secp160r2", "secp192k1", "secp192r1", "secp224k1", "secp224r1", "secp256k1", "secp256r1", "secp384r1", "secp521r1", "brainpoolP256r1", "brainpoolP384r1", "brainpoolP512r1", XDHParameterSpec.X25519, XDHParameterSpec.X448, "brainpoolP256r1", "brainpoolP384r1", "brainpoolP512r1", "Tc26-Gost-3410-12-256-paramSetA", "GostR3410-2001-CryptoPro-A", "GostR3410-2001-CryptoPro-B", "GostR3410-2001-CryptoPro-C", "Tc26-Gost-3410-12-512-paramSetA", "Tc26-Gost-3410-12-512-paramSetB", "Tc26-Gost-3410-12-512-paramSetC", "sm2p256v1"};
    private static final String[] FINITE_FIELD_NAMES = {"ffdhe2048", "ffdhe3072", "ffdhe4096", "ffdhe6144", "ffdhe8192"};

    public static boolean canBeNegotiated(int i, ProtocolVersion protocolVersion) {
        if (i != 29 && i != 30) {
            switch (i) {
                case 23:
                case 24:
                case 25:
                    break;
                default:
                    if (refersToASpecificFiniteField(i)) {
                        return true;
                    }
                    boolean isTLSv13 = TlsUtils.isTLSv13(protocolVersion);
                    if (!refersToASpecificCurve(i)) {
                        return refersToASpecificKem(i) ? isTLSv13 : (i < 65281 || i > 65282) ? isPrivate(i) : !isTLSv13;
                    }
                    if (i != 41) {
                        switch (i) {
                            case 31:
                            case 32:
                            case 33:
                                break;
                            default:
                                return !isTLSv13;
                        }
                    }
                    return isTLSv13;
            }
        }
        return true;
    }

    public static int getCurveBits(int i) {
        switch (i) {
            case 1:
            case 2:
            case 3:
                return CipherSuite.TLS_DHE_DSS_WITH_AES_256_GCM_SHA384;
            case 4:
            case 5:
                return CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256;
            case 6:
            case 7:
                return 233;
            case 8:
                return 239;
            case 9:
            case 10:
                return 283;
            case 11:
            case 12:
                return 409;
            case 13:
            case 14:
                return 571;
            case 15:
            case 16:
            case 17:
                return CipherSuite.TLS_DH_RSA_WITH_AES_128_GCM_SHA256;
            case 18:
            case 19:
                return 192;
            case 20:
            case 21:
                return BERTags.FLAGS;
            case 22:
            case 23:
            case 26:
            case 31:
            case 34:
            case 35:
            case 36:
            case 37:
            case 41:
                return 256;
            case 24:
            case 27:
            case 32:
                return MLKEMEngine.KyberPolyBytes;
            case 25:
                return 521;
            case 28:
            case 33:
            case 38:
            case 39:
            case 40:
                return 512;
            case 29:
                return 252;
            case 30:
                return 446;
            default:
                return 0;
        }
    }

    public static String getCurveName(int i) {
        if (refersToASpecificCurve(i)) {
            return CURVE_NAMES[i - 1];
        }
        return null;
    }

    public static int getFiniteFieldBits(int i) {
        switch (i) {
            case 256:
                return 2048;
            case 257:
                return 3072;
            case ffdhe4096 /* 258 */:
                return 4096;
            case ffdhe6144 /* 259 */:
                return 6144;
            case ffdhe8192 /* 260 */:
                return 8192;
            default:
                return 0;
        }
    }

    public static String getFiniteFieldName(int i) {
        if (refersToASpecificFiniteField(i)) {
            return FINITE_FIELD_NAMES[i + InputDeviceCompat.SOURCE_ANY];
        }
        return null;
    }

    public static String getKemName(int i) {
        if (i != 1896) {
            if (i != 4132) {
                switch (i) {
                    case OQS_mlkem512 /* 583 */:
                        return "ML-KEM-512";
                    case OQS_mlkem768 /* 584 */:
                        return "ML-KEM-768";
                    case OQS_mlkem1024 /* 585 */:
                        return "ML-KEM-1024";
                    default:
                        return null;
                }
            }
            return "ML-KEM-1024";
        }
        return "ML-KEM-768";
    }

    public static int getMaximumChar2CurveBits() {
        return 571;
    }

    public static int getMaximumCurveBits() {
        return 571;
    }

    public static int getMaximumFiniteFieldBits() {
        return 8192;
    }

    public static int getMaximumPrimeCurveBits() {
        return 521;
    }

    public static String getName(int i) {
        if (isPrivate(i)) {
            return "PRIVATE";
        }
        if (i != 1896) {
            if (i != 4132) {
                switch (i) {
                    case 29:
                        return "x25519";
                    case 30:
                        return "x448";
                    case 31:
                        return "brainpoolP256r1tls13";
                    case 32:
                        return "brainpoolP384r1tls13";
                    case 33:
                        return "brainpoolP512r1tls13";
                    case 34:
                        return "GC256A";
                    case 35:
                        return "GC256B";
                    case 36:
                        return "GC256C";
                    case 37:
                        return "GC256D";
                    case 38:
                        return "GC512A";
                    case 39:
                        return "GC512B";
                    case 40:
                        return "GC512C";
                    case 41:
                        return "curveSM2";
                    default:
                        switch (i) {
                            case OQS_mlkem512 /* 583 */:
                                return "OQS_mlkem512";
                            case OQS_mlkem768 /* 584 */:
                                return "OQS_mlkem768";
                            case OQS_mlkem1024 /* 585 */:
                                return "OQS_mlkem1024";
                            default:
                                switch (i) {
                                    case 65281:
                                        return "arbitrary_explicit_prime_curves";
                                    case arbitrary_explicit_char2_curves /* 65282 */:
                                        return "arbitrary_explicit_char2_curves";
                                    default:
                                        String standardName = getStandardName(i);
                                        return standardName != null ? standardName : "UNKNOWN";
                                }
                        }
                }
            }
            return "DRAFT_mlkem1024";
        }
        return "DRAFT_mlkem768";
    }

    public static String getStandardName(int i) {
        String curveName = getCurveName(i);
        if (curveName != null) {
            return curveName;
        }
        String finiteFieldName = getFiniteFieldName(i);
        if (finiteFieldName != null) {
            return finiteFieldName;
        }
        String kemName = getKemName(i);
        if (kemName != null) {
            return kemName;
        }
        return null;
    }

    public static String getText(int i) {
        return getName(i) + "(" + i + ")";
    }

    public static boolean isChar2Curve(int i) {
        return (i >= 1 && i <= 14) || i == 65282;
    }

    public static boolean isFiniteField(int i) {
        return (i & InputDeviceCompat.SOURCE_ANY) == 256;
    }

    public static boolean isPrimeCurve(int i) {
        return (i >= 15 && i <= 41) || i == 65281;
    }

    public static boolean isPrivate(int i) {
        return (i >>> 2) == 127 || (i >>> 8) == 254;
    }

    public static boolean isValid(int i) {
        return refersToASpecificGroup(i) || isPrivate(i) || (i >= 65281 && i <= 65282);
    }

    public static boolean refersToASpecificCurve(int i) {
        return i >= 1 && i <= 41;
    }

    public static boolean refersToASpecificFiniteField(int i) {
        return i >= 256 && i <= 260;
    }

    public static boolean refersToASpecificGroup(int i) {
        return refersToASpecificCurve(i) || refersToASpecificFiniteField(i) || refersToASpecificKem(i);
    }

    public static boolean refersToASpecificKem(int i) {
        if (i == 1896 || i == 4132) {
            return true;
        }
        switch (i) {
            case OQS_mlkem512 /* 583 */:
            case OQS_mlkem768 /* 584 */:
            case OQS_mlkem1024 /* 585 */:
                return true;
            default:
                return false;
        }
    }

    public static boolean refersToAnECDHCurve(int i) {
        return refersToASpecificCurve(i);
    }

    public static boolean refersToAnECDSACurve(int i) {
        return refersToASpecificCurve(i) && !refersToAnXDHCurve(i);
    }

    public static boolean refersToAnXDHCurve(int i) {
        return i >= 29 && i <= 30;
    }
}