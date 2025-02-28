package org.bouncycastle.tls;

import org.bouncycastle.tls.crypto.TlsCryptoUtils;

/* loaded from: classes2.dex */
public class SignatureScheme {
    public static final int ecdsa_brainpoolP256r1tls13_sha256 = 2074;
    public static final int ecdsa_brainpoolP384r1tls13_sha384 = 2075;
    public static final int ecdsa_brainpoolP512r1tls13_sha512 = 2076;
    public static final int ecdsa_secp256r1_sha256 = 1027;
    public static final int ecdsa_secp384r1_sha384 = 1283;
    public static final int ecdsa_secp521r1_sha512 = 1539;
    public static final int ecdsa_sha1 = 515;
    public static final int ed25519 = 2055;
    public static final int ed448 = 2056;
    public static final int rsa_pkcs1_sha1 = 513;
    public static final int rsa_pkcs1_sha256 = 1025;
    public static final int rsa_pkcs1_sha384 = 1281;
    public static final int rsa_pkcs1_sha512 = 1537;
    public static final int rsa_pss_pss_sha256 = 2057;
    public static final int rsa_pss_pss_sha384 = 2058;
    public static final int rsa_pss_pss_sha512 = 2059;
    public static final int rsa_pss_rsae_sha256 = 2052;
    public static final int rsa_pss_rsae_sha384 = 2053;
    public static final int rsa_pss_rsae_sha512 = 2054;
    public static final int sm2sig_sm3 = 1800;

    public static int from(SignatureAndHashAlgorithm signatureAndHashAlgorithm) {
        if (signatureAndHashAlgorithm != null) {
            return from(signatureAndHashAlgorithm.getHash(), signatureAndHashAlgorithm.getSignature());
        }
        throw null;
    }

    public static int from(short s, short s2) {
        return ((s & 255) << 8) | (s2 & 255);
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    public static int getCryptoHashAlgorithm(int i) {
        if (i != 1800) {
            switch (i) {
                case rsa_pss_rsae_sha256 /* 2052 */:
                case rsa_pss_pss_sha256 /* 2057 */:
                    return 4;
                case rsa_pss_rsae_sha384 /* 2053 */:
                case rsa_pss_pss_sha384 /* 2058 */:
                    return 5;
                case rsa_pss_rsae_sha512 /* 2054 */:
                case rsa_pss_pss_sha512 /* 2059 */:
                    return 6;
                case ed25519 /* 2055 */:
                case ed448 /* 2056 */:
                    break;
                default:
                    switch (i) {
                        case ecdsa_brainpoolP256r1tls13_sha256 /* 2074 */:
                            return 4;
                        case ecdsa_brainpoolP384r1tls13_sha384 /* 2075 */:
                            return 5;
                        case ecdsa_brainpoolP512r1tls13_sha512 /* 2076 */:
                            return 6;
                        default:
                            short hashAlgorithm = getHashAlgorithm(i);
                            if (8 != hashAlgorithm && HashAlgorithm.isRecognized(hashAlgorithm)) {
                                return TlsCryptoUtils.getHash(hashAlgorithm);
                            }
                            break;
                    }
            }
            return -1;
        }
        return 7;
    }

    public static int getCryptoHashAlgorithm(SignatureAndHashAlgorithm signatureAndHashAlgorithm) {
        return getCryptoHashAlgorithm(from(signatureAndHashAlgorithm));
    }

    public static short getHashAlgorithm(int i) {
        return (short) ((i >>> 8) & 255);
    }

    public static String getName(int i) {
        if (i != 513) {
            if (i != 515) {
                if (i != 1025) {
                    if (i != 1027) {
                        if (i != 1281) {
                            if (i != 1283) {
                                if (i != 1537) {
                                    if (i != 1539) {
                                        if (i != 1800) {
                                            switch (i) {
                                                case rsa_pss_rsae_sha256 /* 2052 */:
                                                    return "rsa_pss_rsae_sha256";
                                                case rsa_pss_rsae_sha384 /* 2053 */:
                                                    return "rsa_pss_rsae_sha384";
                                                case rsa_pss_rsae_sha512 /* 2054 */:
                                                    return "rsa_pss_rsae_sha512";
                                                case ed25519 /* 2055 */:
                                                    return "ed25519";
                                                case ed448 /* 2056 */:
                                                    return "ed448";
                                                case rsa_pss_pss_sha256 /* 2057 */:
                                                    return "rsa_pss_pss_sha256";
                                                case rsa_pss_pss_sha384 /* 2058 */:
                                                    return "rsa_pss_pss_sha384";
                                                case rsa_pss_pss_sha512 /* 2059 */:
                                                    return "rsa_pss_pss_sha512";
                                                default:
                                                    switch (i) {
                                                        case ecdsa_brainpoolP256r1tls13_sha256 /* 2074 */:
                                                            return "ecdsa_brainpoolP256r1tls13_sha256";
                                                        case ecdsa_brainpoolP384r1tls13_sha384 /* 2075 */:
                                                            return "ecdsa_brainpoolP384r1tls13_sha384";
                                                        case ecdsa_brainpoolP512r1tls13_sha512 /* 2076 */:
                                                            return "ecdsa_brainpoolP512r1tls13_sha512";
                                                        default:
                                                            return "UNKNOWN";
                                                    }
                                            }
                                        }
                                        return "sm2sig_sm3";
                                    }
                                    return "ecdsa_secp521r1_sha512";
                                }
                                return "rsa_pkcs1_sha512";
                            }
                            return "ecdsa_secp384r1_sha384";
                        }
                        return "rsa_pkcs1_sha384";
                    }
                    return "ecdsa_secp256r1_sha256";
                }
                return "rsa_pkcs1_sha256";
            }
            return "ecdsa_sha1";
        }
        return "rsa_pkcs1_sha1";
    }

    public static int getNamedGroup(int i) {
        if (i != 1027) {
            if (i != 1283) {
                if (i != 1539) {
                    if (i != 1800) {
                        switch (i) {
                            case ecdsa_brainpoolP256r1tls13_sha256 /* 2074 */:
                                return 31;
                            case ecdsa_brainpoolP384r1tls13_sha384 /* 2075 */:
                                return 32;
                            case ecdsa_brainpoolP512r1tls13_sha512 /* 2076 */:
                                return 33;
                            default:
                                return -1;
                        }
                    }
                    return 41;
                }
                return 25;
            }
            return 24;
        }
        return 23;
    }

    public static int getRSAPSSCryptoHashAlgorithm(int i) {
        switch (i) {
            case rsa_pss_rsae_sha256 /* 2052 */:
            case rsa_pss_pss_sha256 /* 2057 */:
                return 4;
            case rsa_pss_rsae_sha384 /* 2053 */:
            case rsa_pss_pss_sha384 /* 2058 */:
                return 5;
            case rsa_pss_rsae_sha512 /* 2054 */:
            case rsa_pss_pss_sha512 /* 2059 */:
                return 6;
            case ed25519 /* 2055 */:
            case ed448 /* 2056 */:
            default:
                return -1;
        }
    }

    public static short getSignatureAlgorithm(int i) {
        return (short) (i & 255);
    }

    public static SignatureAndHashAlgorithm getSignatureAndHashAlgorithm(int i) {
        return SignatureAndHashAlgorithm.getInstance(getHashAlgorithm(i), getSignatureAlgorithm(i));
    }

    public static String getText(int i) {
        return getName(i) + "(0x" + Integer.toHexString(i) + ")";
    }

    public static boolean isECDSA(int i) {
        switch (i) {
            case ecdsa_brainpoolP256r1tls13_sha256 /* 2074 */:
            case ecdsa_brainpoolP384r1tls13_sha384 /* 2075 */:
            case ecdsa_brainpoolP512r1tls13_sha512 /* 2076 */:
                return true;
            default:
                return 3 == getSignatureAlgorithm(i);
        }
    }

    public static boolean isPrivate(int i) {
        return (i >>> 9) == 254;
    }

    public static boolean isRSAPSS(int i) {
        switch (i) {
            case rsa_pss_rsae_sha256 /* 2052 */:
            case rsa_pss_rsae_sha384 /* 2053 */:
            case rsa_pss_rsae_sha512 /* 2054 */:
            case rsa_pss_pss_sha256 /* 2057 */:
            case rsa_pss_pss_sha384 /* 2058 */:
            case rsa_pss_pss_sha512 /* 2059 */:
                return true;
            case ed25519 /* 2055 */:
            case ed448 /* 2056 */:
            default:
                return false;
        }
    }
}