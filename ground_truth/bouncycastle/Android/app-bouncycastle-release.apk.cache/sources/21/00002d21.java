package org.bouncycastle.tls;

/* loaded from: classes2.dex */
public class ClientCertificateType {
    public static final short dss_ephemeral_dh_RESERVED = 6;
    public static final short dss_fixed_dh = 4;
    public static final short dss_sign = 2;
    public static final short ecdsa_fixed_ecdh = 66;
    public static final short ecdsa_sign = 64;
    public static final short fortezza_dms_RESERVED = 20;
    public static final short gost_sign256 = 67;
    public static final short gost_sign512 = 68;
    public static final short rsa_ephemeral_dh_RESERVED = 5;
    public static final short rsa_fixed_dh = 3;
    public static final short rsa_fixed_ecdh = 65;
    public static final short rsa_sign = 1;

    public static String getName(short s) {
        if (s != 20) {
            switch (s) {
                case 1:
                    return "rsa_sign";
                case 2:
                    return "dss_sign";
                case 3:
                    return "rsa_fixed_dh";
                case 4:
                    return "dss_fixed_dh";
                case 5:
                    return "rsa_ephemeral_dh_RESERVED";
                case 6:
                    return "dss_ephemeral_dh_RESERVED";
                default:
                    switch (s) {
                        case 64:
                            return "ecdsa_sign";
                        case 65:
                            return "rsa_fixed_ecdh";
                        case 66:
                            return "ecdsa_fixed_ecdh";
                        case 67:
                            return "gost_sign256";
                        case 68:
                            return "gost_sign512";
                        default:
                            return "UNKNOWN";
                    }
            }
        }
        return "fortezza_dms_RESERVED";
    }

    public static String getText(short s) {
        return getName(s) + "(" + ((int) s) + ")";
    }
}