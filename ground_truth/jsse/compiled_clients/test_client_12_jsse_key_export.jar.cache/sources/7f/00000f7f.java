package org.openjsse.sun.net.util;

import java.net.URL;
import java.util.Arrays;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/net/util/IPAddressUtil.class */
public class IPAddressUtil {
    private static final int INADDR4SZ = 4;
    private static final int INADDR16SZ = 16;
    private static final int INT16SZ = 2;
    private static final long L_IPV6_DELIMS = 0;
    private static final long H_IPV6_DELIMS = 671088640;
    private static final long L_GEN_DELIMS = -8935000888854970368L;
    private static final long H_GEN_DELIMS = 671088641;
    private static final long L_AUTH_DELIMS = 288230376151711744L;
    private static final long H_AUTH_DELIMS = 671088641;
    private static final long L_COLON = 288230376151711744L;
    private static final long H_COLON = 0;
    private static final long L_SLASH = 140737488355328L;
    private static final long H_SLASH = 0;
    private static final long L_BACKSLASH = 0;
    private static final long H_BACKSLASH = 268435456;
    private static final long L_NON_PRINTABLE = 4294967295L;
    private static final long H_NON_PRINTABLE = Long.MIN_VALUE;
    private static final long L_EXCLUDE = -8935000884560003073L;
    private static final long H_EXCLUDE = -9223372035915251711L;
    private static final char[] OTHERS = {8263, 8264, 8265, 8448, 8449, 8453, 8454, 10868, 65109, 65110, 65119, 65131, 65283, 65295, 65306, 65311, 65312};

    public static byte[] textToNumericFormatV4(String src) {
        boolean z;
        byte[] res = new byte[4];
        long tmpValue = 0;
        int currByte = 0;
        boolean newOctet = true;
        int len = src.length();
        if (len == 0 || len > 15) {
            return null;
        }
        for (int i = 0; i < len; i++) {
            char c = src.charAt(i);
            if (c == '.') {
                if (newOctet || tmpValue < 0 || tmpValue > 255 || currByte == 3) {
                    return null;
                }
                int i2 = currByte;
                currByte++;
                res[i2] = (byte) (tmpValue & 255);
                tmpValue = 0;
                z = true;
            } else {
                int digit = Character.digit(c, 10);
                if (digit < 0) {
                    return null;
                }
                tmpValue = (tmpValue * 10) + digit;
                z = false;
            }
            newOctet = z;
        }
        if (newOctet || tmpValue < 0 || tmpValue >= (1 << ((4 - currByte) * 8))) {
            return null;
        }
        switch (currByte) {
            case 0:
                res[0] = (byte) ((tmpValue >> 24) & 255);
            case 1:
                res[1] = (byte) ((tmpValue >> 16) & 255);
            case 2:
                res[2] = (byte) ((tmpValue >> 8) & 255);
            case 3:
                res[3] = (byte) ((tmpValue >> 0) & 255);
                break;
        }
        return res;
    }

    /* JADX WARN: Code restructure failed: missing block: B:71:0x0165, code lost:
        if (r9 == false) goto L73;
     */
    /* JADX WARN: Code restructure failed: missing block: B:73:0x016e, code lost:
        if ((r16 + 2) <= 16) goto L72;
     */
    /* JADX WARN: Code restructure failed: missing block: B:74:0x0171, code lost:
        return null;
     */
    /* JADX WARN: Code restructure failed: missing block: B:76:0x0173, code lost:
        r1 = r16;
        r16 = r16 + 1;
        r0[r1] = (byte) ((r10 >> 8) & org.bouncycastle.pqc.crypto.rainbow.util.GF2Field.MASK);
        r16 = r16 + 1;
        r0[r16] = (byte) (r10 & org.bouncycastle.pqc.crypto.rainbow.util.GF2Field.MASK);
     */
    /* JADX WARN: Code restructure failed: missing block: B:78:0x0196, code lost:
        if (r7 == (-1)) goto L84;
     */
    /* JADX WARN: Code restructure failed: missing block: B:79:0x0199, code lost:
        r0 = r16 - r7;
     */
    /* JADX WARN: Code restructure failed: missing block: B:80:0x01a3, code lost:
        if (r16 != 16) goto L78;
     */
    /* JADX WARN: Code restructure failed: missing block: B:81:0x01a6, code lost:
        return null;
     */
    /* JADX WARN: Code restructure failed: missing block: B:83:0x01a8, code lost:
        r15 = 1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:85:0x01af, code lost:
        if (r15 > r0) goto L82;
     */
    /* JADX WARN: Code restructure failed: missing block: B:86:0x01b2, code lost:
        r0[16 - r15] = r0[(r7 + r0) - r15];
        r0[(r7 + r0) - r15] = 0;
        r15 = r15 + 1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:87:0x01d5, code lost:
        r16 = 16;
     */
    /* JADX WARN: Code restructure failed: missing block: B:89:0x01dd, code lost:
        if (r16 == 16) goto L87;
     */
    /* JADX WARN: Code restructure failed: missing block: B:90:0x01e0, code lost:
        return null;
     */
    /* JADX WARN: Code restructure failed: missing block: B:92:0x01e2, code lost:
        r0 = convertFromIPv4MappedAddress(r0);
     */
    /* JADX WARN: Code restructure failed: missing block: B:93:0x01eb, code lost:
        if (r0 == null) goto L91;
     */
    /* JADX WARN: Code restructure failed: missing block: B:95:0x01f0, code lost:
        return r0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:97:0x01f3, code lost:
        return r0;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public static byte[] textToNumericFormatV6(java.lang.String r6) {
        /*
            Method dump skipped, instructions count: 500
            To view this dump change 'Code comments level' option to 'DEBUG'
        */
        throw new UnsupportedOperationException("Method not decompiled: org.openjsse.sun.net.util.IPAddressUtil.textToNumericFormatV6(java.lang.String):byte[]");
    }

    public static boolean isIPv4LiteralAddress(String src) {
        return textToNumericFormatV4(src) != null;
    }

    public static boolean isIPv6LiteralAddress(String src) {
        return textToNumericFormatV6(src) != null;
    }

    public static byte[] convertFromIPv4MappedAddress(byte[] addr) {
        if (isIPv4MappedAddress(addr)) {
            byte[] newAddr = new byte[4];
            System.arraycopy(addr, 12, newAddr, 0, 4);
            return newAddr;
        }
        return null;
    }

    private static boolean isIPv4MappedAddress(byte[] addr) {
        if (addr.length >= 16 && addr[0] == 0 && addr[1] == 0 && addr[2] == 0 && addr[3] == 0 && addr[4] == 0 && addr[5] == 0 && addr[6] == 0 && addr[7] == 0 && addr[8] == 0 && addr[9] == 0 && addr[10] == -1 && addr[11] == -1) {
            return true;
        }
        return false;
    }

    public static boolean match(char c, long lowMask, long highMask) {
        return c < '@' ? ((1 << c) & lowMask) != 0 : c < 128 && ((1 << (c - 64)) & highMask) != 0;
    }

    public static int scan(String s, long lowMask, long highMask) {
        int len;
        boolean match;
        int i = -1;
        if (s == null || (len = s.length()) == 0) {
            return -1;
        }
        boolean match2 = false;
        do {
            i++;
            if (i >= len) {
                break;
            }
            match = match(s.charAt(i), lowMask, highMask);
            match2 = match;
        } while (!match);
        if (match2) {
            return i;
        }
        return -1;
    }

    public static int scan(String s, long lowMask, long highMask, char[] others) {
        int len;
        int i = -1;
        if (s == null || (len = s.length()) == 0) {
            return -1;
        }
        boolean match = false;
        char c0 = others[0];
        while (true) {
            i++;
            if (i >= len) {
                break;
            }
            char c = s.charAt(i);
            boolean match2 = match(c, lowMask, highMask);
            match = match2;
            if (!match2) {
                if (c >= c0 && Arrays.binarySearch(others, c) > -1) {
                    match = true;
                    break;
                }
            } else {
                break;
            }
        }
        if (match) {
            return i;
        }
        return -1;
    }

    private static String describeChar(char c) {
        return (c < ' ' || c == 127) ? c == '\n' ? "LF" : c == '\r' ? "CR" : "control char (code=" + ((int) c) + ")" : c == '\\' ? "'\\'" : "'" + c + "'";
    }

    private static String checkUserInfo(String str) {
        int index = scan(str, -9223231260711714817L, H_EXCLUDE);
        if (index >= 0) {
            return "Illegal character found in user-info: " + describeChar(str.charAt(index));
        }
        return null;
    }

    private static String checkHost(String str) {
        String str2;
        int index;
        if (str.startsWith("[") && str.endsWith("]")) {
            String str3 = str.substring(1, str.length() - 1);
            if (isIPv6LiteralAddress(str3)) {
                int index2 = str3.indexOf(37);
                if (index2 >= 0 && (index = scan((str2 = str3.substring(index2)), L_NON_PRINTABLE, -9223372036183687168L)) >= 0) {
                    return "Illegal character found in IPv6 scoped address: " + describeChar(str2.charAt(index));
                }
                return null;
            }
            return "Unrecognized IPv6 address format";
        }
        int index3 = scan(str, L_EXCLUDE, H_EXCLUDE);
        if (index3 >= 0) {
            return "Illegal character found in host: " + describeChar(str.charAt(index3));
        }
        return null;
    }

    private static String checkAuth(String str) {
        int index = scan(str, -9223231260711714817L, -9223372036586340352L);
        if (index >= 0) {
            return "Illegal character found in authority: " + describeChar(str.charAt(index));
        }
        return null;
    }

    public static String checkAuthority(URL url) {
        if (url == null) {
            return null;
        }
        String u = url.getUserInfo();
        String s = checkUserInfo(u);
        if (s != null) {
            return s;
        }
        String h = url.getHost();
        String s2 = checkHost(h);
        if (s2 != null) {
            return s2;
        }
        if (h == null && u == null) {
            return checkAuth(url.getAuthority());
        }
        return null;
    }

    public static String checkExternalForm(URL url) {
        if (url == null) {
            return null;
        }
        String s = url.getUserInfo();
        int index = scan(s, 140741783322623L, H_NON_PRINTABLE);
        if (index >= 0) {
            return "Illegal character found in authority: " + describeChar(s.charAt(index));
        }
        String s2 = checkHostString(url.getHost());
        if (s2 != null) {
            return s2;
        }
        return null;
    }

    public static String checkHostString(String host) {
        int index;
        if (host != null && (index = scan(host, 140741783322623L, H_NON_PRINTABLE, OTHERS)) >= 0) {
            return "Illegal character found in host: " + describeChar(host.charAt(index));
        }
        return null;
    }
}