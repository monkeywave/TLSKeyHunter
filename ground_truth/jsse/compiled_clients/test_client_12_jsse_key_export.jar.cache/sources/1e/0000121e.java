package org.openjsse.sun.security.ssl;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIServerName;
import sun.net.util.IPAddressUtil;
import sun.security.action.GetPropertyAction;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/Utilities.class */
public final class Utilities {
    private static final String indent = "  ";
    static final char[] hexDigits = "0123456789ABCDEF".toCharArray();
    private static final Pattern lineBreakPatern = Pattern.compile("\\r\\n|\\n|\\r");

    Utilities() {
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static List<SNIServerName> addToSNIServerNameList(List<SNIServerName> serverNames, String hostname) {
        SNIServerName sniHostName = rawToSNIHostName(hostname);
        if (sniHostName == null) {
            return serverNames;
        }
        int size = serverNames.size();
        List<SNIServerName> sniList = size != 0 ? new ArrayList<>(serverNames) : new ArrayList<>(1);
        boolean reset = false;
        int i = 0;
        while (true) {
            if (i >= size) {
                break;
            }
            SNIServerName serverName = sniList.get(i);
            if (serverName.getType() != 0) {
                i++;
            } else {
                sniList.set(i, sniHostName);
                if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                    SSLLogger.fine("the previous server name in SNI (" + serverName + ") was replaced with (" + sniHostName + ")", new Object[0]);
                }
                reset = true;
            }
        }
        if (!reset) {
            sniList.add(sniHostName);
        }
        return Collections.unmodifiableList(sniList);
    }

    private static SNIHostName rawToSNIHostName(String hostname) {
        SNIHostName sniHostName = null;
        if (hostname != null && hostname.indexOf(46) > 0 && !hostname.endsWith(".") && !IPAddressUtil.isIPv4LiteralAddress(hostname) && !IPAddressUtil.isIPv6LiteralAddress(hostname)) {
            try {
                sniHostName = new SNIHostName(hostname);
            } catch (IllegalArgumentException e) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                    SSLLogger.fine(hostname + "\" is not a legal HostName for  server name indication", new Object[0]);
                }
            }
        }
        return sniHostName;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static boolean getBooleanProperty(String propName, boolean defaultValue) {
        String b = GetPropertyAction.privilegedGetProperty(propName);
        if (b == null) {
            return defaultValue;
        }
        if (b.equalsIgnoreCase("false")) {
            return false;
        }
        if (b.equalsIgnoreCase("true")) {
            return true;
        }
        throw new RuntimeException("Value of " + propName + " must either be 'true' or 'false'");
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static int getUIntProperty(String propName, int defaultValue) {
        String val = GetPropertyAction.privilegedGetProperty(propName);
        int value = defaultValue;
        if (val != null && !val.isEmpty()) {
            try {
                value = Integer.parseUnsignedInt(val);
            } catch (NumberFormatException e) {
                throw new RuntimeException("Value of " + propName + " must be unsigned integer");
            }
        }
        return value;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static String indent(String source) {
        return indent(source, indent);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static String indent(String source, String prefix) {
        StringBuilder builder = new StringBuilder();
        if (source == null) {
            builder.append("\n" + prefix + "<blank message>");
        } else {
            String[] lines = lineBreakPatern.split(source);
            boolean isFirst = true;
            for (String line : lines) {
                if (isFirst) {
                    isFirst = false;
                } else {
                    builder.append("\n");
                }
                builder.append(prefix).append(line);
            }
        }
        return builder.toString();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static String toHexString(byte b) {
        return String.valueOf(hexDigits[(b >> 4) & 15]) + String.valueOf(hexDigits[b & 15]);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static String byte16HexString(int id) {
        return "0x" + hexDigits[(id >> 12) & 15] + hexDigits[(id >> 8) & 15] + hexDigits[(id >> 4) & 15] + hexDigits[id & 15];
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static String toHexString(byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            return "";
        }
        StringBuilder builder = new StringBuilder(bytes.length * 3);
        boolean isFirst = true;
        for (byte b : bytes) {
            if (isFirst) {
                isFirst = false;
            } else {
                builder.append(' ');
            }
            builder.append(hexDigits[(b >> 4) & 15]);
            builder.append(hexDigits[b & 15]);
        }
        return builder.toString();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static String toHexString(long lv) {
        StringBuilder builder = new StringBuilder(128);
        boolean isFirst = true;
        do {
            if (isFirst) {
                isFirst = false;
            } else {
                builder.append(' ');
            }
            builder.append(hexDigits[(int) (lv & 15)]);
            long lv2 = lv >>> 4;
            builder.append(hexDigits[(int) (lv2 & 15)]);
            lv = lv2 >>> 4;
        } while (lv != 0);
        builder.reverse();
        return builder.toString();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static byte[] toByteArray(BigInteger bi) {
        byte[] b = bi.toByteArray();
        if (b.length > 1 && b[0] == 0) {
            int n = b.length - 1;
            byte[] newarray = new byte[n];
            System.arraycopy(b, 1, newarray, 0, n);
            b = newarray;
        }
        return b;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static boolean equals(byte[] arr1, int st1, int end1, byte[] arr2, int st2, int end2) {
        int i = st1;
        for (int j = st2; i < end1 && j < end2; j++) {
            if (arr1[i] == arr2[j]) {
                i++;
            } else {
                return false;
            }
        }
        return true;
    }
}