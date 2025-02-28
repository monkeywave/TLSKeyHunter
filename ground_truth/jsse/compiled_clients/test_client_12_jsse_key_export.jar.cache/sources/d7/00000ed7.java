package org.bouncycastle.util;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/util/IPAddress.class */
public class IPAddress {
    public static boolean isValid(String str) {
        return isValidIPv4(str) || isValidIPv6(str);
    }

    public static boolean isValidWithNetMask(String str) {
        return isValidIPv4WithNetmask(str) || isValidIPv6WithNetmask(str);
    }

    public static boolean isValidIPv4(String str) {
        int indexOf;
        if (str.length() == 0) {
            return false;
        }
        int i = 0;
        String str2 = str + ".";
        int i2 = 0;
        while (i2 < str2.length() && (indexOf = str2.indexOf(46, i2)) > i2) {
            if (i == 4) {
                return false;
            }
            try {
                int parseInt = Integer.parseInt(str2.substring(i2, indexOf));
                if (parseInt < 0 || parseInt > 255) {
                    return false;
                }
                i2 = indexOf + 1;
                i++;
            } catch (NumberFormatException e) {
                return false;
            }
        }
        return i == 4;
    }

    public static boolean isValidIPv4WithNetmask(String str) {
        int indexOf = str.indexOf("/");
        String substring = str.substring(indexOf + 1);
        return indexOf > 0 && isValidIPv4(str.substring(0, indexOf)) && (isValidIPv4(substring) || isMaskValue(substring, 32));
    }

    public static boolean isValidIPv6WithNetmask(String str) {
        int indexOf = str.indexOf("/");
        String substring = str.substring(indexOf + 1);
        return indexOf > 0 && isValidIPv6(str.substring(0, indexOf)) && (isValidIPv6(substring) || isMaskValue(substring, 128));
    }

    private static boolean isMaskValue(String str, int i) {
        try {
            int parseInt = Integer.parseInt(str);
            return parseInt >= 0 && parseInt <= i;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    public static boolean isValidIPv6(String str) {
        int indexOf;
        if (str.length() == 0) {
            return false;
        }
        int i = 0;
        String str2 = str + ":";
        boolean z = false;
        int i2 = 0;
        while (i2 < str2.length() && (indexOf = str2.indexOf(58, i2)) >= i2) {
            if (i == 8) {
                return false;
            }
            if (i2 != indexOf) {
                String substring = str2.substring(i2, indexOf);
                if (indexOf != str2.length() - 1 || substring.indexOf(46) <= 0) {
                    try {
                        int parseInt = Integer.parseInt(str2.substring(i2, indexOf), 16);
                        if (parseInt < 0 || parseInt > 65535) {
                            return false;
                        }
                    } catch (NumberFormatException e) {
                        return false;
                    }
                } else if (!isValidIPv4(substring)) {
                    return false;
                } else {
                    i++;
                }
            } else if (indexOf != 1 && indexOf != str2.length() - 1 && z) {
                return false;
            } else {
                z = true;
            }
            i2 = indexOf + 1;
            i++;
        }
        return i == 8 || z;
    }
}