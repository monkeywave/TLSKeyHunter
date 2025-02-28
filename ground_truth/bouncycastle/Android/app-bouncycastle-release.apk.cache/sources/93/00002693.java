package org.bouncycastle.jsse.provider;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Security;
import java.util.logging.Level;
import java.util.logging.Logger;

/* loaded from: classes2.dex */
class PropertyUtils {
    private static final Logger LOG = Logger.getLogger(PropertyUtils.class.getName());

    PropertyUtils() {
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static boolean getBooleanSecurityProperty(String str, boolean z) {
        String securityProperty = getSecurityProperty(str);
        if (securityProperty != null) {
            if ("true".equalsIgnoreCase(securityProperty)) {
                LOG.info("Found boolean security property [" + str + "]: true");
                return true;
            } else if ("false".equalsIgnoreCase(securityProperty)) {
                LOG.info("Found boolean security property [" + str + "]: false");
                return false;
            } else {
                LOG.warning("Unrecognized value for boolean security property [" + str + "]: " + securityProperty);
            }
        }
        LOG.fine("Boolean security property [" + str + "] defaulted to: " + z);
        return z;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static boolean getBooleanSystemProperty(String str, boolean z) {
        String systemProperty = getSystemProperty(str);
        if (systemProperty != null) {
            if ("true".equalsIgnoreCase(systemProperty)) {
                LOG.info("Found boolean system property [" + str + "]: true");
                return true;
            } else if ("false".equalsIgnoreCase(systemProperty)) {
                LOG.info("Found boolean system property [" + str + "]: false");
                return false;
            } else {
                LOG.warning("Unrecognized value for boolean system property [" + str + "]: " + systemProperty);
            }
        }
        LOG.fine("Boolean system property [" + str + "] defaulted to: " + z);
        return z;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static int getIntegerSystemProperty(String str, int i, int i2, int i3) {
        String systemProperty = getSystemProperty(str);
        if (systemProperty != null) {
            try {
                int parseInt = Integer.parseInt(systemProperty);
                if (parseInt >= i2 && parseInt <= i3) {
                    LOG.info("Found integer system property [" + str + "]: " + parseInt);
                    return parseInt;
                }
                Logger logger = LOG;
                if (logger.isLoggable(Level.WARNING)) {
                    logger.warning("Out-of-range (" + getRangeString(i2, i3) + ") integer system property [" + str + "]: " + systemProperty);
                }
            } catch (Exception unused) {
                LOG.warning("Unrecognized value for integer system property [" + str + "]: " + systemProperty);
            }
        }
        LOG.fine("Integer system property [" + str + "] defaulted to: " + i);
        return i;
    }

    private static String getRangeString(int i, int i2) {
        StringBuilder sb = new StringBuilder(32);
        if (Integer.MIN_VALUE != i) {
            sb.append(i);
            sb.append(" <= ");
        }
        sb.append('x');
        if (Integer.MAX_VALUE != i2) {
            sb.append(" <= ");
            sb.append(i2);
        }
        return sb.toString();
    }

    static String getSecurityProperty(final String str) {
        return (String) AccessController.doPrivileged(new PrivilegedAction<String>() { // from class: org.bouncycastle.jsse.provider.PropertyUtils.1
            @Override // java.security.PrivilegedAction
            public String run() {
                return Security.getProperty(str);
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static String getSensitiveStringSystemProperty(String str) {
        String systemProperty = getSystemProperty(str);
        if (systemProperty != null) {
            LOG.info("Found sensitive string system property [" + str + "]");
            return systemProperty;
        }
        return null;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static String[] getStringArraySecurityProperty(String str, String str2) {
        return parseStringArray(getStringSecurityProperty(str, str2));
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static String[] getStringArraySystemProperty(String str) {
        return parseStringArray(getStringSystemProperty(str));
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static String getStringSecurityProperty(String str) {
        String securityProperty = getSecurityProperty(str);
        if (securityProperty != null) {
            LOG.info("Found string security property [" + str + "]: " + securityProperty);
            return securityProperty;
        }
        return null;
    }

    static String getStringSecurityProperty(String str, String str2) {
        String securityProperty = getSecurityProperty(str);
        if (securityProperty != null) {
            LOG.info("Found string security property [" + str + "]: " + securityProperty);
            return securityProperty;
        }
        LOG.warning("String security property [" + str + "] defaulted to: " + str2);
        return str2;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static String getStringSystemProperty(String str) {
        String systemProperty = getSystemProperty(str);
        if (systemProperty != null) {
            LOG.info("Found string system property [" + str + "]: " + systemProperty);
            return systemProperty;
        }
        return null;
    }

    static String getSystemProperty(final String str) {
        try {
            return (String) AccessController.doPrivileged(new PrivilegedAction<String>() { // from class: org.bouncycastle.jsse.provider.PropertyUtils.2
                @Override // java.security.PrivilegedAction
                public String run() {
                    return System.getProperty(str);
                }
            });
        } catch (RuntimeException e) {
            LOG.log(Level.WARNING, "Failed to get system property", (Throwable) e);
            return null;
        }
    }

    private static String[] parseStringArray(String str) {
        if (str == null) {
            return null;
        }
        String[] split = JsseUtils.stripDoubleQuotes(str.trim()).split(",");
        String[] strArr = new String[split.length];
        int i = 0;
        for (String str2 : split) {
            String trim = str2.trim();
            if (trim.length() >= 1) {
                strArr[i] = trim;
                i++;
            }
        }
        return JsseUtils.resize(strArr, i);
    }
}