package org.bouncycastle.jsse.provider;

import java.security.cert.CertPathBuilder;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.X509Certificate;
import java.util.Map;

/* loaded from: classes2.dex */
abstract class PKIXUtil {
    private static final Class<?> pkixRevocationCheckerClass;

    static {
        Class<?> cls;
        try {
            cls = ReflectionUtil.getClass("java.security.cert.PKIXRevocationChecker");
        } catch (Exception unused) {
            cls = null;
        }
        pkixRevocationCheckerClass = cls;
    }

    PKIXUtil() {
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void addStatusResponses(CertPathBuilder certPathBuilder, PKIXBuilderParameters pKIXBuilderParameters, Map<X509Certificate, byte[]> map) {
        if (pkixRevocationCheckerClass != null) {
            JsseUtils_8.addStatusResponses(certPathBuilder, pKIXBuilderParameters, map);
        }
    }
}