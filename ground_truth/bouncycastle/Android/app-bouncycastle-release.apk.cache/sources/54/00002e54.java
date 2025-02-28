package org.bouncycastle.tls.crypto.impl.jcajce;

import java.security.Provider;
import java.security.Security;
import org.bouncycastle.tls.HashAlgorithm;
import org.bouncycastle.tls.SignatureAlgorithm;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.util.Strings;

/* loaded from: classes2.dex */
class JcaUtils {
    JcaUtils() {
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static String getJcaAlgorithmName(SignatureAndHashAlgorithm signatureAndHashAlgorithm) {
        return HashAlgorithm.getName(signatureAndHashAlgorithm.getHash()) + "WITH" + Strings.toUpperCase(SignatureAlgorithm.getName(signatureAndHashAlgorithm.getSignature()));
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static boolean isSunMSCAPIProvider(Provider provider) {
        return provider != null && isSunMSCAPIProviderName(provider.getName());
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static boolean isSunMSCAPIProviderActive() {
        return Security.getProvider("SunMSCAPI") != null;
    }

    static boolean isSunMSCAPIProviderName(String str) {
        return "SunMSCAPI".equals(str);
    }
}