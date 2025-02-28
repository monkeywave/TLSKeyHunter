package org.bouncycastle.jsse.provider;

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import org.bouncycastle.tls.NamedGroup;
import org.bouncycastle.tls.SignatureScheme;

/* loaded from: classes2.dex */
abstract class FipsUtils {
    private static final boolean provAllowGCMCiphersIn12 = PropertyUtils.getBooleanSystemProperty("org.bouncycastle.jsse.fips.allowGCMCiphersIn12", false);
    private static final boolean provAllowRSAKeyExchange = PropertyUtils.getBooleanSystemProperty("org.bouncycastle.jsse.fips.allowRSAKeyExchange", false);
    private static final Set<String> FIPS_SUPPORTED_CIPHERSUITES = createFipsSupportedCipherSuites();
    private static final Set<String> FIPS_SUPPORTED_PROTOCOLS = createFipsSupportedProtocols();

    FipsUtils() {
    }

    private static Set<String> createFipsSupportedCipherSuites() {
        HashSet hashSet = new HashSet();
        hashSet.add("TLS_AES_128_CCM_8_SHA256");
        hashSet.add("TLS_AES_128_CCM_SHA256");
        hashSet.add("TLS_AES_128_GCM_SHA256");
        hashSet.add("TLS_AES_256_GCM_SHA384");
        hashSet.add("TLS_DHE_DSS_WITH_AES_128_CBC_SHA");
        hashSet.add("TLS_DHE_DSS_WITH_AES_128_CBC_SHA256");
        hashSet.add("TLS_DHE_DSS_WITH_AES_256_CBC_SHA");
        hashSet.add("TLS_DHE_DSS_WITH_AES_256_CBC_SHA256");
        hashSet.add("TLS_DHE_RSA_WITH_AES_128_CBC_SHA");
        hashSet.add("TLS_DHE_RSA_WITH_AES_128_CBC_SHA256");
        hashSet.add("TLS_DHE_RSA_WITH_AES_128_CCM");
        hashSet.add("TLS_DHE_RSA_WITH_AES_128_CCM_8");
        hashSet.add("TLS_DHE_RSA_WITH_AES_256_CBC_SHA");
        hashSet.add("TLS_DHE_RSA_WITH_AES_256_CBC_SHA256");
        hashSet.add("TLS_DHE_RSA_WITH_AES_256_CCM");
        hashSet.add("TLS_DHE_RSA_WITH_AES_256_CCM_8");
        hashSet.add("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA");
        hashSet.add("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256");
        hashSet.add("TLS_ECDHE_ECDSA_WITH_AES_128_CCM");
        hashSet.add("TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8");
        hashSet.add("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA");
        hashSet.add("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384");
        hashSet.add("TLS_ECDHE_ECDSA_WITH_AES_256_CCM");
        hashSet.add("TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8");
        hashSet.add("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA");
        hashSet.add("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256");
        hashSet.add("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA");
        hashSet.add("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384");
        boolean z = provAllowGCMCiphersIn12;
        if (z) {
            hashSet.add("TLS_DHE_DSS_WITH_AES_128_GCM_SHA256");
            hashSet.add("TLS_DHE_DSS_WITH_AES_256_GCM_SHA384");
            hashSet.add("TLS_DHE_RSA_WITH_AES_128_GCM_SHA256");
            hashSet.add("TLS_DHE_RSA_WITH_AES_256_GCM_SHA384");
            hashSet.add("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256");
            hashSet.add("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384");
            hashSet.add("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256");
            hashSet.add("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384");
        }
        if (provAllowRSAKeyExchange) {
            hashSet.add("TLS_RSA_WITH_AES_128_CBC_SHA");
            hashSet.add("TLS_RSA_WITH_AES_128_CBC_SHA256");
            hashSet.add("TLS_RSA_WITH_AES_128_CCM");
            hashSet.add("TLS_RSA_WITH_AES_128_CCM_8");
            hashSet.add("TLS_RSA_WITH_AES_256_CBC_SHA");
            hashSet.add("TLS_RSA_WITH_AES_256_CBC_SHA256");
            hashSet.add("TLS_RSA_WITH_AES_256_CCM");
            hashSet.add("TLS_RSA_WITH_AES_256_CCM_8");
            if (z) {
                hashSet.add("TLS_RSA_WITH_AES_128_GCM_SHA256");
                hashSet.add("TLS_RSA_WITH_AES_256_GCM_SHA384");
            }
        }
        return Collections.unmodifiableSet(hashSet);
    }

    private static Set<String> createFipsSupportedProtocols() {
        HashSet hashSet = new HashSet();
        hashSet.add("TLSv1");
        hashSet.add("TLSv1.1");
        hashSet.add("TLSv1.2");
        hashSet.add("TLSv1.3");
        return Collections.unmodifiableSet(hashSet);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static boolean isFipsCipherSuite(String str) {
        return str != null && FIPS_SUPPORTED_CIPHERSUITES.contains(str);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static boolean isFipsNamedGroup(int i) {
        switch (i) {
            case 23:
            case 24:
            case 25:
                return true;
            default:
                switch (i) {
                    case 256:
                    case 257:
                    case NamedGroup.ffdhe4096 /* 258 */:
                    case NamedGroup.ffdhe6144 /* 259 */:
                    case NamedGroup.ffdhe8192 /* 260 */:
                        return true;
                    default:
                        return false;
                }
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static boolean isFipsProtocol(String str) {
        return str != null && FIPS_SUPPORTED_PROTOCOLS.contains(str);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static boolean isFipsSignatureScheme(int i) {
        switch (i) {
            case 513:
            case 514:
            case SignatureScheme.ecdsa_sha1 /* 515 */:
            case 769:
            case 770:
            case 771:
            case 1025:
            case 1026:
            case SignatureScheme.ecdsa_secp256r1_sha256 /* 1027 */:
            case SignatureScheme.rsa_pkcs1_sha384 /* 1281 */:
            case SignatureScheme.ecdsa_secp384r1_sha384 /* 1283 */:
            case SignatureScheme.rsa_pkcs1_sha512 /* 1537 */:
            case SignatureScheme.ecdsa_secp521r1_sha512 /* 1539 */:
            case SignatureScheme.rsa_pss_rsae_sha256 /* 2052 */:
            case SignatureScheme.rsa_pss_rsae_sha384 /* 2053 */:
            case SignatureScheme.rsa_pss_rsae_sha512 /* 2054 */:
            case SignatureScheme.rsa_pss_pss_sha256 /* 2057 */:
            case SignatureScheme.rsa_pss_pss_sha384 /* 2058 */:
            case SignatureScheme.rsa_pss_pss_sha512 /* 2059 */:
                return true;
            default:
                return false;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void removeNonFipsCipherSuites(Collection<String> collection) {
        collection.retainAll(FIPS_SUPPORTED_CIPHERSUITES);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void removeNonFipsProtocols(Collection<String> collection) {
        collection.retainAll(FIPS_SUPPORTED_PROTOCOLS);
    }
}