package org.openjsse.sun.security.validator;

import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.time.Month;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import sun.security.validator.ValidatorException;
import sun.security.x509.X509CertImpl;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/validator/SymantecTLSPolicy.class */
final class SymantecTLSPolicy {
    private static final LocalDate DECEMBER_31_2019 = LocalDate.of(2019, Month.DECEMBER, 31);
    private static final Map<String, LocalDate> EXEMPT_SUBCAS = new HashMap();
    private static final Set<String> FINGERPRINTS;
    private static final LocalDate APRIL_16_2019;

    static {
        EXEMPT_SUBCAS.put("AC2B922ECFD5E01711772FEA8ED372DE9D1E2245FCE3F57A9CDBEC77296A424B", DECEMBER_31_2019);
        EXEMPT_SUBCAS.put("A4FE7C7F15155F3F0AEF7AAA83CF6E06DEB97CA3F909DF920AC1490882D488ED", DECEMBER_31_2019);
        FINGERPRINTS = new HashSet(Arrays.asList("FF856A2D251DCD88D36656F450126798CFABAADE40799C722DE4D2B5DB36A73A", "37D51006C512EAAB626421F1EC8C92013FC5F82AE98EE533EB4619B8DEB4D06C", "5EDB7AC43B82A06A8761E8D7BE4979EBF2611F7DD79BF91C1C6B566A219ED766", "B478B812250DF878635C2AA7EC7D155EAA625EE82916E2CD294361886CD1FBD4", "A0459B9F63B22559F5FA5D4C6DB3F9F72FF19342033578F073BF1D1B46CBB912", "8D722F81A9C113C0791DF136A2966DB26C950A971DB46B4199F4EA54B78BFB9F", "A4310D50AF18A6447190372A86AFAF8B951FFB431D837F1E5688B45971ED1557", "4B03F45807AD70F21BFC2CAE71C9FDE4604C064CF5FFB686BAE5DBAAD7FDD34C", "3F9F27D583204B9E09C8A3D2066C4B57D3A2479C3693650880505698105DBCE9", "3A43E220FE7F3EA9653D1E21742EAC2B75C20FD8980305BC502CAF8C2D9B41A1", "A4B6B3996FC2F306B3FD8681BD63413D8C5009CC4FA329C2CCF0E2FA1B140305", "83CE3C1229688A593D485F81973C0F9195431EDA37CC5E36430E79C7A888638B", "EB04CF5EB1F39AFA762F2BB120F296CBA520C1B97DB1589565B81CB9A17B7244", "69DDD7EA90BB57C93E135DC85EA6FCD5480B603239BDC454FC758B2A26CF7F79", "9ACFAB7E43C8D880D06B262A94DEEEE4B4659989C3D0CAF19BAF6405E41AB7DF", "2399561127A57125DE8CEFEA610DDF2FA078B5C8067F4E828290BFB860E84B3C"));
        APRIL_16_2019 = LocalDate.of(2019, Month.APRIL, 16);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void checkDistrust(X509Certificate[] chain) throws ValidatorException {
        X509Certificate anchor = chain[chain.length - 1];
        if (FINGERPRINTS.contains(fingerprint(anchor))) {
            Date notBefore = chain[0].getNotBefore();
            LocalDate ldNotBefore = notBefore.toInstant().atZone(ZoneOffset.UTC).toLocalDate();
            if (chain.length > 2) {
                X509Certificate subCA = chain[chain.length - 2];
                LocalDate distrustDate = EXEMPT_SUBCAS.get(fingerprint(subCA));
                if (distrustDate != null) {
                    checkNotBefore(ldNotBefore, distrustDate, anchor);
                    return;
                }
            }
            checkNotBefore(ldNotBefore, APRIL_16_2019, anchor);
        }
    }

    private static String fingerprint(X509Certificate cert) {
        if (cert instanceof X509CertImpl) {
            return ((X509CertImpl) cert).getFingerprint("SHA-256");
        }
        return X509CertImpl.getFingerprint("SHA-256", cert);
    }

    private static void checkNotBefore(LocalDate notBeforeDate, LocalDate distrustDate, X509Certificate anchor) throws ValidatorException {
        if (notBeforeDate.isAfter(distrustDate)) {
            throw new ValidatorException("TLS Server certificate issued after " + distrustDate + " and anchored by a distrusted legacy Symantec root CA: " + anchor.getSubjectX500Principal(), ValidatorException.T_UNTRUSTED_CERT, anchor);
        }
    }

    private SymantecTLSPolicy() {
    }
}