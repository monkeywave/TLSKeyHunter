package org.openjsse.sun.security.validator;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import sun.security.validator.ValidatorException;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/validator/EndEntityChecker.class */
public class EndEntityChecker {
    private static final String OID_EXTENDED_KEY_USAGE = "2.5.29.37";
    private static final String OID_EKU_TLS_SERVER = "1.3.6.1.5.5.7.3.1";
    private static final String OID_EKU_TLS_CLIENT = "1.3.6.1.5.5.7.3.2";
    private static final String OID_EKU_CODE_SIGNING = "1.3.6.1.5.5.7.3.3";
    private static final String OID_EKU_TIME_STAMPING = "1.3.6.1.5.5.7.3.8";
    private static final String OID_EKU_ANY_USAGE = "2.5.29.37.0";
    private static final String OID_EKU_NS_SGC = "2.16.840.1.113730.4.1";
    private static final String OID_EKU_MS_SGC = "1.3.6.1.4.1.311.10.3.3";
    private static final String OID_SUBJECT_ALT_NAME = "2.5.29.17";
    private static final String NSCT_SSL_CLIENT = "ssl_client";
    private static final String NSCT_SSL_SERVER = "ssl_server";
    private static final String NSCT_CODE_SIGNING = "object_signing";
    private static final int KU_SIGNATURE = 0;
    private static final int KU_KEY_ENCIPHERMENT = 2;
    private static final int KU_KEY_AGREEMENT = 4;
    private static final Collection<String> KU_SERVER_SIGNATURE = Arrays.asList("DHE_DSS", "DHE_RSA", "ECDHE_ECDSA", "ECDHE_RSA", "RSA_EXPORT", "UNKNOWN");
    private static final Collection<String> KU_SERVER_ENCRYPTION = Arrays.asList("RSA");
    private static final Collection<String> KU_SERVER_KEY_AGREEMENT = Arrays.asList("DH_DSS", "DH_RSA", "ECDH_ECDSA", "ECDH_RSA");
    private final String variant;
    private final String type;

    private EndEntityChecker(String type, String variant) {
        this.type = type;
        this.variant = variant;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static EndEntityChecker getInstance(String type, String variant) {
        return new EndEntityChecker(type, variant);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void check(X509Certificate[] chain, Object parameter, boolean checkUnresolvedCritExts) throws CertificateException {
        if (this.variant.equals(Validator.VAR_GENERIC)) {
            return;
        }
        Set<String> exts = getCriticalExtensions(chain[0]);
        if (this.variant.equals(Validator.VAR_TLS_SERVER)) {
            checkTLSServer(chain[0], (String) parameter, exts);
        } else if (this.variant.equals(Validator.VAR_TLS_CLIENT)) {
            checkTLSClient(chain[0], exts);
        } else if (this.variant.equals(Validator.VAR_CODE_SIGNING)) {
            checkCodeSigning(chain[0], exts);
        } else if (this.variant.equals(Validator.VAR_JCE_SIGNING)) {
            checkCodeSigning(chain[0], exts);
        } else if (this.variant.equals(Validator.VAR_PLUGIN_CODE_SIGNING)) {
            checkCodeSigning(chain[0], exts);
        } else if (this.variant.equals(Validator.VAR_TSA_SERVER)) {
            checkTSAServer(chain[0], exts);
        } else {
            throw new CertificateException("Unknown variant: " + this.variant);
        }
        if (checkUnresolvedCritExts) {
            checkRemainingExtensions(exts);
        }
        Iterator it = CADistrustPolicy.POLICIES.iterator();
        while (it.hasNext()) {
            CADistrustPolicy policy = (CADistrustPolicy) it.next();
            policy.checkDistrust(this.variant, chain);
        }
    }

    private Set<String> getCriticalExtensions(X509Certificate cert) {
        Set<String> exts = cert.getCriticalExtensionOIDs();
        if (exts == null) {
            exts = Collections.emptySet();
        }
        return exts;
    }

    private void checkRemainingExtensions(Set<String> exts) throws CertificateException {
        exts.remove("2.5.29.19");
        exts.remove(OID_SUBJECT_ALT_NAME);
        if (!exts.isEmpty()) {
            throw new CertificateException("Certificate contains unsupported critical extensions: " + exts);
        }
    }

    private boolean checkEKU(X509Certificate cert, Set<String> exts, String expectedEKU) throws CertificateException {
        List<String> eku = cert.getExtendedKeyUsage();
        return eku == null || eku.contains(expectedEKU) || eku.contains(OID_EKU_ANY_USAGE);
    }

    private boolean checkKeyUsage(X509Certificate cert, int bit) throws CertificateException {
        boolean[] keyUsage = cert.getKeyUsage();
        if (keyUsage == null) {
            return true;
        }
        return keyUsage.length > bit && keyUsage[bit];
    }

    private void checkTLSClient(X509Certificate cert, Set<String> exts) throws CertificateException {
        if (!checkKeyUsage(cert, 0)) {
            throw new ValidatorException("KeyUsage does not allow digital signatures", ValidatorException.T_EE_EXTENSIONS, cert);
        }
        if (!checkEKU(cert, exts, OID_EKU_TLS_CLIENT)) {
            throw new ValidatorException("Extended key usage does not permit use for TLS client authentication", ValidatorException.T_EE_EXTENSIONS, cert);
        }
        if (!SimpleValidator.getNetscapeCertTypeBit(cert, NSCT_SSL_CLIENT)) {
            throw new ValidatorException("Netscape cert type does not permit use for SSL client", ValidatorException.T_EE_EXTENSIONS, cert);
        }
        exts.remove("2.5.29.15");
        exts.remove(OID_EXTENDED_KEY_USAGE);
        exts.remove("2.16.840.1.113730.1.1");
    }

    private void checkTLSServer(X509Certificate cert, String parameter, Set<String> exts) throws CertificateException {
        if (KU_SERVER_ENCRYPTION.contains(parameter)) {
            if (!checkKeyUsage(cert, 2)) {
                throw new ValidatorException("KeyUsage does not allow key encipherment", ValidatorException.T_EE_EXTENSIONS, cert);
            }
        } else if (KU_SERVER_SIGNATURE.contains(parameter)) {
            if (!checkKeyUsage(cert, 0)) {
                throw new ValidatorException("KeyUsage does not allow digital signatures", ValidatorException.T_EE_EXTENSIONS, cert);
            }
        } else if (KU_SERVER_KEY_AGREEMENT.contains(parameter)) {
            if (!checkKeyUsage(cert, 4)) {
                throw new ValidatorException("KeyUsage does not allow key agreement", ValidatorException.T_EE_EXTENSIONS, cert);
            }
        } else {
            throw new CertificateException("Unknown authType: " + parameter);
        }
        if (!checkEKU(cert, exts, OID_EKU_TLS_SERVER) && !checkEKU(cert, exts, OID_EKU_MS_SGC) && !checkEKU(cert, exts, OID_EKU_NS_SGC)) {
            throw new ValidatorException("Extended key usage does not permit use for TLS server authentication", ValidatorException.T_EE_EXTENSIONS, cert);
        }
        if (!SimpleValidator.getNetscapeCertTypeBit(cert, NSCT_SSL_SERVER)) {
            throw new ValidatorException("Netscape cert type does not permit use for SSL server", ValidatorException.T_EE_EXTENSIONS, cert);
        }
        exts.remove("2.5.29.15");
        exts.remove(OID_EXTENDED_KEY_USAGE);
        exts.remove("2.16.840.1.113730.1.1");
    }

    private void checkCodeSigning(X509Certificate cert, Set<String> exts) throws CertificateException {
        if (!checkKeyUsage(cert, 0)) {
            throw new ValidatorException("KeyUsage does not allow digital signatures", ValidatorException.T_EE_EXTENSIONS, cert);
        }
        if (!checkEKU(cert, exts, OID_EKU_CODE_SIGNING)) {
            throw new ValidatorException("Extended key usage does not permit use for code signing", ValidatorException.T_EE_EXTENSIONS, cert);
        }
        if (!this.variant.equals(Validator.VAR_JCE_SIGNING)) {
            if (!SimpleValidator.getNetscapeCertTypeBit(cert, NSCT_CODE_SIGNING)) {
                throw new ValidatorException("Netscape cert type does not permit use for code signing", ValidatorException.T_EE_EXTENSIONS, cert);
            }
            exts.remove("2.16.840.1.113730.1.1");
        }
        exts.remove("2.5.29.15");
        exts.remove(OID_EXTENDED_KEY_USAGE);
    }

    private void checkTSAServer(X509Certificate cert, Set<String> exts) throws CertificateException {
        if (!checkKeyUsage(cert, 0)) {
            throw new ValidatorException("KeyUsage does not allow digital signatures", ValidatorException.T_EE_EXTENSIONS, cert);
        }
        if (cert.getExtendedKeyUsage() == null) {
            throw new ValidatorException("Certificate does not contain an extended key usage extension required for a TSA server", ValidatorException.T_EE_EXTENSIONS, cert);
        }
        if (!checkEKU(cert, exts, OID_EKU_TIME_STAMPING)) {
            throw new ValidatorException("Extended key usage does not permit use for TSA server", ValidatorException.T_EE_EXTENSIONS, cert);
        }
        exts.remove("2.5.29.15");
        exts.remove(OID_EXTENDED_KEY_USAGE);
    }
}