package org.openjsse.sun.security.validator;

import java.security.AlgorithmConstraints;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.List;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/validator/Validator.class */
public abstract class Validator {
    static final X509Certificate[] CHAIN0 = new X509Certificate[0];
    public static final String TYPE_SIMPLE = "Simple";
    public static final String TYPE_PKIX = "PKIX";
    public static final String VAR_GENERIC = "generic";
    public static final String VAR_CODE_SIGNING = "code signing";
    public static final String VAR_JCE_SIGNING = "jce signing";
    public static final String VAR_TLS_CLIENT = "tls client";
    public static final String VAR_TLS_SERVER = "tls server";
    public static final String VAR_TSA_SERVER = "tsa server";
    public static final String VAR_PLUGIN_CODE_SIGNING = "plugin code signing";
    private final String type;
    final EndEntityChecker endEntityChecker;
    final String variant;
    @Deprecated
    volatile Date validationDate;

    abstract X509Certificate[] engineValidate(X509Certificate[] x509CertificateArr, Collection<X509Certificate> collection, List<byte[]> list, AlgorithmConstraints algorithmConstraints, Object obj) throws CertificateException;

    public abstract Collection<X509Certificate> getTrustedCertificates();

    /* JADX INFO: Access modifiers changed from: package-private */
    public Validator(String type, String variant) {
        this.type = type;
        this.variant = variant;
        this.endEntityChecker = EndEntityChecker.getInstance(type, variant);
    }

    public static Validator getInstance(String type, String variant, KeyStore ks) {
        return getInstance(type, variant, TrustStoreUtil.getTrustedCerts(ks));
    }

    public static Validator getInstance(String type, String variant, Collection<X509Certificate> trustedCerts) {
        if (type.equals(TYPE_SIMPLE)) {
            return new SimpleValidator(variant, trustedCerts);
        }
        if (type.equals(TYPE_PKIX)) {
            return new PKIXValidator(variant, trustedCerts);
        }
        throw new IllegalArgumentException("Unknown validator type: " + type);
    }

    public static Validator getInstance(String type, String variant, PKIXBuilderParameters params) {
        if (!type.equals(TYPE_PKIX)) {
            throw new IllegalArgumentException("getInstance(PKIXBuilderParameters) can only be used with PKIX validator");
        }
        return new PKIXValidator(variant, params);
    }

    public final X509Certificate[] validate(X509Certificate[] chain) throws CertificateException {
        return validate(chain, null, null);
    }

    public final X509Certificate[] validate(X509Certificate[] chain, Collection<X509Certificate> otherCerts) throws CertificateException {
        return validate(chain, otherCerts, null);
    }

    public final X509Certificate[] validate(X509Certificate[] chain, Collection<X509Certificate> otherCerts, Object parameter) throws CertificateException {
        return validate(chain, otherCerts, Collections.emptyList(), null, parameter);
    }

    public final X509Certificate[] validate(X509Certificate[] chain, Collection<X509Certificate> otherCerts, List<byte[]> responseList, AlgorithmConstraints constraints, Object parameter) throws CertificateException {
        X509Certificate[] chain2 = engineValidate(chain, otherCerts, responseList, constraints, parameter);
        if (chain2.length > 1) {
            boolean checkUnresolvedCritExts = this.type != TYPE_PKIX;
            this.endEntityChecker.check(chain2, parameter, checkUnresolvedCritExts);
        }
        return chain2;
    }

    @Deprecated
    public void setValidationDate(Date validationDate) {
        this.validationDate = validationDate;
    }
}