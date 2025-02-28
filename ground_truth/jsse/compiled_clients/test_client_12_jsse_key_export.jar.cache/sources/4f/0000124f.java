package org.openjsse.sun.security.validator;

import java.io.IOException;
import java.security.AlgorithmConstraints;
import java.security.GeneralSecurityException;
import java.security.Principal;
import java.security.PublicKey;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.security.auth.x500.X500Principal;
import sun.security.provider.certpath.AlgorithmChecker;
import sun.security.provider.certpath.UntrustedChecker;
import sun.security.util.DerInputStream;
import sun.security.util.DerValue;
import sun.security.util.ObjectIdentifier;
import sun.security.validator.ValidatorException;
import sun.security.x509.KeyIdentifier;
import sun.security.x509.NetscapeCertTypeExtension;
import sun.security.x509.X509CertImpl;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/validator/SimpleValidator.class */
public final class SimpleValidator extends Validator {
    static final String OID_BASIC_CONSTRAINTS = "2.5.29.19";
    static final String OID_NETSCAPE_CERT_TYPE = "2.16.840.1.113730.1.1";
    static final String OID_KEY_USAGE = "2.5.29.15";
    static final String OID_EXTENDED_KEY_USAGE = "2.5.29.37";
    static final String OID_EKU_ANY_USAGE = "2.5.29.37.0";
    static final ObjectIdentifier OBJID_NETSCAPE_CERT_TYPE = NetscapeCertTypeExtension.NetscapeCertType_Id;
    private static final String NSCT_SSL_CA = "ssl_ca";
    private static final String NSCT_CODE_SIGNING_CA = "object_signing_ca";
    private final Map<X500Principal, List<X509Certificate>> trustedX500Principals;
    private final Collection<X509Certificate> trustedCerts;

    /* JADX INFO: Access modifiers changed from: package-private */
    public SimpleValidator(String variant, Collection<X509Certificate> trustedCerts) {
        super(Validator.TYPE_SIMPLE, variant);
        this.trustedCerts = trustedCerts;
        this.trustedX500Principals = new HashMap();
        for (X509Certificate cert : trustedCerts) {
            X500Principal principal = cert.getSubjectX500Principal();
            List<X509Certificate> list = this.trustedX500Principals.get(principal);
            if (list == null) {
                list = new ArrayList<>(2);
                this.trustedX500Principals.put(principal, list);
            }
            list.add(cert);
        }
    }

    @Override // org.openjsse.sun.security.validator.Validator
    public Collection<X509Certificate> getTrustedCertificates() {
        return this.trustedCerts;
    }

    @Override // org.openjsse.sun.security.validator.Validator
    X509Certificate[] engineValidate(X509Certificate[] chain, Collection<X509Certificate> otherCerts, List<byte[]> responseList, AlgorithmConstraints constraints, Object parameter) throws CertificateException {
        if (chain == null || chain.length == 0) {
            throw new CertificateException("null or zero-length certificate chain");
        }
        X509Certificate[] chain2 = buildTrustedChain(chain);
        Date date = this.validationDate;
        if (date == null) {
            date = new Date();
        }
        UntrustedChecker untrustedChecker = new UntrustedChecker();
        X509Certificate anchorCert = chain2[chain2.length - 1];
        try {
            untrustedChecker.check(anchorCert);
            TrustAnchor anchor = new TrustAnchor(anchorCert, null);
            AlgorithmChecker defaultAlgChecker = new AlgorithmChecker(anchor, this.variant);
            AlgorithmChecker appAlgChecker = null;
            if (constraints != null) {
                appAlgChecker = new AlgorithmChecker(anchor, constraints, (Date) null, this.variant);
            }
            int maxPathLength = chain2.length - 1;
            for (int i = chain2.length - 2; i >= 0; i--) {
                X509Certificate issuerCert = chain2[i + 1];
                X509Certificate cert = chain2[i];
                try {
                    untrustedChecker.check(cert, Collections.emptySet());
                    try {
                        defaultAlgChecker.check(cert, Collections.emptySet());
                        if (appAlgChecker != null) {
                            appAlgChecker.check(cert, Collections.emptySet());
                        }
                        if (!this.variant.equals(Validator.VAR_CODE_SIGNING) && !this.variant.equals(Validator.VAR_JCE_SIGNING)) {
                            cert.checkValidity(date);
                        }
                        if (!cert.getIssuerX500Principal().equals(issuerCert.getSubjectX500Principal())) {
                            throw new ValidatorException(ValidatorException.T_NAME_CHAINING, cert);
                        }
                        try {
                            cert.verify(issuerCert.getPublicKey());
                            if (i != 0) {
                                maxPathLength = checkExtensions(cert, maxPathLength);
                            }
                        } catch (GeneralSecurityException e) {
                            throw new ValidatorException(ValidatorException.T_SIGNATURE_ERROR, cert, e);
                        }
                    } catch (CertPathValidatorException cpve) {
                        throw new ValidatorException(ValidatorException.T_ALGORITHM_DISABLED, cert, cpve);
                    }
                } catch (CertPathValidatorException cpve2) {
                    throw new ValidatorException("Untrusted certificate: " + cert.getSubjectX500Principal(), ValidatorException.T_UNTRUSTED_CERT, cert, cpve2);
                }
            }
            return chain2;
        } catch (CertPathValidatorException cpve3) {
            throw new ValidatorException("Untrusted certificate: " + anchorCert.getSubjectX500Principal(), ValidatorException.T_UNTRUSTED_CERT, anchorCert, cpve3);
        }
    }

    private int checkExtensions(X509Certificate cert, int maxPathLen) throws CertificateException {
        Set<String> critSet = cert.getCriticalExtensionOIDs();
        if (critSet == null) {
            critSet = Collections.emptySet();
        }
        int pathLenConstraint = checkBasicConstraints(cert, critSet, maxPathLen);
        checkKeyUsage(cert, critSet);
        checkNetscapeCertType(cert, critSet);
        if (!critSet.isEmpty()) {
            throw new ValidatorException("Certificate contains unknown critical extensions: " + critSet, ValidatorException.T_CA_EXTENSIONS, cert);
        }
        return pathLenConstraint;
    }

    private void checkNetscapeCertType(X509Certificate cert, Set<String> critSet) throws CertificateException {
        if (!this.variant.equals(Validator.VAR_GENERIC)) {
            if (this.variant.equals(Validator.VAR_TLS_CLIENT) || this.variant.equals(Validator.VAR_TLS_SERVER)) {
                if (!getNetscapeCertTypeBit(cert, NSCT_SSL_CA)) {
                    throw new ValidatorException("Invalid Netscape CertType extension for SSL CA certificate", ValidatorException.T_CA_EXTENSIONS, cert);
                }
                critSet.remove(OID_NETSCAPE_CERT_TYPE);
            } else if (this.variant.equals(Validator.VAR_CODE_SIGNING) || this.variant.equals(Validator.VAR_JCE_SIGNING)) {
                if (!getNetscapeCertTypeBit(cert, NSCT_CODE_SIGNING_CA)) {
                    throw new ValidatorException("Invalid Netscape CertType extension for code signing CA certificate", ValidatorException.T_CA_EXTENSIONS, cert);
                }
                critSet.remove(OID_NETSCAPE_CERT_TYPE);
            } else {
                throw new CertificateException("Unknown variant " + this.variant);
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static boolean getNetscapeCertTypeBit(X509Certificate cert, String type) {
        NetscapeCertTypeExtension ext;
        try {
            if (cert instanceof X509CertImpl) {
                X509CertImpl certImpl = (X509CertImpl) cert;
                ObjectIdentifier oid = OBJID_NETSCAPE_CERT_TYPE;
                ext = (NetscapeCertTypeExtension) certImpl.getExtension(oid);
                if (ext == null) {
                    return true;
                }
            } else {
                byte[] extVal = cert.getExtensionValue(OID_NETSCAPE_CERT_TYPE);
                if (extVal == null) {
                    return true;
                }
                DerInputStream in = new DerInputStream(extVal);
                byte[] encoded = in.getOctetString();
                ext = new NetscapeCertTypeExtension(new DerValue(encoded).getUnalignedBitString().toByteArray());
            }
            Boolean val = ext.get(type);
            return val.booleanValue();
        } catch (IOException e) {
            return false;
        }
    }

    private int checkBasicConstraints(X509Certificate cert, Set<String> critSet, int maxPathLen) throws CertificateException {
        critSet.remove(OID_BASIC_CONSTRAINTS);
        int constraints = cert.getBasicConstraints();
        if (constraints < 0) {
            throw new ValidatorException("End user tried to act as a CA", ValidatorException.T_CA_EXTENSIONS, cert);
        }
        if (!X509CertImpl.isSelfIssued(cert)) {
            if (maxPathLen <= 0) {
                throw new ValidatorException("Violated path length constraints", ValidatorException.T_CA_EXTENSIONS, cert);
            }
            maxPathLen--;
        }
        if (maxPathLen > constraints) {
            maxPathLen = constraints;
        }
        return maxPathLen;
    }

    private void checkKeyUsage(X509Certificate cert, Set<String> critSet) throws CertificateException {
        critSet.remove(OID_KEY_USAGE);
        critSet.remove(OID_EXTENDED_KEY_USAGE);
        boolean[] keyUsageInfo = cert.getKeyUsage();
        if (keyUsageInfo != null) {
            if (keyUsageInfo.length < 6 || !keyUsageInfo[5]) {
                throw new ValidatorException("Wrong key usage: expected keyCertSign", ValidatorException.T_CA_EXTENSIONS, cert);
            }
        }
    }

    private X509Certificate[] buildTrustedChain(X509Certificate[] chain) throws CertificateException {
        List<X509Certificate> c = new ArrayList<>(chain.length);
        for (X509Certificate cert : chain) {
            X509Certificate trustedCert = getTrustedCertificate(cert);
            if (trustedCert != null) {
                c.add(trustedCert);
                return (X509Certificate[]) c.toArray(CHAIN0);
            }
            c.add(cert);
        }
        X509Certificate cert2 = chain[chain.length - 1];
        cert2.getSubjectX500Principal();
        X500Principal issuer = cert2.getIssuerX500Principal();
        List<X509Certificate> list = this.trustedX500Principals.get(issuer);
        if (list != null) {
            X509Certificate matchedCert = list.get(0);
            X509CertImpl certImpl = X509CertImpl.toImpl(cert2);
            KeyIdentifier akid = certImpl.getAuthKeyId();
            if (akid != null) {
                Iterator<X509Certificate> it = list.iterator();
                while (true) {
                    if (!it.hasNext()) {
                        break;
                    }
                    X509Certificate sup = it.next();
                    X509CertImpl supCert = X509CertImpl.toImpl(sup);
                    if (akid.equals(supCert.getSubjectKeyId())) {
                        matchedCert = sup;
                        break;
                    }
                }
            }
            c.add(matchedCert);
            return (X509Certificate[]) c.toArray(CHAIN0);
        }
        throw new ValidatorException(ValidatorException.T_NO_TRUST_ANCHOR);
    }

    private X509Certificate getTrustedCertificate(X509Certificate cert) {
        Principal certSubjectName = cert.getSubjectX500Principal();
        List<X509Certificate> list = this.trustedX500Principals.get(certSubjectName);
        if (list == null) {
            return null;
        }
        Principal certIssuerName = cert.getIssuerX500Principal();
        PublicKey certPublicKey = cert.getPublicKey();
        for (X509Certificate mycert : list) {
            if (mycert.equals(cert)) {
                return cert;
            }
            if (mycert.getIssuerX500Principal().equals(certIssuerName) && mycert.getPublicKey().equals(certPublicKey)) {
                return mycert;
            }
        }
        return null;
    }
}