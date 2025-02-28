package org.bouncycastle.jce.provider;

import java.security.InvalidAlgorithmParameterException;
import java.security.PublicKey;
import java.security.cert.CertPath;
import java.security.cert.CertPathParameters;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertPathValidatorResult;
import java.security.cert.CertPathValidatorSpi;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.PKIXCertPathChecker;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.jcajce.PKIXExtendedBuilderParameters;
import org.bouncycastle.jcajce.PKIXExtendedParameters;
import org.bouncycastle.jcajce.interfaces.BCX509Certificate;
import org.bouncycastle.jcajce.util.BCJcaJceHelper;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jce.exception.ExtCertPathValidatorException;
import org.bouncycastle.x509.ExtendedPKIXParameters;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jce/provider/PKIXCertPathValidatorSpi.class */
public class PKIXCertPathValidatorSpi extends CertPathValidatorSpi {
    private final JcaJceHelper helper;
    private final boolean isForCRLCheck;

    public PKIXCertPathValidatorSpi() {
        this(false);
    }

    public PKIXCertPathValidatorSpi(boolean z) {
        this.helper = new BCJcaJceHelper();
        this.isForCRLCheck = z;
    }

    @Override // java.security.cert.CertPathValidatorSpi
    public CertPathValidatorResult engineValidate(CertPath certPath, CertPathParameters certPathParameters) throws CertPathValidatorException, InvalidAlgorithmParameterException {
        PKIXExtendedParameters pKIXExtendedParameters;
        X500Name ca;
        PublicKey cAPublicKey;
        HashSet hashSet;
        HashSet hashSet2;
        if (certPathParameters instanceof PKIXParameters) {
            PKIXExtendedParameters.Builder builder = new PKIXExtendedParameters.Builder((PKIXParameters) certPathParameters);
            if (certPathParameters instanceof ExtendedPKIXParameters) {
                ExtendedPKIXParameters extendedPKIXParameters = (ExtendedPKIXParameters) certPathParameters;
                builder.setUseDeltasEnabled(extendedPKIXParameters.isUseDeltasEnabled());
                builder.setValidityModel(extendedPKIXParameters.getValidityModel());
            }
            pKIXExtendedParameters = builder.build();
        } else if (certPathParameters instanceof PKIXExtendedBuilderParameters) {
            pKIXExtendedParameters = ((PKIXExtendedBuilderParameters) certPathParameters).getBaseParameters();
        } else if (!(certPathParameters instanceof PKIXExtendedParameters)) {
            throw new InvalidAlgorithmParameterException("Parameters must be a " + PKIXParameters.class.getName() + " instance.");
        } else {
            pKIXExtendedParameters = (PKIXExtendedParameters) certPathParameters;
        }
        if (pKIXExtendedParameters.getTrustAnchors() == null) {
            throw new InvalidAlgorithmParameterException("trustAnchors is null, this is not allowed for certification path validation.");
        }
        List<? extends Certificate> certificates = certPath.getCertificates();
        int size = certificates.size();
        if (certificates.isEmpty()) {
            throw new CertPathValidatorException("Certification path is empty.", null, certPath, -1);
        }
        Date validityDate = CertPathValidatorUtilities.getValidityDate(pKIXExtendedParameters, new Date());
        Set initialPolicies = pKIXExtendedParameters.getInitialPolicies();
        try {
            TrustAnchor findTrustAnchor = CertPathValidatorUtilities.findTrustAnchor((X509Certificate) certificates.get(certificates.size() - 1), pKIXExtendedParameters.getTrustAnchors(), pKIXExtendedParameters.getSigProvider());
            if (findTrustAnchor == null) {
                throw new CertPathValidatorException("Trust anchor for certification path not found.", null, certPath, -1);
            }
            checkCertificate(findTrustAnchor.getTrustedCert());
            PKIXExtendedParameters build = new PKIXExtendedParameters.Builder(pKIXExtendedParameters).setTrustAnchor(findTrustAnchor).build();
            ArrayList[] arrayListArr = new ArrayList[size + 1];
            for (int i = 0; i < arrayListArr.length; i++) {
                arrayListArr[i] = new ArrayList();
            }
            HashSet hashSet3 = new HashSet();
            hashSet3.add(RFC3280CertPathUtilities.ANY_POLICY);
            PKIXPolicyNode pKIXPolicyNode = new PKIXPolicyNode(new ArrayList(), 0, hashSet3, null, new HashSet(), RFC3280CertPathUtilities.ANY_POLICY, false);
            arrayListArr[0].add(pKIXPolicyNode);
            PKIXNameConstraintValidator pKIXNameConstraintValidator = new PKIXNameConstraintValidator();
            HashSet hashSet4 = new HashSet();
            int i2 = build.isExplicitPolicyRequired() ? 0 : size + 1;
            int i3 = build.isAnyPolicyInhibited() ? 0 : size + 1;
            int i4 = build.isPolicyMappingInhibited() ? 0 : size + 1;
            X509Certificate trustedCert = findTrustAnchor.getTrustedCert();
            try {
                if (trustedCert != null) {
                    ca = PrincipalUtils.getSubjectPrincipal(trustedCert);
                    cAPublicKey = trustedCert.getPublicKey();
                } else {
                    ca = PrincipalUtils.getCA(findTrustAnchor);
                    cAPublicKey = findTrustAnchor.getCAPublicKey();
                }
                try {
                    AlgorithmIdentifier algorithmIdentifier = CertPathValidatorUtilities.getAlgorithmIdentifier(cAPublicKey);
                    algorithmIdentifier.getAlgorithm();
                    algorithmIdentifier.getParameters();
                    int i5 = size;
                    if (build.getTargetConstraints() == null || build.getTargetConstraints().match((Certificate) ((X509Certificate) certificates.get(0)))) {
                        List<PKIXCertPathChecker> certPathCheckers = build.getCertPathCheckers();
                        for (PKIXCertPathChecker pKIXCertPathChecker : certPathCheckers) {
                            pKIXCertPathChecker.init(false);
                        }
                        ProvCrlRevocationChecker provCrlRevocationChecker = build.isRevocationEnabled() ? new ProvCrlRevocationChecker(this.helper) : null;
                        X509Certificate x509Certificate = null;
                        int size2 = certificates.size() - 1;
                        while (size2 >= 0) {
                            int i6 = size - size2;
                            x509Certificate = (X509Certificate) certificates.get(size2);
                            boolean z = size2 == certificates.size() - 1;
                            try {
                                checkCertificate(x509Certificate);
                                RFC3280CertPathUtilities.processCertA(certPath, build, validityDate, provCrlRevocationChecker, size2, cAPublicKey, z, ca, trustedCert);
                                RFC3280CertPathUtilities.processCertBC(certPath, size2, pKIXNameConstraintValidator, this.isForCRLCheck);
                                pKIXPolicyNode = RFC3280CertPathUtilities.processCertE(certPath, size2, RFC3280CertPathUtilities.processCertD(certPath, size2, hashSet4, pKIXPolicyNode, arrayListArr, i3, this.isForCRLCheck));
                                RFC3280CertPathUtilities.processCertF(certPath, size2, pKIXPolicyNode, i2);
                                if (i6 != size) {
                                    if (x509Certificate == null || x509Certificate.getVersion() != 1) {
                                        RFC3280CertPathUtilities.prepareNextCertA(certPath, size2);
                                        pKIXPolicyNode = RFC3280CertPathUtilities.prepareCertB(certPath, size2, arrayListArr, pKIXPolicyNode, i4);
                                        RFC3280CertPathUtilities.prepareNextCertG(certPath, size2, pKIXNameConstraintValidator);
                                        int prepareNextCertH1 = RFC3280CertPathUtilities.prepareNextCertH1(certPath, size2, i2);
                                        int prepareNextCertH2 = RFC3280CertPathUtilities.prepareNextCertH2(certPath, size2, i4);
                                        int prepareNextCertH3 = RFC3280CertPathUtilities.prepareNextCertH3(certPath, size2, i3);
                                        i2 = RFC3280CertPathUtilities.prepareNextCertI1(certPath, size2, prepareNextCertH1);
                                        i4 = RFC3280CertPathUtilities.prepareNextCertI2(certPath, size2, prepareNextCertH2);
                                        i3 = RFC3280CertPathUtilities.prepareNextCertJ(certPath, size2, prepareNextCertH3);
                                        RFC3280CertPathUtilities.prepareNextCertK(certPath, size2);
                                        i5 = RFC3280CertPathUtilities.prepareNextCertM(certPath, size2, RFC3280CertPathUtilities.prepareNextCertL(certPath, size2, i5));
                                        RFC3280CertPathUtilities.prepareNextCertN(certPath, size2);
                                        Set<String> criticalExtensionOIDs = x509Certificate.getCriticalExtensionOIDs();
                                        if (criticalExtensionOIDs != null) {
                                            hashSet2 = new HashSet(criticalExtensionOIDs);
                                            hashSet2.remove(RFC3280CertPathUtilities.KEY_USAGE);
                                            hashSet2.remove(RFC3280CertPathUtilities.CERTIFICATE_POLICIES);
                                            hashSet2.remove(RFC3280CertPathUtilities.POLICY_MAPPINGS);
                                            hashSet2.remove(RFC3280CertPathUtilities.INHIBIT_ANY_POLICY);
                                            hashSet2.remove(RFC3280CertPathUtilities.ISSUING_DISTRIBUTION_POINT);
                                            hashSet2.remove(RFC3280CertPathUtilities.DELTA_CRL_INDICATOR);
                                            hashSet2.remove(RFC3280CertPathUtilities.POLICY_CONSTRAINTS);
                                            hashSet2.remove(RFC3280CertPathUtilities.BASIC_CONSTRAINTS);
                                            hashSet2.remove(RFC3280CertPathUtilities.SUBJECT_ALTERNATIVE_NAME);
                                            hashSet2.remove(RFC3280CertPathUtilities.NAME_CONSTRAINTS);
                                        } else {
                                            hashSet2 = new HashSet();
                                        }
                                        RFC3280CertPathUtilities.prepareNextCertO(certPath, size2, hashSet2, certPathCheckers);
                                        trustedCert = x509Certificate;
                                        ca = PrincipalUtils.getSubjectPrincipal(trustedCert);
                                        try {
                                            cAPublicKey = CertPathValidatorUtilities.getNextWorkingKey(certPath.getCertificates(), size2, this.helper);
                                            AlgorithmIdentifier algorithmIdentifier2 = CertPathValidatorUtilities.getAlgorithmIdentifier(cAPublicKey);
                                            algorithmIdentifier2.getAlgorithm();
                                            algorithmIdentifier2.getParameters();
                                        } catch (CertPathValidatorException e) {
                                            throw new CertPathValidatorException("Next working key could not be retrieved.", e, certPath, size2);
                                        }
                                    } else if (i6 != 1 || !x509Certificate.equals(findTrustAnchor.getTrustedCert())) {
                                        throw new CertPathValidatorException("Version 1 certificates can't be used as CA ones.", null, certPath, size2);
                                    }
                                }
                                size2--;
                            } catch (AnnotatedException e2) {
                                throw new CertPathValidatorException(e2.getMessage(), e2.getUnderlyingException(), certPath, size2);
                            }
                        }
                        int wrapupCertB = RFC3280CertPathUtilities.wrapupCertB(certPath, size2 + 1, RFC3280CertPathUtilities.wrapupCertA(i2, x509Certificate));
                        Set<String> criticalExtensionOIDs2 = x509Certificate.getCriticalExtensionOIDs();
                        if (criticalExtensionOIDs2 != null) {
                            hashSet = new HashSet(criticalExtensionOIDs2);
                            hashSet.remove(RFC3280CertPathUtilities.KEY_USAGE);
                            hashSet.remove(RFC3280CertPathUtilities.CERTIFICATE_POLICIES);
                            hashSet.remove(RFC3280CertPathUtilities.POLICY_MAPPINGS);
                            hashSet.remove(RFC3280CertPathUtilities.INHIBIT_ANY_POLICY);
                            hashSet.remove(RFC3280CertPathUtilities.ISSUING_DISTRIBUTION_POINT);
                            hashSet.remove(RFC3280CertPathUtilities.DELTA_CRL_INDICATOR);
                            hashSet.remove(RFC3280CertPathUtilities.POLICY_CONSTRAINTS);
                            hashSet.remove(RFC3280CertPathUtilities.BASIC_CONSTRAINTS);
                            hashSet.remove(RFC3280CertPathUtilities.SUBJECT_ALTERNATIVE_NAME);
                            hashSet.remove(RFC3280CertPathUtilities.NAME_CONSTRAINTS);
                            hashSet.remove(RFC3280CertPathUtilities.CRL_DISTRIBUTION_POINTS);
                            hashSet.remove(Extension.extendedKeyUsage.getId());
                        } else {
                            hashSet = new HashSet();
                        }
                        RFC3280CertPathUtilities.wrapupCertF(certPath, size2 + 1, certPathCheckers, hashSet);
                        PKIXPolicyNode wrapupCertG = RFC3280CertPathUtilities.wrapupCertG(certPath, build, initialPolicies, size2 + 1, arrayListArr, pKIXPolicyNode, hashSet4);
                        if (wrapupCertB > 0 || wrapupCertG != null) {
                            return new PKIXCertPathValidatorResult(findTrustAnchor, wrapupCertG, x509Certificate.getPublicKey());
                        }
                        throw new CertPathValidatorException("Path processing failed on policy.", null, certPath, size2);
                    }
                    throw new ExtCertPathValidatorException("Target certificate in certification path does not match targetConstraints.", null, certPath, 0);
                } catch (CertPathValidatorException e3) {
                    throw new ExtCertPathValidatorException("Algorithm identifier of public key of trust anchor could not be read.", e3, certPath, -1);
                }
            } catch (RuntimeException e4) {
                throw new ExtCertPathValidatorException("Subject of trust anchor could not be (re)encoded.", e4, certPath, -1);
            }
        } catch (AnnotatedException e5) {
            throw new CertPathValidatorException(e5.getMessage(), e5.getUnderlyingException(), certPath, certificates.size() - 1);
        }
    }

    static void checkCertificate(X509Certificate x509Certificate) throws AnnotatedException {
        if (x509Certificate instanceof BCX509Certificate) {
            RuntimeException runtimeException = null;
            try {
                if (null != ((BCX509Certificate) x509Certificate).getTBSCertificateNative()) {
                    return;
                }
            } catch (RuntimeException e) {
                runtimeException = e;
            }
            throw new AnnotatedException("unable to process TBSCertificate", runtimeException);
        }
        try {
            TBSCertificate.getInstance(x509Certificate.getTBSCertificate());
        } catch (IllegalArgumentException e2) {
            throw new AnnotatedException(e2.getMessage());
        } catch (CertificateEncodingException e3) {
            throw new AnnotatedException("unable to process TBSCertificate", e3);
        }
    }
}