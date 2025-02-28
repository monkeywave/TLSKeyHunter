package org.bouncycastle.jce.provider;

import java.security.InvalidAlgorithmParameterException;
import java.security.cert.CertPath;
import java.security.cert.CertPathParameters;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertPathValidatorResult;
import java.security.cert.CertPathValidatorSpi;
import java.security.cert.PKIXParameters;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashSet;
import org.bouncycastle.jcajce.PKIXCertStoreSelector;
import org.bouncycastle.jcajce.PKIXExtendedParameters;
import org.bouncycastle.jcajce.util.BCJcaJceHelper;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.x509.ExtendedPKIXParameters;
import org.bouncycastle.x509.X509AttributeCertStoreSelector;
import org.bouncycastle.x509.X509AttributeCertificate;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jce/provider/PKIXAttrCertPathValidatorSpi.class */
public class PKIXAttrCertPathValidatorSpi extends CertPathValidatorSpi {
    private final JcaJceHelper helper = new BCJcaJceHelper();

    @Override // java.security.cert.CertPathValidatorSpi
    public CertPathValidatorResult engineValidate(CertPath certPath, CertPathParameters certPathParameters) throws CertPathValidatorException, InvalidAlgorithmParameterException {
        PKIXExtendedParameters pKIXExtendedParameters;
        if ((certPathParameters instanceof ExtendedPKIXParameters) || (certPathParameters instanceof PKIXExtendedParameters)) {
            HashSet hashSet = new HashSet();
            HashSet hashSet2 = new HashSet();
            HashSet hashSet3 = new HashSet();
            HashSet hashSet4 = new HashSet();
            if (certPathParameters instanceof PKIXParameters) {
                PKIXExtendedParameters.Builder builder = new PKIXExtendedParameters.Builder((PKIXParameters) certPathParameters);
                if (certPathParameters instanceof ExtendedPKIXParameters) {
                    ExtendedPKIXParameters extendedPKIXParameters = (ExtendedPKIXParameters) certPathParameters;
                    builder.setUseDeltasEnabled(extendedPKIXParameters.isUseDeltasEnabled());
                    builder.setValidityModel(extendedPKIXParameters.getValidityModel());
                    hashSet = extendedPKIXParameters.getAttrCertCheckers();
                    hashSet2 = extendedPKIXParameters.getProhibitedACAttributes();
                    hashSet3 = extendedPKIXParameters.getNecessaryACAttributes();
                }
                pKIXExtendedParameters = builder.build();
            } else {
                pKIXExtendedParameters = (PKIXExtendedParameters) certPathParameters;
            }
            Date date = new Date();
            Date validityDate = CertPathValidatorUtilities.getValidityDate(pKIXExtendedParameters, date);
            PKIXCertStoreSelector targetConstraints = pKIXExtendedParameters.getTargetConstraints();
            if (targetConstraints instanceof X509AttributeCertStoreSelector) {
                X509AttributeCertificate attributeCert = ((X509AttributeCertStoreSelector) targetConstraints).getAttributeCert();
                CertPath processAttrCert1 = RFC3281CertPathUtilities.processAttrCert1(attributeCert, pKIXExtendedParameters);
                CertPathValidatorResult processAttrCert2 = RFC3281CertPathUtilities.processAttrCert2(certPath, pKIXExtendedParameters);
                X509Certificate x509Certificate = (X509Certificate) certPath.getCertificates().get(0);
                RFC3281CertPathUtilities.processAttrCert3(x509Certificate, pKIXExtendedParameters);
                RFC3281CertPathUtilities.processAttrCert4(x509Certificate, hashSet4);
                RFC3281CertPathUtilities.processAttrCert5(attributeCert, validityDate);
                RFC3281CertPathUtilities.processAttrCert7(attributeCert, certPath, processAttrCert1, pKIXExtendedParameters, hashSet);
                RFC3281CertPathUtilities.additionalChecks(attributeCert, hashSet2, hashSet3);
                RFC3281CertPathUtilities.checkCRLs(attributeCert, pKIXExtendedParameters, date, validityDate, x509Certificate, certPath.getCertificates(), this.helper);
                return processAttrCert2;
            }
            throw new InvalidAlgorithmParameterException("TargetConstraints must be an instance of " + X509AttributeCertStoreSelector.class.getName() + " for " + getClass().getName() + " class.");
        }
        throw new InvalidAlgorithmParameterException("Parameters must be a " + ExtendedPKIXParameters.class.getName() + " instance.");
    }
}