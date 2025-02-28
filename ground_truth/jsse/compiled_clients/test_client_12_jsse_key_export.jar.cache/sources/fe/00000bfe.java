package org.bouncycastle.jce.provider;

import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.PKIXCertPathChecker;
import org.bouncycastle.jcajce.PKIXCertRevocationChecker;
import org.bouncycastle.jcajce.PKIXCertRevocationCheckerParameters;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jce/provider/WrappedRevocationChecker.class */
class WrappedRevocationChecker implements PKIXCertRevocationChecker {
    private final PKIXCertPathChecker checker;

    public WrappedRevocationChecker(PKIXCertPathChecker pKIXCertPathChecker) {
        this.checker = pKIXCertPathChecker;
    }

    @Override // org.bouncycastle.jcajce.PKIXCertRevocationChecker
    public void setParameter(String str, Object obj) {
    }

    @Override // org.bouncycastle.jcajce.PKIXCertRevocationChecker
    public void initialize(PKIXCertRevocationCheckerParameters pKIXCertRevocationCheckerParameters) throws CertPathValidatorException {
        this.checker.init(false);
    }

    @Override // org.bouncycastle.jcajce.PKIXCertRevocationChecker
    public void check(Certificate certificate) throws CertPathValidatorException {
        this.checker.check(certificate);
    }
}