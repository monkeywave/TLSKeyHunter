package org.bouncycastle.jcajce;

import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;

/* loaded from: classes2.dex */
public interface PKIXCertRevocationChecker {
    void check(Certificate certificate) throws CertPathValidatorException;

    void initialize(PKIXCertRevocationCheckerParameters pKIXCertRevocationCheckerParameters) throws CertPathValidatorException;

    void setParameter(String str, Object obj);
}