package org.bouncycastle.jce.provider;

import java.security.cert.CertPath;
import java.security.cert.CertPathValidatorException;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jce/provider/RecoverableCertPathValidatorException.class */
class RecoverableCertPathValidatorException extends CertPathValidatorException {
    public RecoverableCertPathValidatorException(String str, Throwable th, CertPath certPath, int i) {
        super(str, th, certPath, i);
    }
}