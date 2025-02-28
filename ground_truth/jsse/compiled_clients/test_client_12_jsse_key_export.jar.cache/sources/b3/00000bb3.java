package org.bouncycastle.jce.exception;

import java.security.cert.CertificateEncodingException;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jce/exception/ExtCertificateEncodingException.class */
public class ExtCertificateEncodingException extends CertificateEncodingException implements ExtException {
    private Throwable cause;

    public ExtCertificateEncodingException(String str, Throwable th) {
        super(str);
        this.cause = th;
    }

    @Override // java.lang.Throwable, org.bouncycastle.jce.exception.ExtException
    public Throwable getCause() {
        return this.cause;
    }
}