package org.bouncycastle.x509;

import java.security.cert.CertificateEncodingException;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/x509/ExtCertificateEncodingException.class */
class ExtCertificateEncodingException extends CertificateEncodingException {
    Throwable cause;

    /* JADX INFO: Access modifiers changed from: package-private */
    public ExtCertificateEncodingException(String str, Throwable th) {
        super(str);
        this.cause = th;
    }

    @Override // java.lang.Throwable
    public Throwable getCause() {
        return this.cause;
    }
}