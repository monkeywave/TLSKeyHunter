package org.bouncycastle.jce.provider;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jce/provider/PKIXNameConstraintValidatorException.class */
public class PKIXNameConstraintValidatorException extends Exception {
    private Throwable cause;

    public PKIXNameConstraintValidatorException(String str) {
        super(str);
    }

    public PKIXNameConstraintValidatorException(String str, Throwable th) {
        super(str);
        this.cause = th;
    }

    @Override // java.lang.Throwable
    public Throwable getCause() {
        return this.cause;
    }
}