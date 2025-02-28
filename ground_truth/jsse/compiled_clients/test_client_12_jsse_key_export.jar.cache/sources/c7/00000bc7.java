package org.bouncycastle.jce.provider;

import org.bouncycastle.jce.exception.ExtException;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jce/provider/AnnotatedException.class */
public class AnnotatedException extends Exception implements ExtException {
    private Throwable _underlyingException;

    public AnnotatedException(String str, Throwable th) {
        super(str);
        this._underlyingException = th;
    }

    public AnnotatedException(String str) {
        this(str, null);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public Throwable getUnderlyingException() {
        return this._underlyingException;
    }

    @Override // java.lang.Throwable, org.bouncycastle.jce.exception.ExtException
    public Throwable getCause() {
        return this._underlyingException;
    }
}