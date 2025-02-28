package org.bouncycastle.jce.provider;

import org.bouncycastle.jce.exception.ExtException;

/* loaded from: classes2.dex */
public class AnnotatedException extends Exception implements ExtException {
    private Throwable _underlyingException;

    public AnnotatedException(String str) {
        this(str, null);
    }

    public AnnotatedException(String str, Throwable th) {
        super(str);
        this._underlyingException = th;
    }

    @Override // java.lang.Throwable, org.bouncycastle.jce.exception.ExtException
    public Throwable getCause() {
        return this._underlyingException;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public Throwable getUnderlyingException() {
        return this._underlyingException;
    }
}