package org.bouncycastle.crypto.p011io;

import java.io.IOException;

/* renamed from: org.bouncycastle.crypto.io.CipherIOException */
/* loaded from: classes2.dex */
public class CipherIOException extends IOException {
    private static final long serialVersionUID = 1;
    private final Throwable cause;

    public CipherIOException(String str, Throwable th) {
        super(str);
        this.cause = th;
    }

    @Override // java.lang.Throwable
    public Throwable getCause() {
        return this.cause;
    }
}