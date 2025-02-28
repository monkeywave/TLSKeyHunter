package org.bouncycastle.crypto.p005io;

import java.io.IOException;

/* renamed from: org.bouncycastle.crypto.io.CipherIOException */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/io/CipherIOException.class */
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