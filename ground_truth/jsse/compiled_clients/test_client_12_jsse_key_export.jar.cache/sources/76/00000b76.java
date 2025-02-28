package org.bouncycastle.jcajce.provider.util;

import javax.crypto.BadPaddingException;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/util/BadBlockException.class */
public class BadBlockException extends BadPaddingException {
    private final Throwable cause;

    public BadBlockException(String str, Throwable th) {
        super(str);
        this.cause = th;
    }

    @Override // java.lang.Throwable
    public Throwable getCause() {
        return this.cause;
    }
}