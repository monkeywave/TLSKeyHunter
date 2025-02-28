package org.bouncycastle.util.p012io.pem;

import java.io.IOException;

/* renamed from: org.bouncycastle.util.io.pem.PemGenerationException */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/util/io/pem/PemGenerationException.class */
public class PemGenerationException extends IOException {
    private Throwable cause;

    public PemGenerationException(String str, Throwable th) {
        super(str);
        this.cause = th;
    }

    public PemGenerationException(String str) {
        super(str);
    }

    @Override // java.lang.Throwable
    public Throwable getCause() {
        return this.cause;
    }
}