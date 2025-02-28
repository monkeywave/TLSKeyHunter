package org.bouncycastle.util.encoders;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/util/encoders/EncoderException.class */
public class EncoderException extends IllegalStateException {
    private Throwable cause;

    /* JADX INFO: Access modifiers changed from: package-private */
    public EncoderException(String str, Throwable th) {
        super(str);
        this.cause = th;
    }

    @Override // java.lang.Throwable
    public Throwable getCause() {
        return this.cause;
    }
}