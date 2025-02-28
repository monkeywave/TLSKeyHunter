package org.bouncycastle.crypto;

/* loaded from: classes.dex */
public class InvalidCipherTextException extends CryptoException {
    public InvalidCipherTextException() {
    }

    public InvalidCipherTextException(String str) {
        super(str);
    }

    public InvalidCipherTextException(String str, Throwable th) {
        super(str, th);
    }
}