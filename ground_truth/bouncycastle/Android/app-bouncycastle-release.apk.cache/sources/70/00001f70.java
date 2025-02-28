package org.bouncycastle.jcajce;

import javax.crypto.SecretKey;
import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
public final class SecretKeyWithEncapsulation implements SecretKey {
    private final byte[] encapsulation;
    private final SecretKey secretKey;

    public SecretKeyWithEncapsulation(SecretKey secretKey, byte[] bArr) {
        this.secretKey = secretKey;
        this.encapsulation = Arrays.clone(bArr);
    }

    public boolean equals(Object obj) {
        return this.secretKey.equals(obj);
    }

    @Override // java.security.Key
    public String getAlgorithm() {
        return this.secretKey.getAlgorithm();
    }

    public byte[] getEncapsulation() {
        return Arrays.clone(this.encapsulation);
    }

    @Override // java.security.Key
    public byte[] getEncoded() {
        return this.secretKey.getEncoded();
    }

    @Override // java.security.Key
    public String getFormat() {
        return this.secretKey.getFormat();
    }

    public int hashCode() {
        return this.secretKey.hashCode();
    }
}