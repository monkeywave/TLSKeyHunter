package org.bouncycastle.jcajce.spec;

import javax.crypto.SecretKey;

/* loaded from: classes2.dex */
public class RepeatedSecretKeySpec implements SecretKey {
    private String algorithm;

    public RepeatedSecretKeySpec(String str) {
        this.algorithm = str;
    }

    @Override // java.security.Key
    public String getAlgorithm() {
        return this.algorithm;
    }

    @Override // java.security.Key
    public byte[] getEncoded() {
        return null;
    }

    @Override // java.security.Key
    public String getFormat() {
        return null;
    }
}