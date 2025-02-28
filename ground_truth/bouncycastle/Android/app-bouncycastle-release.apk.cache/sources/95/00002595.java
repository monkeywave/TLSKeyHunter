package org.bouncycastle.jcajce.spec;

/* loaded from: classes2.dex */
public class KEMParameterSpec extends KTSParameterSpec {
    public KEMParameterSpec(String str) {
        this(str, 256);
    }

    public KEMParameterSpec(String str, int i) {
        super(str, i, null, null, null);
    }

    public int getKeySizeInBits() {
        return getKeySize();
    }
}