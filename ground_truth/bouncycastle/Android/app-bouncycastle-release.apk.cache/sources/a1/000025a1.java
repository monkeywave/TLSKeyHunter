package org.bouncycastle.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;
import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
public class SM2ParameterSpec implements AlgorithmParameterSpec {

    /* renamed from: id */
    private byte[] f954id;

    public SM2ParameterSpec(byte[] bArr) {
        if (bArr == null) {
            throw new NullPointerException("id string cannot be null");
        }
        this.f954id = Arrays.clone(bArr);
    }

    public byte[] getID() {
        return Arrays.clone(this.f954id);
    }
}