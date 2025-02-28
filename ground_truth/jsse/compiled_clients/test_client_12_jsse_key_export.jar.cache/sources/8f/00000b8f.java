package org.bouncycastle.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;
import org.bouncycastle.util.Arrays;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/spec/SM2ParameterSpec.class */
public class SM2ParameterSpec implements AlgorithmParameterSpec {

    /* renamed from: id */
    private byte[] f626id;

    public SM2ParameterSpec(byte[] bArr) {
        if (bArr == null) {
            throw new NullPointerException("id string cannot be null");
        }
        this.f626id = Arrays.clone(bArr);
    }

    public byte[] getID() {
        return Arrays.clone(this.f626id);
    }
}