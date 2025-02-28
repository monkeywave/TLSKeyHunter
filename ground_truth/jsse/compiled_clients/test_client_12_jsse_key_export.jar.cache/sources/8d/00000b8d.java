package org.bouncycastle.jcajce.spec;

import java.security.spec.EncodedKeySpec;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/spec/RawEncodedKeySpec.class */
public class RawEncodedKeySpec extends EncodedKeySpec {
    public RawEncodedKeySpec(byte[] bArr) {
        super(bArr);
    }

    @Override // java.security.spec.EncodedKeySpec
    public String getFormat() {
        return "RAW";
    }
}