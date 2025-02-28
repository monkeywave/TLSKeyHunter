package org.bouncycastle.jcajce.spec;

import java.security.spec.EncodedKeySpec;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/spec/OpenSSHPrivateKeySpec.class */
public class OpenSSHPrivateKeySpec extends EncodedKeySpec {
    private final String format;

    public OpenSSHPrivateKeySpec(byte[] bArr) {
        super(bArr);
        if (bArr[0] == 48) {
            this.format = "ASN.1";
        } else if (bArr[0] != 111) {
            throw new IllegalArgumentException("unknown byte encoding");
        } else {
            this.format = "OpenSSH";
        }
    }

    @Override // java.security.spec.EncodedKeySpec
    public String getFormat() {
        return this.format;
    }
}