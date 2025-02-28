package org.bouncycastle.jcajce.spec;

import java.security.spec.EncodedKeySpec;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/spec/OpenSSHPublicKeySpec.class */
public class OpenSSHPublicKeySpec extends EncodedKeySpec {
    private static final String[] allowedTypes = {"ssh-rsa", "ssh-ed25519", "ssh-dss"};
    private final String type;

    public OpenSSHPublicKeySpec(byte[] bArr) {
        super(bArr);
        int i = 0 + 1;
        int i2 = i + 1;
        int i3 = i2 + 1;
        int i4 = i3 + 1;
        int i5 = ((bArr[0] & 255) << 24) | ((bArr[i] & 255) << 16) | ((bArr[i2] & 255) << 8) | (bArr[i3] & 255);
        if (i4 + i5 >= bArr.length) {
            throw new IllegalArgumentException("invalid public key blob: type field longer than blob");
        }
        this.type = Strings.fromByteArray(Arrays.copyOfRange(bArr, i4, i4 + i5));
        if (this.type.startsWith("ecdsa")) {
            return;
        }
        for (int i6 = 0; i6 < allowedTypes.length; i6++) {
            if (allowedTypes[i6].equals(this.type)) {
                return;
            }
        }
        throw new IllegalArgumentException("unrecognised public key type " + this.type);
    }

    @Override // java.security.spec.EncodedKeySpec
    public String getFormat() {
        return "OpenSSH";
    }

    public String getType() {
        return this.type;
    }
}