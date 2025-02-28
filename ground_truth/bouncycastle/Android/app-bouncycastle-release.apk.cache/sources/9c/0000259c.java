package org.bouncycastle.jcajce.spec;

import java.security.spec.EncodedKeySpec;
import kotlin.UByte;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

/* loaded from: classes2.dex */
public class OpenSSHPublicKeySpec extends EncodedKeySpec {
    private static final String[] allowedTypes = {"ssh-rsa", "ssh-ed25519", "ssh-dss"};
    private final String type;

    public OpenSSHPublicKeySpec(byte[] bArr) {
        super(bArr);
        int i = 0;
        int i2 = (((bArr[0] & UByte.MAX_VALUE) << 24) | ((bArr[1] & UByte.MAX_VALUE) << 16) | ((bArr[2] & UByte.MAX_VALUE) << 8) | (bArr[3] & UByte.MAX_VALUE)) + 4;
        if (i2 >= bArr.length) {
            throw new IllegalArgumentException("invalid public key blob: type field longer than blob");
        }
        String fromByteArray = Strings.fromByteArray(Arrays.copyOfRange(bArr, 4, i2));
        this.type = fromByteArray;
        if (fromByteArray.startsWith("ecdsa")) {
            return;
        }
        while (true) {
            String[] strArr = allowedTypes;
            if (i >= strArr.length) {
                throw new IllegalArgumentException("unrecognised public key type " + this.type);
            }
            if (strArr[i].equals(this.type)) {
                return;
            }
            i++;
        }
    }

    @Override // java.security.spec.EncodedKeySpec
    public String getFormat() {
        return "OpenSSH";
    }

    public String getType() {
        return this.type;
    }
}