package org.bouncycastle.crypto.paddings;

import java.security.SecureRandom;
import kotlin.UByte;
import org.bouncycastle.crypto.InvalidCipherTextException;

/* loaded from: classes2.dex */
public class X923Padding implements BlockCipherPadding {
    SecureRandom random = null;

    @Override // org.bouncycastle.crypto.paddings.BlockCipherPadding
    public int addPadding(byte[] bArr, int i) {
        byte length = (byte) (bArr.length - i);
        while (i < bArr.length - 1) {
            SecureRandom secureRandom = this.random;
            if (secureRandom == null) {
                bArr[i] = 0;
            } else {
                bArr[i] = (byte) secureRandom.nextInt();
            }
            i++;
        }
        bArr[i] = length;
        return length;
    }

    @Override // org.bouncycastle.crypto.paddings.BlockCipherPadding
    public String getPaddingName() {
        return "X9.23";
    }

    @Override // org.bouncycastle.crypto.paddings.BlockCipherPadding
    public void init(SecureRandom secureRandom) throws IllegalArgumentException {
        this.random = secureRandom;
    }

    @Override // org.bouncycastle.crypto.paddings.BlockCipherPadding
    public int padCount(byte[] bArr) throws InvalidCipherTextException {
        int i = bArr[bArr.length - 1] & UByte.MAX_VALUE;
        if ((((bArr.length - i) | (i - 1)) >> 31) == 0) {
            return i;
        }
        throw new InvalidCipherTextException("pad block corrupted");
    }
}