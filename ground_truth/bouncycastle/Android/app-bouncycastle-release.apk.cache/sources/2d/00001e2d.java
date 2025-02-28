package org.bouncycastle.crypto.paddings;

import java.security.SecureRandom;
import kotlin.UByte;
import kotlin.jvm.internal.ByteCompanionObject;
import org.bouncycastle.crypto.InvalidCipherTextException;

/* loaded from: classes2.dex */
public class ISO7816d4Padding implements BlockCipherPadding {
    @Override // org.bouncycastle.crypto.paddings.BlockCipherPadding
    public int addPadding(byte[] bArr, int i) {
        int length = bArr.length - i;
        bArr[i] = ByteCompanionObject.MIN_VALUE;
        while (true) {
            i++;
            if (i >= bArr.length) {
                return length;
            }
            bArr[i] = 0;
        }
    }

    @Override // org.bouncycastle.crypto.paddings.BlockCipherPadding
    public String getPaddingName() {
        return "ISO7816-4";
    }

    @Override // org.bouncycastle.crypto.paddings.BlockCipherPadding
    public void init(SecureRandom secureRandom) throws IllegalArgumentException {
    }

    @Override // org.bouncycastle.crypto.paddings.BlockCipherPadding
    public int padCount(byte[] bArr) throws InvalidCipherTextException {
        int i;
        int length = bArr.length;
        int i2 = -1;
        int i3 = -1;
        while (true) {
            length--;
            if (length < 0) {
                break;
            }
            i2 ^= ((((i ^ 128) - 1) >> 31) & i3) & (length ^ i2);
            i3 &= ((bArr[length] & UByte.MAX_VALUE) - 1) >> 31;
        }
        if (i2 >= 0) {
            return bArr.length - i2;
        }
        throw new InvalidCipherTextException("pad block corrupted");
    }
}