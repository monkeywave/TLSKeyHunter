package org.bouncycastle.oer;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import kotlin.jvm.internal.ByteCompanionObject;
import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
public class BitBuilder {
    private static final byte[] bits = {ByteCompanionObject.MIN_VALUE, 64, 32, 16, 8, 4, 2, 1};
    byte[] buf = new byte[1];
    int pos = 0;

    public void pad() {
        int i = this.pos;
        this.pos = i + (i % 8);
    }

    public int write(OutputStream outputStream) throws IOException {
        int i = this.pos;
        int i2 = (i + (i % 8)) / 8;
        outputStream.write(this.buf, 0, i2);
        outputStream.flush();
        return i2;
    }

    public void write7BitBytes(int i) {
        boolean z = false;
        for (int i2 = 4; i2 >= 0; i2--) {
            if (!z && ((-33554432) & i) != 0) {
                z = true;
            }
            if (z) {
                writeBit(i2).writeBits(i, 32, 7);
            }
            i <<= 7;
        }
    }

    public void write7BitBytes(BigInteger bigInteger) {
        int i;
        int bitLength = (bigInteger.bitLength() + (bigInteger.bitLength() % 8)) / 8;
        BigInteger shiftLeft = BigInteger.valueOf(254L).shiftLeft(bitLength * 8);
        boolean z = false;
        while (bitLength >= 0) {
            if (!z && bigInteger.and(shiftLeft).compareTo(BigInteger.ZERO) != 0) {
                z = true;
            }
            if (z) {
                writeBit(bitLength).writeBits(bigInteger.and(shiftLeft).shiftRight(i - 8).intValue(), 8, 7);
            }
            bigInteger = bigInteger.shiftLeft(7);
            bitLength--;
        }
    }

    public int writeAndClear(OutputStream outputStream) throws IOException {
        int i = this.pos;
        int i2 = (i + (i % 8)) / 8;
        outputStream.write(this.buf, 0, i2);
        outputStream.flush();
        zero();
        return i2;
    }

    public BitBuilder writeBit(int i) {
        int i2 = this.pos;
        int i3 = i2 / 8;
        byte[] bArr = this.buf;
        if (i3 >= bArr.length) {
            byte[] bArr2 = new byte[bArr.length + 4];
            System.arraycopy(bArr, 0, bArr2, 0, i2 / 8);
            Arrays.clear(this.buf);
            this.buf = bArr2;
        }
        if (i == 0) {
            byte[] bArr3 = this.buf;
            int i4 = this.pos;
            int i5 = i4 / 8;
            bArr3[i5] = (byte) ((~bits[i4 % 8]) & bArr3[i5]);
        } else {
            byte[] bArr4 = this.buf;
            int i6 = this.pos;
            int i7 = i6 / 8;
            bArr4[i7] = (byte) (bits[i6 % 8] | bArr4[i7]);
        }
        this.pos++;
        return this;
    }

    public BitBuilder writeBits(long j, int i) {
        for (int i2 = i - 1; i2 >= 0; i2--) {
            writeBit(((1 << i2) & j) > 0 ? 1 : 0);
        }
        return this;
    }

    public BitBuilder writeBits(long j, int i, int i2) {
        for (int i3 = i - 1; i3 >= i - i2; i3--) {
            writeBit(((1 << i3) & j) != 0 ? 1 : 0);
        }
        return this;
    }

    public void zero() {
        Arrays.clear(this.buf);
        this.pos = 0;
    }
}