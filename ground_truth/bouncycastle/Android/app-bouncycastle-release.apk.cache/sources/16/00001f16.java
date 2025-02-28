package org.bouncycastle.crypto.util;

import java.math.BigInteger;
import kotlin.UByte;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

/* loaded from: classes2.dex */
class SSHBuffer {
    private final byte[] buffer;
    private int pos = 0;

    public SSHBuffer(byte[] bArr) {
        this.buffer = bArr;
    }

    public SSHBuffer(byte[] bArr, byte[] bArr2) {
        this.buffer = bArr2;
        for (int i = 0; i != bArr.length; i++) {
            if (bArr[i] != bArr2[i]) {
                throw new IllegalArgumentException("magic-number incorrect");
            }
        }
        this.pos += bArr.length;
    }

    public byte[] getBuffer() {
        return Arrays.clone(this.buffer);
    }

    public boolean hasRemaining() {
        return this.pos < this.buffer.length;
    }

    public BigInteger readBigNumPositive() {
        int readU32 = readU32();
        int i = this.pos;
        int i2 = i + readU32;
        byte[] bArr = this.buffer;
        if (i2 <= bArr.length) {
            int i3 = readU32 + i;
            this.pos = i3;
            return new BigInteger(1, Arrays.copyOfRange(bArr, i, i3));
        }
        throw new IllegalArgumentException("not enough data for big num");
    }

    public byte[] readBlock() {
        int readU32 = readU32();
        if (readU32 == 0) {
            return new byte[0];
        }
        int i = this.pos;
        byte[] bArr = this.buffer;
        if (i <= bArr.length - readU32) {
            int i2 = readU32 + i;
            this.pos = i2;
            return Arrays.copyOfRange(bArr, i, i2);
        }
        throw new IllegalArgumentException("not enough data for block");
    }

    public byte[] readPaddedBlock() {
        return readPaddedBlock(8);
    }

    public byte[] readPaddedBlock(int i) {
        int i2;
        int readU32 = readU32();
        if (readU32 == 0) {
            return new byte[0];
        }
        int i3 = this.pos;
        byte[] bArr = this.buffer;
        if (i3 <= bArr.length - readU32) {
            if (readU32 % i == 0) {
                int i4 = i3 + readU32;
                this.pos = i4;
                if (readU32 > 0 && (i2 = bArr[i4 - 1] & UByte.MAX_VALUE) > 0 && i2 < i) {
                    i4 -= i2;
                    int i5 = 1;
                    int i6 = i4;
                    while (i5 <= i2) {
                        if (i5 != (this.buffer[i6] & UByte.MAX_VALUE)) {
                            throw new IllegalArgumentException("incorrect padding");
                        }
                        i5++;
                        i6++;
                    }
                }
                return Arrays.copyOfRange(this.buffer, i3, i4);
            }
            throw new IllegalArgumentException("missing padding");
        }
        throw new IllegalArgumentException("not enough data for block");
    }

    public String readString() {
        return Strings.fromByteArray(readBlock());
    }

    public int readU32() {
        int i = this.pos;
        byte[] bArr = this.buffer;
        if (i <= bArr.length - 4) {
            int i2 = i + 1;
            this.pos = i2;
            int i3 = i + 2;
            this.pos = i3;
            int i4 = ((bArr[i2] & UByte.MAX_VALUE) << 16) | ((bArr[i] & UByte.MAX_VALUE) << 24);
            int i5 = i + 3;
            this.pos = i5;
            this.pos = i + 4;
            return (bArr[i5] & UByte.MAX_VALUE) | i4 | ((bArr[i3] & UByte.MAX_VALUE) << 8);
        }
        throw new IllegalArgumentException("4 bytes for U32 exceeds buffer.");
    }

    public void skipBlock() {
        int readU32 = readU32();
        int i = this.pos;
        if (i > this.buffer.length - readU32) {
            throw new IllegalArgumentException("not enough data for block");
        }
        this.pos = i + readU32;
    }
}