package org.bouncycastle.crypto.util;

import java.math.BigInteger;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/util/SSHBuffer.class */
class SSHBuffer {
    private final byte[] buffer;
    private int pos = 0;

    public SSHBuffer(byte[] bArr, byte[] bArr2) {
        this.buffer = bArr2;
        for (int i = 0; i != bArr.length; i++) {
            if (bArr[i] != bArr2[i]) {
                throw new IllegalArgumentException("magic-number incorrect");
            }
        }
        this.pos += bArr.length;
    }

    public SSHBuffer(byte[] bArr) {
        this.buffer = bArr;
    }

    public int readU32() {
        if (this.pos > this.buffer.length - 4) {
            throw new IllegalArgumentException("4 bytes for U32 exceeds buffer.");
        }
        byte[] bArr = this.buffer;
        int i = this.pos;
        this.pos = i + 1;
        byte[] bArr2 = this.buffer;
        int i2 = this.pos;
        this.pos = i2 + 1;
        int i3 = ((bArr[i] & 255) << 24) | ((bArr2[i2] & 255) << 16);
        byte[] bArr3 = this.buffer;
        int i4 = this.pos;
        this.pos = i4 + 1;
        int i5 = i3 | ((bArr3[i4] & 255) << 8);
        byte[] bArr4 = this.buffer;
        int i6 = this.pos;
        this.pos = i6 + 1;
        return i5 | (bArr4[i6] & 255);
    }

    public String readString() {
        return Strings.fromByteArray(readBlock());
    }

    public byte[] readBlock() {
        int readU32 = readU32();
        if (readU32 == 0) {
            return new byte[0];
        }
        if (this.pos > this.buffer.length - readU32) {
            throw new IllegalArgumentException("not enough data for block");
        }
        int i = this.pos;
        this.pos += readU32;
        return Arrays.copyOfRange(this.buffer, i, this.pos);
    }

    public void skipBlock() {
        int readU32 = readU32();
        if (this.pos > this.buffer.length - readU32) {
            throw new IllegalArgumentException("not enough data for block");
        }
        this.pos += readU32;
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
        if (this.pos > this.buffer.length - readU32) {
            throw new IllegalArgumentException("not enough data for block");
        }
        if (0 != readU32 % i) {
            throw new IllegalArgumentException("missing padding");
        }
        int i3 = this.pos;
        this.pos += readU32;
        int i4 = this.pos;
        if (readU32 > 0 && 0 < (i2 = this.buffer[this.pos - 1] & 255) && i2 < i) {
            i4 -= i2;
            int i5 = 1;
            int i6 = i4;
            while (i5 <= i2) {
                if (i5 != (this.buffer[i6] & 255)) {
                    throw new IllegalArgumentException("incorrect padding");
                }
                i5++;
                i6++;
            }
        }
        return Arrays.copyOfRange(this.buffer, i3, i4);
    }

    public BigInteger readBigNumPositive() {
        int readU32 = readU32();
        if (this.pos + readU32 > this.buffer.length) {
            throw new IllegalArgumentException("not enough data for big num");
        }
        int i = this.pos;
        this.pos += readU32;
        return new BigInteger(1, Arrays.copyOfRange(this.buffer, i, this.pos));
    }

    public byte[] getBuffer() {
        return Arrays.clone(this.buffer);
    }

    public boolean hasRemaining() {
        return this.pos < this.buffer.length;
    }
}