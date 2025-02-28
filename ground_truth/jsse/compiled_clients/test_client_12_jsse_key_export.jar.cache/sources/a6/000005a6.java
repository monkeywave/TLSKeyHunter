package org.bouncycastle.crypto.prng;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.SecureRandom;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/prng/FixedSecureRandom.class */
public class FixedSecureRandom extends SecureRandom {
    private byte[] _data;
    private int _index;
    private int _intPad;

    /* JADX WARN: Type inference failed for: r2v1, types: [byte[], byte[][]] */
    public FixedSecureRandom(byte[] bArr) {
        this(false, (byte[][]) new byte[]{bArr});
    }

    public FixedSecureRandom(byte[][] bArr) {
        this(false, bArr);
    }

    /* JADX WARN: Type inference failed for: r2v1, types: [byte[], byte[][]] */
    public FixedSecureRandom(boolean z, byte[] bArr) {
        this(z, (byte[][]) new byte[]{bArr});
    }

    public FixedSecureRandom(boolean z, byte[][] bArr) {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        for (int i = 0; i != bArr.length; i++) {
            try {
                byteArrayOutputStream.write(bArr[i]);
            } catch (IOException e) {
                throw new IllegalArgumentException("can't save value array.");
            }
        }
        this._data = byteArrayOutputStream.toByteArray();
        if (z) {
            this._intPad = this._data.length % 4;
        }
    }

    @Override // java.security.SecureRandom, java.util.Random
    public void nextBytes(byte[] bArr) {
        System.arraycopy(this._data, this._index, bArr, 0, bArr.length);
        this._index += bArr.length;
    }

    @Override // java.security.SecureRandom
    public byte[] generateSeed(int i) {
        byte[] bArr = new byte[i];
        nextBytes(bArr);
        return bArr;
    }

    @Override // java.util.Random
    public int nextInt() {
        int nextValue = 0 | (nextValue() << 24) | (nextValue() << 16);
        if (this._intPad == 2) {
            this._intPad--;
        } else {
            nextValue |= nextValue() << 8;
        }
        if (this._intPad == 1) {
            this._intPad--;
        } else {
            nextValue |= nextValue();
        }
        return nextValue;
    }

    @Override // java.util.Random
    public long nextLong() {
        return 0 | (nextValue() << 56) | (nextValue() << 48) | (nextValue() << 40) | (nextValue() << 32) | (nextValue() << 24) | (nextValue() << 16) | (nextValue() << 8) | nextValue();
    }

    public boolean isExhausted() {
        return this._index == this._data.length;
    }

    private int nextValue() {
        byte[] bArr = this._data;
        int i = this._index;
        this._index = i + 1;
        return bArr[i] & 255;
    }
}