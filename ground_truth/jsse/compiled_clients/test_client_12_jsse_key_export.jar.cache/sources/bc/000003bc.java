package org.bouncycastle.crypto;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/StreamBlockCipher.class */
public abstract class StreamBlockCipher implements BlockCipher, StreamCipher {
    private final BlockCipher cipher;

    /* JADX INFO: Access modifiers changed from: protected */
    public StreamBlockCipher(BlockCipher blockCipher) {
        this.cipher = blockCipher;
    }

    public BlockCipher getUnderlyingCipher() {
        return this.cipher;
    }

    @Override // org.bouncycastle.crypto.StreamCipher
    public final byte returnByte(byte b) {
        return calculateByte(b);
    }

    @Override // org.bouncycastle.crypto.StreamCipher
    public int processBytes(byte[] bArr, int i, int i2, byte[] bArr2, int i3) throws DataLengthException {
        if (i + i2 > bArr.length) {
            throw new DataLengthException("input buffer too small");
        }
        if (i3 + i2 > bArr2.length) {
            throw new OutputLengthException("output buffer too short");
        }
        int i4 = i;
        int i5 = i + i2;
        int i6 = i3;
        while (i4 < i5) {
            int i7 = i6;
            i6++;
            int i8 = i4;
            i4++;
            bArr2[i7] = calculateByte(bArr[i8]);
        }
        return i2;
    }

    protected abstract byte calculateByte(byte b);
}