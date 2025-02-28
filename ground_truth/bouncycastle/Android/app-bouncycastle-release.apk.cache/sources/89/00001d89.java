package org.bouncycastle.crypto.fpe;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.params.FPEParameters;
import org.bouncycastle.util.Pack;

/* loaded from: classes2.dex */
public abstract class FPEEngine {
    protected final BlockCipher baseCipher;
    protected boolean forEncryption;
    protected FPEParameters fpeParameters;

    /* JADX INFO: Access modifiers changed from: protected */
    public FPEEngine(BlockCipher blockCipher) {
        this.baseCipher = blockCipher;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public static byte[] toByteArray(short[] sArr) {
        byte[] bArr = new byte[sArr.length * 2];
        for (int i = 0; i != sArr.length; i++) {
            Pack.shortToBigEndian(sArr[i], bArr, i * 2);
        }
        return bArr;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public static short[] toShortArray(byte[] bArr) {
        if ((bArr.length & 1) == 0) {
            int length = bArr.length / 2;
            short[] sArr = new short[length];
            for (int i = 0; i != length; i++) {
                sArr[i] = Pack.bigEndianToShort(bArr, i * 2);
            }
            return sArr;
        }
        throw new IllegalArgumentException("data must be an even number of bytes for a wide radix");
    }

    protected abstract int decryptBlock(byte[] bArr, int i, int i2, byte[] bArr2, int i3);

    protected abstract int encryptBlock(byte[] bArr, int i, int i2, byte[] bArr2, int i3);

    public abstract String getAlgorithmName();

    public abstract void init(boolean z, CipherParameters cipherParameters);

    public int processBlock(byte[] bArr, int i, int i2, byte[] bArr2, int i3) {
        if (this.fpeParameters != null) {
            if (i2 >= 0) {
                if (bArr == null || bArr2 == null) {
                    throw new NullPointerException("buffer value is null");
                }
                if (bArr.length >= i + i2) {
                    if (bArr2.length >= i3 + i2) {
                        return this.forEncryption ? encryptBlock(bArr, i, i2, bArr2, i3) : decryptBlock(bArr, i, i2, bArr2, i3);
                    }
                    throw new OutputLengthException("output buffer too short");
                }
                throw new DataLengthException("input buffer too short");
            }
            throw new IllegalArgumentException("input length cannot be negative");
        }
        throw new IllegalStateException("FPE engine not initialized");
    }
}